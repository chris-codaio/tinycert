"""TinyCert Session

This module provides the Session class which wraps an authenticated session with TinyCert's rest API.
"""

# pylint: disable=wrong-import-order,wrong-import-position

from __future__ import unicode_literals
from future import standard_library
standard_library.install_aliases()

from past.builtins import basestring
from builtins import object
import collections
from contextlib import contextmanager
import hashlib
import hmac

# pylint: disable=import-error
import urllib.error
import urllib.parse
import urllib.request
# pylint: enable=import-error

import requests

from .cert import CertificateApi
from .ca import CertificateAuthorityApi


class NoSessionException(Exception):
    """Raised if an attempt is made to use a session without first calling connect()"""
    def __init__(self):
        Exception.__init__(self)
        self.value = 'Must connect the session first'

    def __str__(self):
        return repr(self.value)


@contextmanager
def auto_session(api_key, account, passphrase):
    """Context manager for holding a connected session object within scope."""
    session = Session(api_key)
    session.connect(account, passphrase)
    try:
        yield session
    finally:
        session.disconnect()


class Session(object):
    """Holds a session token and wraps the TinyCert API.

    Preferred usage is:
    with auto_session(api_key, account, passphrase) as session:
          ca = session.ca()
          ca.list()

    Raw usage is:
    #connect to connect a new session before calling other APIs.
    #disconnect when complete.
    """
    def __init__(self, api_key, session_token=None):
        self._api_key = api_key
        self._session_token = session_token

    def request(self, path, params=None):
        """Make a request via the TinyCert API."""
        if params is None:
            params = {}

        if self._session_token:
            params['token'] = self._session_token

        signed_request_payload = self._sign_request_payload(params)

        response = requests.post('https://www.tinycert.org/api/v1/%s' % path,
                                 headers={'content-type': 'application/x-www-form-urlencoded'},
                                 data=signed_request_payload)
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _flatten_array_elements(params):
        """Flattens arrays into numerically indexed entries, further flattening if the array elements are dicts."""
        flattened_params = {}
        for key, value in params.items():
            if not isinstance(value, (list, tuple)):
                flattened_params[key] = value
                continue
            for index, entry in enumerate(value):
                if isinstance(entry, basestring):
                    flattened_params['%s[%i]' % (key, index)] = entry
                else:
                    for dict_key, dict_value in entry.items():
                        flattened_params['%s[%i][%s]' % (key, index, dict_key)] = dict_value
        return flattened_params

    def _sign_request_payload(self, params):
        """Digitally sign the request payload.

        Follows the instructions at https://www.tinycert.org/docs/api/v1/auth
        """
        # 0. To get PHP-like associative arrays, expand them as separate entries in the params dict.
        flattened_params = self._flatten_array_elements(params)

        # 1. Sort params by key, alphabetically
        ordered_params = collections.OrderedDict(sorted(flattened_params.items()))

        # 2. Combine parameters into a URL-encoded query string
        query_string = urllib.parse.urlencode(ordered_params, True)

        # 3. Use SHA256 to calculacte an HMAC digest of the query string, using the API key as the secret.
        hasher = hmac.new(
            self._api_key.encode('utf-8'),
            digestmod=hashlib.sha256,
        )
        hasher.update(query_string.encode('utf-8'))
        hash = hasher.hexdigest()

        # 4. Add the signed hash to the query string
        query_string += '&digest=%s' % hash

        return query_string

    def connect(self, account, passphrase):
        """Connect this session to TinyCert, enabling API calls"""
        params = {'email': account, 'passphrase': passphrase}
        response = self.request('connect', params)
        self._session_token = response['token']

    def disconnect(self):
        """Disconnect this session from TinyCert by retiring the session token."""
        self.request('disconnect')
        self._session_token = None

    # pylint: disable=invalid-name
    @property
    def ca(self):
        """Retrieve the CertificateAuthority API wrapper."""
        if self._session_token is None:
            raise NoSessionException()
        return CertificateAuthorityApi(self)

    @property
    def cert(self):
        """Retrieve the Certificate API wrapper for the given CA."""
        if self._session_token is None:
            raise NoSessionException()
        return CertificateApi(self)
