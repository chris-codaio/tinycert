"""Unit tests for the tiny_cert module."""
# pylint: disable=missing-docstring,protected-access

from __future__ import unicode_literals

import requests_mock

from tinycert.session import Session
from tinycert.session import auto_session


FAKE_API_KEY = 'somekey'
FAKE_SESSION_TOKEN = 'sometoken'
FAKE_ACCOUNT = 'me@foo.com'
FAKE_PASSPHRASE = 'my passphrase'


def setup_requests_mock(mock):
    expected_connect_body = ('email=me%40foo.com'
                             '&passphrase=my+passphrase'
                             '&digest=9b8062b8ab91dd2ff4bb9d24d7be5234659ba94c772a8e056d26388e052b8537')

    def json_connect_response(request, context):
        if request.body == expected_connect_body:
            context.status_code = 200
            return {'token': FAKE_SESSION_TOKEN}
        context.status_code = 400
        return {}

    mock.register_uri('POST',
                      'https://www.tinycert.org/api/v1/connect',
                      request_headers={'content-type': 'application/x-www-form-urlencoded'},
                      json=json_connect_response)

    expected_disconnect_body = ('token=sometoken'
                                '&digest=a83d65e81eb4e6cae1b0fc95c26f6ac838e278f22b0a94d8a42c4a193a58420d')

    def json_disconnect_response(request, context):
        if request.body == expected_disconnect_body:
            context.status_code = 200
            return {}
        context.status_code = 400
        return {}

    mock.register_uri('POST',
                      'https://www.tinycert.org/api/v1/disconnect',
                      request_headers={'content-type': 'application/x-www-form-urlencoded'},
                      json=json_disconnect_response)


def test_signing_request_payload():
    with requests_mock.Mocker() as mock:
        setup_requests_mock(mock)
        session = Session('ThisIsMySuperSecretAPIKey')

        params = {
            'token': 'd7dd6880c206216a9ed74f92ca8edaef88728bbb2c8b23020c624de9a7d08d6f',
            'ca_id': 123,
            'CN': 'example.com',
            'O': 'ACME, Inc.',
            'OU': 'IT Department',
            'C': 'US',
            'ST': 'Illinois',
            'L': 'Chicago',
            'SANs': [
                {'DNS': 'www.example.com'},
                {'DNS': 'example.com'}
            ]
        }

        expected_payload = ('C=US'
                            '&CN=example.com'
                            '&L=Chicago'
                            '&O=ACME%2C+Inc.'
                            '&OU=IT+Department'
                            '&SANs%5B0%5D%5BDNS%5D=www.example.com'
                            '&SANs%5B1%5D%5BDNS%5D=example.com'
                            '&ST=Illinois'
                            '&ca_id=123'
                            '&token=d7dd6880c206216a9ed74f92ca8edaef88728bbb2c8b23020c624de9a7d08d6f'
                            '&digest=16b436bd8779dadf0327a97eac54b631e02c4643cbf52ccc1358431691f74b21')

        signed_payload = session._sign_request_payload(params)
        assert signed_payload == expected_payload


def test_connect():
    with requests_mock.Mocker() as mock:
        setup_requests_mock(mock)
        session = Session(FAKE_API_KEY)
        session.connect(FAKE_ACCOUNT, FAKE_PASSPHRASE)
        assert session._session_token == FAKE_SESSION_TOKEN
        assert session.ca
        assert session.cert


def test_disconnect():
    with requests_mock.Mocker() as mock:
        setup_requests_mock(mock)
        session = Session(FAKE_API_KEY, FAKE_SESSION_TOKEN)
        assert session._session_token == FAKE_SESSION_TOKEN
        session.disconnect()
        assert session._session_token is None


def test_context_manager():
    with requests_mock.Mocker() as mock:
        setup_requests_mock(mock)
        with auto_session(FAKE_API_KEY, FAKE_ACCOUNT, FAKE_PASSPHRASE) as session:
            assert session._session_token == FAKE_SESSION_TOKEN
            assert session.ca
            assert session.cert

        assert session._session_token is None
