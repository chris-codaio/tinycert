"""Unit tests for the tiny_cert module."""
from __future__ import unicode_literals

import unittest

import requests_mock

from tinycert.session import Session
from tinycert.session import auto_session


class SessionTest(unittest.TestCase):
    """Unit tests for the tiny_cert module."""
    FAKE_API_KEY = 'somekey'
    FAKE_SESSION_TOKEN = 'sometoken'
    FAKE_ACCOUNT = 'me@foo.com'
    FAKE_PASSPHRASE = 'my passphrase'

    def _setup_mock_requests(self, mock_requests):
        expected_connect_body = ('email=me%40foo.com'
                                 '&passphrase=my+passphrase'
                                 '&digest=9b8062b8ab91dd2ff4bb9d24d7be5234659ba94c772a8e056d26388e052b8537')

        def json_connect_response(request, context):
            if request.body == expected_connect_body:
                context.status_code = 200
                return {'token': SessionTest.FAKE_SESSION_TOKEN}
            context.status_code = 400
            return {}

        mock_requests.register_uri('POST',
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

        mock_requests.register_uri('POST',
                                   'https://www.tinycert.org/api/v1/disconnect',
                                   request_headers={'content-type': 'application/x-www-form-urlencoded'},
                                   json=json_disconnect_response)

    def testSigningRequestPayload(self):
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
        self.assertEquals(signed_payload, expected_payload)

    @requests_mock.Mocker()
    def testConnect(self, mock_requests):
        self._setup_mock_requests(mock_requests)
        session = Session(SessionTest.FAKE_API_KEY)
        session.connect(SessionTest.FAKE_ACCOUNT, SessionTest.FAKE_PASSPHRASE)
        self.assertEquals(session._session_token, SessionTest.FAKE_SESSION_TOKEN)
        self.assertIsNotNone(session.ca)
        self.assertIsNotNone(session.cert)

    @requests_mock.Mocker()
    def testDisconnect(self, mock_requests):
        self._setup_mock_requests(mock_requests)
        session = Session(SessionTest.FAKE_API_KEY, SessionTest.FAKE_SESSION_TOKEN)
        self.assertEquals(session._session_token, SessionTest.FAKE_SESSION_TOKEN)
        session.disconnect()
        self.assertIsNone(session._session_token)

    @requests_mock.Mocker()
    def testContextManager(self, mock_requests):
        self._setup_mock_requests(mock_requests)
        with auto_session(SessionTest.FAKE_API_KEY, SessionTest.FAKE_ACCOUNT, SessionTest.FAKE_PASSPHRASE) as session:
            self.assertEquals(session._session_token, SessionTest.FAKE_SESSION_TOKEN)
            self.assertIsNotNone(session.ca)
            self.assertIsNotNone(session.cert)

        self.assertIsNone(session._session_token)


if __name__ == '__main__':
    unittest.main()
