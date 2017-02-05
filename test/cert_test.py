"""Unit tests for the cert module."""
from __future__ import unicode_literals

import unittest

import mock

from tinycert.cert import CertificateApi
from tinycert.cert import State


class CertificateApiTest(unittest.TestCase):
    """Unit tests for the CertificateApi class."""
    def setUp(self):
        self.session = mock.MagicMock()
        self.session.request = mock.MagicMock()
        self.api = CertificateApi(self.session)

    def list_test(self):
        expected_list = [
            {'id': 123, 'name': 'test cert', 'status': 'good', 'expires': 987654321},
            {'id': 456, 'name': 'another test cert', 'status': 'revoked', 'expires': 987654322}
        ]
        self.session.request.return_value = expected_list

        result = self.api.list(555, State.good.value | State.revoked.value)
        self.assertEqual(result, expected_list)
        self.session.request.assert_called_with('cert/list', {'ca_id': 555, 'what': 6})

    def details_test(self):
        expected_result = {
            'id': 123,
            'status': 'good',
            'C': 'US',
            'ST': 'Washington',
            'L': 'Seattle',
            'O': 'Acme, Inc.',
            'OU': 'IT Department',
            'CN': 'Acme, Inc. CA',
            'Alt': [
                {'DNS': 'www.example.com'},
                {'DNS': 'example.com'}
            ],
            'hash_alg': 'SHA256'
        }
        self.session.request.return_value = expected_result

        result = self.api.details(123)
        self.assertEqual(result, expected_result)
        self.session.request.assert_called_with('cert/details', {'cert_id': 123})

    def get_test(self):
        expected_result = {
            'pem': ('-----BEGIN RSA PRIVATE KEY-----'
                    'KEYMATERIALHERE...'
                    '-----END RSA PRIVATE KEY-----')
        }
        self.session.request.return_value = expected_result

        result = self.api.get(123, 'key.dec')
        self.assertEqual(result, expected_result)
        self.session.request.assert_called_with('cert/get', {'cert_id': 123, 'what': 'key.dec'})

    def reissue_test(self):
        expected_result = {
            'cert_id': 456
        }
        self.session.request.return_value = expected_result

        result = self.api.reissue(123)
        self.assertEqual(result, expected_result)
        self.session.request.assert_called_with('cert/reissue', {'cert_id': 123})

    def set_status_test(self):
        self.session.request.return_value = {}
        result = self.api.set_status(123, 'hold')
        self.assertEqual(result, {})
        self.session.request.assert_called_with('cert/status', {'cert_id': 123, 'status': 'hold'})

    def create_test(self):
        expected_result = {
            'cert_id': 456
        }
        self.session.request.return_value = expected_result

        create_detail = {
            'C': 'US',
            'CN': '*.example.com',
            'L': 'Seattle',
            'O': 'Acme, Inc.',
            'OU': 'IT Department',
            'SANs': [
                {'DNS': 'www.example.com'},
                {'DNS': 'example.com'}
            ],
            'ST': 'Washington'
        }
        expected_detail = create_detail.copy()
        expected_detail['ca_id'] = 123

        result = self.api.create(123, create_detail)
        self.assertEqual(result, expected_result)
        self.session.request.assert_called_with('cert/new', expected_detail)
