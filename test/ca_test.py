"""Unit tests for the ca module."""
from __future__ import unicode_literals

import unittest
import mock

from tinycert.ca import CertificateAuthorityApi


class CertificateAuthorityApiTest(unittest.TestCase):
    """Unit tests for the CertificateAuthorityApi class."""
    def setUp(self):
        self.session = mock.MagicMock()
        self.session.request = mock.MagicMock()
        self.api = CertificateAuthorityApi(self.session)

    def list_test(self):
        expected_list = [
            {'id': 123, 'name': 'test ca'},
            {'id': 456, 'name': 'another test ca'}
        ]
        self.session.request.return_value = expected_list

        result = self.api.list()
        self.assertEqual(result, expected_list)
        self.session.request.assert_called_with('ca/list')

    def details_test(self):
        expected_result = {
            'id': 123,
            'C': 'US',
            'ST': 'Washington',
            'L': 'Seattle',
            'O': 'Acme, Inc.',
            'OU': 'Secure Digital Certificate Signing',
            'CN': 'Acme, Inc. CA',
            'E': 'admin@acme.com',
            'hash_alg': 'SHA256'
        }
        self.session.request.return_value = expected_result

        result = self.api.details(123)
        self.assertEqual(result, expected_result)
        self.session.request.assert_called_with('ca/details', {'ca_id': 123})

    def get_test(self):
        expected_result = {
            'pem': ('-----BEGIN CERTIFICATE-----'
                    'ABUNCHOFSTUFFHERE...'
                    '-----END CERTIFICATE-----')
        }
        self.session.request.return_value = expected_result

        result = self.api.get(123)
        self.assertEqual(result, expected_result)
        self.session.request.assert_called_with('ca/get', {'ca_id': 123, 'what': 'cert'})

    def delete_test(self):
        self.session.request.return_value = {}
        result = self.api.delete(123)
        self.assertEqual(result, {})
        self.session.request.assert_called_with('ca/delete', {'ca_id': 123})

    def create_test(self):
        expected_result = {
            'ca_id': 123
        }
        self.session.request.return_value = expected_result

        create_detail = {
            'C': 'US',
            'O': 'Acme, Inc.',
            'L': 'Seattle',
            'ST': 'Washington',
            'hash_method': 'sha256'
        }
        result = self.api.create(create_detail)
        self.assertEqual(result, expected_result)
        self.session.request.assert_called_with('ca/new', create_detail)
