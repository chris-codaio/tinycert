"""Unit tests for the ca module."""
# pylint: disable=missing-docstring

from __future__ import unicode_literals

import mock
import pytest

from tinycert.ca import CertificateAuthorityApi


@pytest.fixture(name='session')
def fixture_session():
    fixture = mock.MagicMock()
    fixture.request = mock.MagicMock()
    return fixture


@pytest.fixture(name='api')
def fixture_api(session):
    return CertificateAuthorityApi(session)


def list_test(session, api):
    expected_list = [
        {'id': 123, 'name': 'test ca'},
        {'id': 456, 'name': 'another test ca'}
    ]
    session.request.return_value = expected_list

    result = api.list()
    assert result == expected_list
    session.request.assert_called_with('ca/list')


def details_test(session, api):
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
    session.request.return_value = expected_result

    result = api.details(123)
    assert result == expected_result
    session.request.assert_called_with('ca/details', {'ca_id': 123})


def get_test(session, api):
    expected_result = {
        'pem': ('-----BEGIN CERTIFICATE-----'
                'ABUNCHOFSTUFFHERE...'
                '-----END CERTIFICATE-----')
    }
    session.request.return_value = expected_result

    result = api.get(123)
    assert result == expected_result
    session.request.assert_called_with('ca/get', {'ca_id': 123, 'what': 'cert'})


def delete_test(session, api):
    session.request.return_value = {}
    result = api.delete(123)
    assert result == {}
    session.request.assert_called_with('ca/delete', {'ca_id': 123})


def create_test(session, api):
    expected_result = {
        'ca_id': 123
    }
    session.request.return_value = expected_result

    create_detail = {
        'C': 'US',
        'O': 'Acme, Inc.',
        'L': 'Seattle',
        'ST': 'Washington',
        'hash_method': 'sha256'
    }
    result = api.create(create_detail)
    assert result == expected_result
    session.request.assert_called_with('ca/new', create_detail)
