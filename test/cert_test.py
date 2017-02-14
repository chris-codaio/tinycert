"""Unit tests for the cert module."""
# pylint: disable=missing-docstring

from __future__ import unicode_literals

import mock
import pytest

from tinycert.cert import CertificateApi
from tinycert.cert import State


@pytest.fixture(name='session')
def fixture_session():
    fixture = mock.MagicMock()
    fixture.request = mock.MagicMock()
    return fixture


@pytest.fixture(name='api')
def fixture_api(session):
    return CertificateApi(session)


def list_test(session, api):
    expected_list = [
        {'id': 123, 'name': 'test cert', 'status': 'good', 'expires': 987654321},
        {'id': 456, 'name': 'another test cert', 'status': 'revoked', 'expires': 987654322}
    ]
    session.request.return_value = expected_list

    result = api.list(555, State.good.value | State.revoked.value)
    assert result == expected_list
    session.request.assert_called_with('cert/list', {'ca_id': 555, 'what': 6})


def details_test(session, api):
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
    session.request.return_value = expected_result

    result = api.details(123)
    assert result == expected_result
    session.request.assert_called_with('cert/details', {'cert_id': 123})


def get_test(session, api):
    expected_result = {
        'pem': ('-----BEGIN RSA PRIVATE KEY-----'
                'KEYMATERIALHERE...'
                '-----END RSA PRIVATE KEY-----')
    }
    session.request.return_value = expected_result

    result = api.get(123, 'key.dec')
    assert result == expected_result
    session.request.assert_called_with('cert/get', {'cert_id': 123, 'what': 'key.dec'})


def reissue_test(session, api):
    expected_result = {
        'cert_id': 456
    }
    session.request.return_value = expected_result

    result = api.reissue(123)
    assert result == expected_result
    session.request.assert_called_with('cert/reissue', {'cert_id': 123})


def set_status_test(session, api):
    session.request.return_value = {}
    result = api.set_status(123, 'hold')
    assert result == {}
    session.request.assert_called_with('cert/status', {'cert_id': 123, 'status': 'hold'})


def create_test(session, api):
    expected_result = {
        'cert_id': 456
    }
    session.request.return_value = expected_result

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

    result = api.create(123, create_detail)
    assert result == expected_result
    session.request.assert_called_with('cert/new', expected_detail)
