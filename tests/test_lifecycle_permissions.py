"""Lifecycle operations must be governed as writes, not default reads."""
import pytest
from cortex.api import ApiV1
from cortex.config import CortexConfig, WritesConfig
from cortex.db import Database
from cortex.gateway import PermissionResolver
from cortex.sessions import SessionAuth
from cortex.users import IdentityService

@pytest.fixture
def identity(tmp_path):
    service = IdentityService(Database(tmp_path / 'identity.sqlite'))
    service.create_user('reader', password='synthetic-test-password')
    return service

@pytest.mark.parametrize('name', ['set_memory_state', 'supersede_note'])
def test_lifecycle_is_write_default_denied(identity, name):
    config = CortexConfig()
    principal = identity.principal_for_username('reader')
    resolver = PermissionResolver(config, identity)
    assert resolver.allowed(principal, 'cortex.search')
    assert not resolver.allowed(principal, f'cortex.{name}')
    user = identity.get_user('reader')
    identity.tool_permissions.set(subject_type='user', subject_id=user['id'], tool_pattern=f'cortex.{name}', effect='allow')
    assert resolver.allowed(principal, f'cortex.{name}')
    identity.tool_permissions.set(subject_type='user', subject_id=user['id'], tool_pattern='cortex.*', effect='deny')
    assert not resolver.allowed(principal, f'cortex.{name}')

@pytest.mark.parametrize('enabled', [False, True])
def test_lifecycle_admin_catalog_matches_write_enable(identity, enabled):
    config = CortexConfig(writes=WritesConfig(enabled=enabled))
    api = ApiV1(config, identity, SessionAuth(identity, secure_cookies=False))
    names = {item['name'] for item in api._tool_catalog(identity.get_user('reader')['id'], is_admin=False)}
    assert ('set_memory_state' in names) is enabled
    assert ('supersede_note' in names) is enabled
