"""Account-boundary acceptance tests; synthetic stores only."""
import asyncio
import json
import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient
from cortex.access import VaultAccessResolver, VaultAccessError
from cortex.api import ApiV1
from cortex.config import CortexConfig, VaultConfig, VaultsConfig, DatabaseConfig, Principal
from cortex.db import Database
from cortex.server import CortexServer
from cortex.sessions import SessionAuth
from cortex.users import IdentityService
from cortex.vaults import attach_vault_manager, VaultManagerError
from cortex.memory_lifecycle import parse_memory_bytes

@pytest.fixture
def accounts(tmp_path):
    cfg = CortexConfig(vault=VaultConfig(path=tmp_path/'legacy-do-not-open'),
        vaults=VaultsConfig(root=tmp_path/'accounts',index_dir=tmp_path/'indexes'),
        database=DatabaseConfig(path=tmp_path/'identity.sqlite'))
    identity=IdentityService(Database(cfg.database.path),cfg)
    manager=attach_vault_manager(identity,cfg)
    identity.create_user('alice',password='alice-pass',is_admin=True)
    identity.create_user('bob',password='bob-pass')
    for name in ('alice','bob'):
        (manager.root_for(name)/'owned.md').write_text(name+' private body\n')
    yield cfg,identity,manager
    manager.close()

def test_global_vault_absent_and_cannot_be_requested(accounts):
    cfg,identity,manager=accounts
    cfg.vault.path.mkdir(); (cfg.vault.path/'leak.md').write_text('legacy secret')
    assert set(manager.vault_ids())=={'alice','bob'}
    assert not manager.exists('main')
    with pytest.raises(VaultManagerError): manager.get('main')
    access=VaultAccessResolver(cfg,manager,identity)
    for name in ('alice','bob'):
        p=identity.principal_for_username(name)
        assert access.select(p)[0].vault_id==name
        with pytest.raises(VaultAccessError): access.select(p,'main')

def test_no_missing_account_or_orphan_fallback(accounts):
    cfg,identity,manager=accounts
    access=VaultAccessResolver(cfg,manager,identity)
    (manager.root/'orphan').mkdir()
    admin=identity.principal_for_username('alice')
    assert 'orphan' not in access.visible_vaults(admin)
    with pytest.raises(VaultAccessError): access.select(Principal(name='unmapped',scopes=['**']))
    import shutil
    manager.close(); shutil.rmtree(manager.root_for('alice'))
    with pytest.raises(VaultAccessError): access.select(admin)

def test_group_cannot_grant_global_or_other_account(accounts):
    cfg,identity,manager=accounts
    identity.create_group('legacy',scopes=['**'],write_scopes=['**'])
    identity.add_to_group('bob','legacy')
    access=VaultAccessResolver(cfg,manager,identity)
    bob=identity.principal_for_username('bob')
    assert access.visible_vaults(bob)==['bob']
    with pytest.raises(VaultAccessError): access.select(bob,'alice')

def test_http_boot_without_legacy_and_api_owner_default(accounts):
    cfg,identity,manager=accounts
    srv=CortexServer(cfg,identity=identity)
    assert not cfg.vault.path.exists()
    with pytest.raises(VaultAccessError): _=srv.vault
    api=ApiV1(cfg,identity,SessionAuth(identity,secure_cookies=False))
    with TestClient(Starlette(routes=api.routes())) as client:
        assert client.get('/api/v1/vaults/alice/notes/owned.md').status_code==401
        assert client.post('/api/v1/auth/login',json={'username':'alice','password':'alice-pass'}).status_code==200
        payload=client.get('/api/v1/vaults').json()
        assert payload['default_vault']=='alice'
        assert payload['vaults'][0]['id']=='alice'
        assert 'main' not in {v['id'] for v in payload['vaults']}
        assert client.get('/api/v1/vaults/main/notes/owned.md').status_code==404
    with TestClient(Starlette(routes=api.routes())) as client:
        assert client.post('/api/v1/auth/login',json={'username':'bob','password':'bob-pass'}).status_code==200
        assert client.get('/api/v1/vaults/alice/notes/owned.md').status_code==404
        assert client.get('/api/v1/vaults/bob/notes/owned.md').json()['markdown']=='bob private body\n'

def test_api_token_narrows_owner_paths(accounts):
    cfg,identity,manager=accounts
    (manager.root_for('bob')/'Public').mkdir()
    (manager.root_for('bob')/'Public'/'visible.md').write_text('public allowed')
    token=identity.mint_token('bob','restricted',scopes=['Public/**'])
    api=ApiV1(cfg,identity,SessionAuth(identity,secure_cookies=False))
    with TestClient(Starlette(routes=api.routes())) as client:
        client.headers['Authorization']='Bearer '+token.token
        assert client.get('/api/v1/vaults/bob/notes/Public/visible.md').status_code==200
        assert client.get('/api/v1/vaults/bob/notes/owned.md').status_code==404
        assert client.get('/api/v1/vaults/alice/notes/owned.md').status_code==404


def test_mcp_defaults_to_account_even_admin(accounts):
    cfg,identity,manager=accounts
    srv=CortexServer(cfg,identity.principal_for_username('alice'),identity=identity)
    async def run():
        result=await srv.mcp.call_tool('read_note',{'path':'owned.md'})
        if isinstance(result,tuple): result=result[0]
        assert 'alice private body' in result[0].text
        assert 'bob private body' not in result[0].text
        result=await srv.mcp.call_tool('status',{})
        if isinstance(result,tuple): result=result[0]
        assert json.loads(result[0].text)['vault']=='alice'
    asyncio.run(run())

@pytest.mark.parametrize('body_changed,explicit,expected',[(True,None,'unreviewed'),(False,None,'current'),(True,'current','current')])
def test_body_review_invalidation(body_changed,explicit,expected):
    p=Principal(name='alice')
    old=b'---\nmemory_state: current\n---\nBody\n'
    new=b'---\nmemory_state: current\ntitle: New title\n---\n'+(b'Changed\n' if body_changed else b'Body\n')
    updated=CortexServer._ordinary_metadata(new,old,p,'test edit',explicit)
    assert parse_memory_bytes(updated)[0]['memory_state']==expected
    assert parse_memory_bytes(updated)[1]==parse_memory_bytes(new)[1]
