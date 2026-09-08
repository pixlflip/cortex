"""Adversarial lifecycle regression tests; all vaults are temporary fixtures."""
import asyncio
import hashlib
import json
import subprocess
from pathlib import Path
import pytest
from cortex.config import CortexConfig, IndexConfig, Principal, VaultConfig, VaultsConfig, WritesConfig
from cortex.server import CortexServer
from cortex.memory_lifecycle import parse_memory_bytes, update_metadata_bytes, inspect_memory_bytes

@pytest.fixture
def service(tmp_path):
    root = tmp_path/'vaults'/'tester'; root.mkdir(parents=True)
    p = Principal(name='tester', scopes=['Public/**'], write_scopes=['Public/**'])
    cfg = CortexConfig(vault=VaultConfig(), vaults=VaultsConfig(root=root.parent, index_dir=tmp_path/'indexes'), index=IndexConfig(path=tmp_path/'idx.sqlite'),
        principals=[p], writes=WritesConfig(enabled=True))
    srv = CortexServer(cfg, principal=p)
    srv.git.ensure_repo()
    for path,raw in {'Public/old.md':b'# Beacon\r\nOld fact\r\n', 'Public/new.md':b'# Beacon\nNew fact\n', 'Private/hidden.md':b'# Beacon\nPrivate\n'}.items():
        target=root/path; target.parent.mkdir(exist_ok=True); target.write_bytes(raw)
    srv.git.commit('fixture','baseline')
    yield srv,p
    srv.index.close()


def sha(srv,path): return hashlib.sha256(srv.vault._resolve(path).read_bytes()).hexdigest()

def tool(srv,name,**arguments):
    async def run():
        result=await srv.mcp.call_tool(name,arguments)
        if isinstance(result,tuple): result=result[0]
        if name == 'context_pack':
            return result[0].text
        if name == 'search':
            return [json.loads(item.text) for item in result]
        return json.loads(result[0].text)
    return asyncio.run(run())

@pytest.mark.parametrize('raw',[b'---\n---\n\nBody\n',b'--- \r\nx: y\r\n--- \r\n\r\nBody\r\n',b'plain\r\n\n',b'---\nx: y\n---',b'---\nx: y\n---\n'])
def test_body_exact_across_yaml_shapes(raw):
    before=parse_memory_bytes(raw)[1]
    after=update_metadata_bytes(raw,{'memory_state':'current'})
    assert parse_memory_bytes(after)[1] == before

@pytest.mark.parametrize('raw',[b'---\nx: y',b'---\nmemory_state: current\nmemory_state: draft\n---\ntext', b'---\n- item\n---\ntext'])
def test_malformed_yaml_not_reinterpreted(raw):
    with pytest.raises(ValueError): update_metadata_bytes(raw,{'memory_state':'current'})
    assert inspect_memory_bytes(raw)['state']=='unreviewed'
    assert inspect_memory_bytes(raw)['warnings']

@pytest.mark.parametrize('state',[None,[],{},12,'CURRENT','published'])
def test_bad_state_write_paths_fail(service,state):
    srv,p=service
    raw='---\nmemory_state: '+json.dumps(state)+'\n---\nBody\n'
    with pytest.raises(ValueError): srv._do_write_note(p,'Public/bad.md',raw,'test',validate_frontmatter=False)
    assert not srv.vault.exists('Public/bad.md')
    old=sha(srv,'Public/old.md')
    with pytest.raises(ValueError): srv._do_update_frontmatter(p,'Public/old.md',{'memory_state':state},'test')
    assert sha(srv,'Public/old.md')==old


def test_yaml_state_honored_and_status_independent(service):
    srv,p=service
    srv._do_write_note(p,'Public/current.md','---\nstatus: completed\nmemory_state: current\n---\nBody\n','decision')
    fm=srv.vault.read_frontmatter('Public/current.md')
    assert fm['status']=='completed' and fm['memory_state']=='current'
    assert fm['memory_state_changed_by']=='tester'
    assert 'verified' not in str(fm.keys())


def test_managed_metadata_cannot_be_forged_or_removed(service):
    srv,p=service
    srv._do_set_memory_state(p,'Public/old.md','current','review',sha(srv,'Public/old.md'))
    before=sha(srv,'Public/old.md')
    with pytest.raises(ValueError): srv._do_patch_note(p,'Public/old.md','memory_state: current','memory_state: superseded','bad')
    with pytest.raises(ValueError): srv._do_update_frontmatter(p,'Public/old.md',{'memory_superseded_by':'Private/hidden.md'},'bad')
    assert sha(srv,'Public/old.md')==before
    srv._do_write_note(p,'Public/old.md','# Beacon\nnew body\n','normal content edit',overwrite=True)
    assert srv.vault.read_frontmatter('Public/old.md')['memory_state']=='unreviewed'


def test_disputed_search_includes_explicit_warning(service):
    srv,p=service
    tool(srv,'set_memory_state',path='Public/old.md',memory_state='disputed',reason='review',expected_sha256=sha(srv,'Public/old.md'))
    hit=next(x for x in tool(srv,'search',query='Beacon') if x['path']=='Public/old.md')
    assert hit['memory_state']=='disputed' and hit['warnings']


def test_supersession_body_history_schema_and_scope(service):
    srv,p=service
    before={path:parse_memory_bytes(srv.vault._resolve(path).read_bytes())[1] for path in ('Public/old.md','Public/new.md')}
    result=tool(srv,'supersede_note',old_path='Public/old.md',replacement_path='Public/new.md',reason='explicit synthetic decision',old_sha256=sha(srv,'Public/old.md'),replacement_sha256=sha(srv,'Public/new.md'))
    assert result['audited'] and result['index_status']=='ready'
    for path,body in before.items(): assert parse_memory_bytes(srv.vault._resolve(path).read_bytes())[1]==body
    assert srv.vault.read_frontmatter('Public/new.md')['memory_supersedes']==['Public/old.md']
    found=tool(srv,'search',query='Beacon')
    assert 'Public/old.md' not in {x['path'] for x in found}
    assert all(x['path'].startswith('Public/') for x in found)
    assert found[0]['memory_state']=='current'
    history=tool(srv,'search',query='Beacon',include_historical=True)
    assert any(x['path']=='Public/old.md' and x['memory_state']=='superseded' and x['warnings'] for x in history)
    regex=tool(srv,'search',query='Beacon',regex=True)
    assert regex[0]['memory_state']=='current'
    pack=tool(srv,'context_pack',query='Beacon')
    assert 'memory_state=current' in pack and 'Public/old.md' not in pack
    with pytest.raises(ValueError): srv._do_set_memory_state(p,'Public/old.md','current','bad reactivation',sha(srv,'Public/old.md'))

@pytest.mark.parametrize('replacement',['Public/old.md','Public/missing.md','Private/hidden.md'])
def test_bad_replacement_no_mutation(service,replacement):
    srv,p=service; before=sha(srv,'Public/old.md')
    with pytest.raises(ValueError): srv._do_supersede_note(p,'Public/old.md',replacement,'bad',before,'0'*64)
    assert sha(srv,'Public/old.md')==before

@pytest.mark.parametrize('failure',['write','commit'])
def test_failure_rolls_back_both_notes_and_git_index(service,monkeypatch,failure):
    srv,p=service
    originals={path:srv.vault._resolve(path).read_bytes() for path in ('Public/old.md','Public/new.md')}
    head=srv.git.head()
    if failure=='write':
        real=srv.vault.write_bytes; calls=0
        def fail_second(path,raw):
            nonlocal calls
            calls+=1
            if calls==2: raise OSError('injected')
            return real(path,raw)
        monkeypatch.setattr(srv.vault,'write_bytes',fail_second)
    else:
        def fail_commit(*args,**kwargs): raise RuntimeError('injected')
        monkeypatch.setattr(srv.git,'commit',fail_commit)
    with pytest.raises((OSError,RuntimeError)):
        srv._do_supersede_note(p,'Public/old.md','Public/new.md','test',sha(srv,'Public/old.md'),sha(srv,'Public/new.md'))
    assert srv.git.head()==head
    for path,raw in originals.items(): assert srv.vault._resolve(path).read_bytes()==raw
    assert not subprocess.check_output(['git','diff','--cached','--name-only'],cwd=srv.vault.root).strip()


def test_index_failure_returns_audited_pending(service,monkeypatch):
    srv,p=service
    def fail(): raise RuntimeError('index offline')
    monkeypatch.setattr(srv.index,'ensure_fresh',fail)
    result=srv._do_set_memory_state(p,'Public/old.md','disputed','evidence conflict',sha(srv,'Public/old.md'))
    assert result['saved'] and result['audited'] and result['commit']
    assert result['index_status']=='pending'


def test_stale_hash_and_blank_reason_rejected(service):
    srv,p=service; before=sha(srv,'Public/old.md')
    with pytest.raises(ValueError): srv._do_set_memory_state(p,'Public/old.md','current','x','0'*64)
    with pytest.raises(ValueError): srv._do_set_memory_state(p,'Public/old.md','current',' ',before)
    assert sha(srv,'Public/old.md')==before


def test_fixed_enum_in_mcp_schema(service):
    srv,p=service
    tools=asyncio.run(srv.mcp.list_tools())
    schema=next(t.inputSchema for t in tools if t.name=='set_memory_state')
    assert schema['properties']['memory_state']['enum']==['unreviewed','draft','current','superseded','disputed']
    assert 'expected_sha256' in schema['required']


def test_cycle_and_staged_changes_refused(service):
    srv,p=service
    path='Public/old.md'
    raw=srv.vault._resolve(path).read_bytes()
    srv.vault._resolve(path).write_bytes(update_metadata_bytes(raw, {'memory_supersedes':[path]}))
    before=sha(srv,path)
    with pytest.raises(ValueError, match='cycle'):
        srv._do_supersede_note(p,path,'Public/new.md','bad',before,sha(srv,'Public/new.md'))
    assert sha(srv,path)==before
    subprocess.run(['git','add','--',path],cwd=srv.vault.root,check=True)
    with pytest.raises(ValueError,match='staged'):
        srv._do_set_memory_state(p,path,'disputed','review',before)
    assert sha(srv,path)==before


def test_git_note_paths_are_literal(service):
    srv,p=service
    path='Public/[draft].md'
    srv._do_write_note(p,path,'# Draft\n','create')
    assert subprocess.check_output(['git','--literal-pathspecs','ls-files','--',path],cwd=srv.vault.root).decode().strip()==path
