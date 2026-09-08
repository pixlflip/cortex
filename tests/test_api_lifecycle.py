"""Lifecycle state in REST reads and recall, with ordinary scope enforcement."""
import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient
from cortex.api import ApiV1
from cortex.sessions import SessionAuth
from test_multivault import multivault


def test_rest_lifecycle_recall_and_explicit_history(multivault):
    cfg, identity, manager = multivault
    root = manager.root_for("alice")
    states = {'old': 'superseded', 'active': 'current', 'conflict': 'disputed', 'legacy': None}
    for name, state in states.items():
        fm = f'---\nmemory_state: {state}\n---\n' if state else ''
        (root / 'Shared' / f'{name}.md').write_text(fm + '# Example\nLifecycle beacon\n')
    (root / 'Private' / 'hidden.md').write_text('---\nmemory_state: current\n---\n# Lifecycle beacon\n')
    api = ApiV1(cfg, identity, SessionAuth(identity, secure_cookies=False))
    with TestClient(Starlette(routes=api.routes())) as client:
        assert client.post('/api/v1/auth/login', json={'username':'alice','password':'alice-pw'}).status_code == 200
        r = client.get('/api/v1/vaults/alice/search', params={'q':'Lifecycle beacon'})
        assert r.status_code == 200, r.text
        rows = r.json()['results']
        paths = {r['path'] for r in rows}
        assert 'Shared/old.md' not in paths
        assert 'Private/hidden.md' in paths
        assert rows[0]['memory_state'] == 'current'
        assert {r['memory_state'] for r in rows} >= {'current','disputed','unreviewed'}
        hist = client.get('/api/v1/vaults/alice/search', params={'q':'Lifecycle beacon','include_historical':'true'}).json()['results']
        assert any(r['path']=='Shared/old.md' and r['memory_state']=='superseded' for r in hist)
        note = client.get('/api/v1/vaults/alice/notes/Shared/old.md')
        assert note.status_code == 200, note.text
        assert note.json()['memory']['state'] == 'superseded'
