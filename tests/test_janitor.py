from pathlib import Path

from cortex.config import CortexConfig, DatabaseConfig, IndexConfig, JanitorConfig, VaultConfig, VaultsConfig
from cortex.db import Database
from cortex.janitor import JanitorBoundary, JanitorReport, run_janitor_all
from cortex.vaults import VaultManager


def test_boundary_is_deny_first_and_cannot_allow_protected_material():
    boundary = JanitorBoundary(JanitorConfig(allowed_paths=["**"], forbidden_paths=["Private/**"]))
    assert boundary.allows("Notes/hello.md")
    assert not boundary.allows("Private/hello.md")
    assert not boundary.allows("cortex.yaml")
    assert not boundary.allows("copied/config/cortex.yaml")
    assert not boundary.allows("state/cortex.sqlite")
    assert not boundary.allows("rules/janitor/policy.md")


def _config(tmp_path: Path) -> CortexConfig:
    main = tmp_path / "main"
    main.mkdir()
    return CortexConfig(
        vault=VaultConfig(path=main),
        vaults=VaultsConfig(root=tmp_path / "vaults", index_dir=tmp_path / "indexes"),
        index=IndexConfig(path=tmp_path / "main-index.sqlite"),
        database=DatabaseConfig(path=tmp_path / "cortex.db"),
        janitor=JanitorConfig(enabled=True, dry_run=True),
    )


def test_macro_janitor_reports_each_vault_and_rollup(tmp_path: Path):
    config = _config(tmp_path)
    manager = VaultManager(config)
    manager.provision("alice")
    manager.close()
    (config.vault.path / "Start.md").write_text("[[Missing]]\n", encoding="utf-8")
    (config.vaults.root / "alice" / "Good.md").write_text("# Fine\n", encoding="utf-8")
    db = Database(config.database.path)

    results = run_janitor_all(config, db)

    assert [vault for vault, _ in results] == ["main", "alice"]
    assert all(isinstance(report, JanitorReport) for _, report in results)
    with db.connection() as conn:
        rows = conn.execute("SELECT vault, details_json FROM janitor_reports ORDER BY id").fetchall()
    assert [row["vault"] for row in rows] == ["main", "alice", "*"]
    assert "Missing" in rows[0]["details_json"]


def test_macro_janitor_isolates_a_failing_vault(tmp_path: Path, monkeypatch):
    config = _config(tmp_path)
    manager = VaultManager(config)
    manager.provision("alice")
    manager.close()
    db = Database(config.database.path)
    original = VaultManager.store_for

    def failing(self, vault_id):
        if vault_id == "main":
            raise OSError("broken vault")
        return original(self, vault_id)

    monkeypatch.setattr(VaultManager, "store_for", failing)
    results = dict(run_janitor_all(config, db))
    assert isinstance(results["main"], OSError)
    assert isinstance(results["alice"], JanitorReport)
    with db.connection() as conn:
        rollup = conn.execute("SELECT details_json FROM janitor_reports WHERE vault='*'").fetchone()
    assert '"failed_vaults": ["main"]' in rollup["details_json"]
