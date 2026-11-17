"""Vault-facing endpoints: explicit grants, content, lifecycle and git audit."""

from __future__ import annotations

import hashlib
import mimetypes
import re
from datetime import datetime
from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..scopes import filter_paths, path_allowed
from ..serialization import normalize_json
from ..memory_lifecycle import inspect_memory_bytes
from ..recall import SemanticUnavailable, recall_hits, resolve_mode
from ..vault import VaultError, canonical_asset_path, canonical_note_path
from ..vaults import VaultManagerError

from ._base import ApiBase
from ._common import (
    ApiError,
    ApiIdentity,
    _NOT_FOUND,
    _unauthenticated,
)


class VaultRoutesMixin(ApiBase):
    """Handler mixin for :class:`cortex.api.ApiV1`."""

    # -- admin: explicit account-vault grants --------------------------------

    def _require_grant_admin(self, request: Request) -> ApiIdentity:
        ident = self._require_identity(request, admin=True)
        # A path-restricted credential is not a grant-administration credential.
        if ident.principal is not None and ident.principal.token_scopes is not None:
            raise ApiError(403, "forbidden", "grant administration requires an unrestricted admin credential")
        return ident

    async def vault_grants_collection(self, request: Request) -> Response:
        ident = self._require_grant_admin(request)
        return JSONResponse({"grants": self.identity.list_vault_grants(actor=ident.user)})

    async def vault_grant_item(self, request: Request) -> Response:
        ident = self._require_grant_admin(request)  # before lookup or parsing
        username, vault = request.path_params["username"], request.path_params["vault"]
        self._get_user_or_404(username)
        self._get_user_or_404(vault)
        if request.method == "DELETE":
            self.identity.revoke_vault_grant(username, vault, actor=ident.user)
            return Response(status_code=204)
        body = await self._json_body(request)
        if set(body) != {"read_scopes", "write_scopes"}:
            raise ApiError(400, "invalid_request", "read_scopes and write_scopes are required; no other fields allowed")
        grant = self.identity.set_vault_grant(
            username, vault, read_scopes=body["read_scopes"],
            write_scopes=body["write_scopes"], actor=ident.user,
        )
        return JSONResponse({"grant": grant})

    # -- B2/B3: one authorization path for every vault-facing API -------------

    def _api_principal(self, ident: ApiIdentity):
        principal = ident.principal or self.identity.principal_for_username(
            ident.username
        )
        if principal is None:
            raise _unauthenticated()
        return principal

    def _select_vault(self, ident: ApiIdentity, vault_id: str, *, write: bool = False):
        return self.vault_access.select(
            self._api_principal(ident), vault_id, write=write
        )

    async def vaults_collection(self, request: Request) -> Response:
        ident = self._require_identity(request)
        principal = self._api_principal(ident)
        items: list[dict] = []
        for grant in self.vault_access.grants(principal):
            try:
                bundle = self.vault_manager.get(grant.vault_id)
            except VaultManagerError:
                continue
            notes = filter_paths(bundle.store.list_notes(), list(grant.scopes))
            stats = bundle.index.stats()
            size = 0
            for path in notes:
                try:
                    size += bundle.store._resolve(path).stat().st_size
                except OSError:
                    pass
            items.append(
                {
                    "id": grant.vault_id,
                    "relation": grant.relation,
                    "scopes": list(grant.scopes),
                    "write_scopes": list(grant.write_scopes),
                    "note_count": len(notes),
                    "size_bytes": size,
                    # A slice does not grant whole-vault activity/size metadata.
                    "head_commit": bundle.git.head() if grant.relation != "explicit" else None,
                    "last_commit_iso": bundle.git.head_time() if grant.relation != "explicit" else None,
                    "last_indexed_iso": stats["last_indexed"] if grant.relation != "explicit" else None,
                    "index_note_count": stats["note_count"] if grant.relation != "explicit" else None,
                    "sync_adapter": self.vault_manager.sync_config_for(
                        grant.vault_id
                    ).adapter if grant.relation != "explicit" else None,
                }
            )
        return JSONResponse({"vaults": items, "default_vault": next(
            (item["id"] for item in items if item["id"] == principal.name), None
        )})

    async def vault_tree(self, request: Request) -> Response:
        ident = self._require_identity(request)
        bundle, scoped, _ = self._select_vault(ident, request.path_params["vault"])
        paths = filter_paths(bundle.store.list_notes(), scoped.scopes)
        root: dict = {"name": "", "type": "folder", "children": {}}
        for path in paths:
            node = root
            parts = path.split("/")
            for part in parts[:-1]:
                node = node["children"].setdefault(
                    part, {"name": part, "type": "folder", "children": {}}
                )
            node["children"][parts[-1]] = {
                "name": parts[-1],
                "type": "note",
                "path": path,
            }

        def freeze(node: dict) -> dict:
            if node["type"] == "note":
                return node
            children = [freeze(child) for child in node["children"].values()]
            children.sort(
                key=lambda item: (item["type"] != "folder", item["name"].lower())
            )
            return {"name": node["name"], "type": "folder", "children": children}

        return JSONResponse({"vault": bundle.vault_id, "tree": freeze(root)})

    async def vault_note(self, request: Request) -> Response:
        ident = self._require_identity(request)
        bundle, scoped, _ = self._select_vault(ident, request.path_params["vault"])
        raw_path = request.path_params["path"]
        path = canonical_note_path(raw_path)
        if path is None or not path_allowed(path, scoped.scopes):
            raise ApiError(404, "not_found", _NOT_FOUND)
        try:
            note = bundle.store.read_note(path)
            file_path = bundle.store._resolve(path)
            content = file_path.read_bytes()
        except (VaultError, OSError):
            raise ApiError(404, "not_found", _NOT_FOUND)
        etag = '"' + hashlib.sha256(content).hexdigest() + '"'
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers={"ETag": etag})
        return JSONResponse(
            {
                "vault": bundle.vault_id,
                "path": path,
                "markdown": note.body,
                "raw": note.raw,
                "frontmatter": normalize_json(note.frontmatter),
                "memory": inspect_memory_bytes(content),
                "etag": etag,
                "modified_at": int(file_path.stat().st_mtime),
            },
            headers={"ETag": etag, "Cache-Control": "private, no-cache"},
        )

    async def vault_search(self, request: Request) -> Response:
        ident = self._require_identity(request)
        bundle, scoped, _ = self._select_vault(ident, request.path_params["vault"])
        query = request.query_params.get("q", "").strip()
        if not query:
            return JSONResponse({"results": []})
        limit = self._query_int(request, "limit", 50, minimum=1, maximum=200)
        historical = request.query_params.get("include_historical", "false").lower()
        if historical not in ("true", "false"):
            raise ApiError(400, "invalid_request", "include_historical must be true or false")
        try:
            mode = resolve_mode(request.query_params.get("mode"), self.config.search.default_mode)
            hits = recall_hits(bundle.store, bundle.index, query, scoped.scopes,
                               include_historical=historical == "true",
                               mode=mode, semantic=self.semantic)
        except SemanticUnavailable as exc:
            raise ApiError(409, "semantic_unavailable", str(exc)) from None
        except ValueError as exc:
            raise ApiError(400, "invalid_request", str(exc)) from None
        folder = request.query_params.get("folder")
        tag = request.query_params.get("tag")
        results: list[dict] = []
        for hit in hits:
            if not path_allowed(hit.path, scoped.scopes):
                continue
            if folder and not hit.path.startswith(folder.rstrip("/") + "/"):
                continue
            if tag:
                try:
                    note = bundle.store.read_note(hit.path)
                except VaultError:
                    continue
                tags = note.frontmatter.get("tags", [])
                if isinstance(tags, str):
                    tags = [tags]
                if tag.lstrip("#") not in [str(value).lstrip("#") for value in tags]:
                    continue
            results.append(
                {
                    "path": hit.path,
                    "line": hit.line,
                    "snippet": hit.snippet,
                    "score": hit.score,
                    "headings": hit.headings,
                    "memory_state": hit.memory_state,
                    "memory_warnings": hit.warnings or [],
                    "retrieval_mode": hit.retrieval_mode,
                    **(
                        {"lexical_rank": hit.lexical_rank, "semantic_rank": hit.semantic_rank,
                         "similarity": hit.similarity}
                        if hit.retrieval_mode == "hybrid" else {}
                    ),
                }
            )
        return JSONResponse({"results": results[:limit]})

    async def vault_asset(self, request: Request) -> Response:
        ident = self._require_identity(request)
        bundle, scoped, _ = self._select_vault(ident, request.path_params["vault"])
        path = canonical_asset_path(request.path_params["path"])
        if path is None or not path_allowed(path, scoped.scopes):
            raise ApiError(404, "not_found", _NOT_FOUND)
        try:
            resolved = bundle.store._resolve(path)
            if not resolved.is_file():
                raise OSError
            data = resolved.read_bytes()
        except (VaultError, OSError):
            raise ApiError(404, "not_found", _NOT_FOUND)
        media_type = mimetypes.guess_type(path)[0] or "application/octet-stream"
        safe_inline = media_type.startswith("image/") and media_type != "image/svg+xml"
        disposition = "inline" if safe_inline else "attachment"
        return Response(
            data,
            media_type=media_type,
            headers={
                "Content-Disposition": f'{disposition}; filename="{Path(path).name}"',
                "Content-Security-Policy": "default-src 'none'; sandbox",
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "private, max-age=300",
            },
        )

    async def vault_tags(self, request: Request) -> Response:
        ident = self._require_identity(request)
        bundle, scoped, _ = self._select_vault(ident, request.path_params["vault"])
        tags: dict[str, list[str]] = {}
        inline = re.compile(r"(?<![\w/])#([A-Za-z0-9_/-]+)")
        for path in filter_paths(bundle.store.list_notes(), scoped.scopes):
            try:
                note = bundle.store.read_note(path)
            except VaultError:
                continue
            values = note.frontmatter.get("tags", [])
            if isinstance(values, str):
                values = [values]
            found = {str(value).lstrip("#") for value in values}
            found.update(inline.findall(note.body))
            for tag in found:
                if tag:
                    tags.setdefault(tag, []).append(path)
        return JSONResponse(
            {
                "tags": [
                    {"name": tag, "count": len(paths), "paths": sorted(paths)}
                    for tag, paths in sorted(tags.items())
                ]
            }
        )

    async def vault_links(self, request: Request) -> Response:
        ident = self._require_identity(request)
        bundle, scoped, _ = self._select_vault(ident, request.path_params["vault"])
        path = canonical_note_path(request.path_params["path"])
        if path is None or not path_allowed(path, scoped.scopes):
            raise ApiError(404, "not_found", _NOT_FOUND)
        visible = filter_paths(bundle.store.list_notes(), scoped.scopes)
        by_key: dict[str, str] = {}
        for candidate in visible:
            by_key[candidate.lower()] = candidate
            by_key[Path(candidate).stem.lower()] = candidate
        link_re = re.compile(r"!?(?:\[\[)([^\]|#]+)(?:#[^\]|]+)?(?:\|[^\]]+)?\]\]")
        try:
            note = bundle.store.read_note(path)
        except VaultError:
            raise ApiError(404, "not_found", _NOT_FOUND)
        outbound = []
        for raw in link_re.findall(note.body):
            target = raw.strip()
            resolved = by_key.get(target.lower()) or by_key.get(
                (target + ".md").lower()
            )
            outbound.append(
                {"target": target, "path": resolved, "broken": resolved is None}
            )
        inbound = []
        aliases = {path.lower(), Path(path).stem.lower()}
        for candidate in visible:
            if candidate == path:
                continue
            try:
                body = bundle.store.read_note(candidate).body
            except VaultError:
                continue
            if any(raw.strip().lower() in aliases for raw in link_re.findall(body)):
                inbound.append(candidate)
        return JSONResponse({"path": path, "outbound": outbound, "inbound": inbound})

    # -- B4: lifecycle and aggregated git audit -------------------------------

    async def admin_vault_action(self, request: Request) -> Response:
        self._require_identity(request, admin=True)
        vault = request.path_params["vault"]
        action = request.path_params["action"]
        if action == "provision":
            result = self.vault_manager.provision(vault)
            return JSONResponse(
                {
                    "vault": result.vault_id,
                    "created": result.created_dir,
                    "initialized_git": result.initialized_git,
                    "seeded": result.seeded,
                    "commit": result.commit,
                }
            )
        if action == "repair":
            result = self.vault_manager.repair(vault)
            return JSONResponse(
                {
                    "vault": result.vault_id,
                    "initialized_git": result.initialized_git,
                    "baseline_commit": result.baseline_commit,
                    "indexed_notes": result.indexed_notes,
                }
            )
        if action == "archive":
            path = self.vault_manager.archive(vault)
            return JSONResponse(
                {"vault": vault, "archived": True, "archive": str(path)}
            )
        raise ApiError(404, "not_found", _NOT_FOUND)

    async def commit_audit(self, request: Request) -> Response:
        ident = self._require_identity(request)
        principal = self._api_principal(ident)
        vault_filter = request.query_params.get("vault")
        actor_filter = (
            request.query_params.get("user") or request.query_params.get("actor", "")
        ).lower()
        path_filter = request.query_params.get("path")
        since = self._query_time(request, "from")
        until = self._query_time(request, "to")
        limit = self._query_int(request, "limit", 100, minimum=1, maximum=500)
        events: list[dict] = []
        for grant in self.vault_access.grants(principal):
            # Cross-account path grants never expose whole-vault Git history:
            # a commit can touch multiple paths outside the granted slice.
            # Admins retain the macro timeline.
            if not ident.is_admin and grant.relation != "owner":
                continue
            if vault_filter and grant.vault_id != vault_filter:
                continue
            bundle = self.vault_manager.get(grant.vault_id)
            for commit in bundle.git.log(limit=limit, path=path_filter):
                if (
                    actor_filter
                    and actor_filter not in commit.actor.lower()
                    and actor_filter not in commit.subject.lower()
                ):
                    continue
                try:
                    commit_ts = int(
                        datetime.fromisoformat(
                            commit.iso_date.replace("Z", "+00:00")
                        ).timestamp()
                    )
                except ValueError:
                    commit_ts = 0
                if since is not None and commit_ts < since:
                    continue
                if until is not None and commit_ts > until:
                    continue
                events.append(
                    {
                        "vault": grant.vault_id,
                        "sha": commit.sha,
                        "actor": commit.actor,
                        "subject": commit.subject,
                        "date": commit.iso_date,
                        "diff": bundle.git.diff_summary(commit.sha),
                    }
                )
        events.sort(key=lambda item: item["date"], reverse=True)
        return JSONResponse({"commits": events[:limit]})
