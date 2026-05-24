import json
import os
import re

from ..models.extension import ExtensionInfo, ExtensionManifest
from ..platform.base import AbstractPlatform, VSCodePaths

# UUID-style directory names (pre-release temp dirs) - skip them
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class ExtensionScanner:

    def __init__(self, platform: AbstractPlatform, paths: VSCodePaths):
        self._platform = platform
        self._paths = paths

    def scan(self) -> list:
        catalog = self._load_catalog()
        ext_dir = self._paths.extensions_dir

        if not self._platform.path_exists(ext_dir):
            return []

        # When the catalog is populated use it as the authoritative list of
        # active extension directories - this ensures we read the correct
        # version after updates (VS Code leaves old versioned dirs on disk
        # until the next restart).
        active_dirs = set(catalog.keys()) if catalog else None

        candidates = []
        for entry in sorted(self._platform.list_directory(ext_dir)):
            if entry.startswith(".") or entry == "extensions.json":
                continue
            if _UUID_RE.match(entry):
                continue
            if active_dirs is not None and entry.lower() not in active_dirs:
                continue

            pkg_path = os.path.join(ext_dir, entry, "package.json")
            if not self._platform.path_exists(pkg_path):
                continue

            try:
                raw = self._platform.read_json_file(pkg_path)
            except (json.JSONDecodeError, OSError):
                continue

            manifest = self._parse_manifest(raw)
            cat_entry = catalog.get(entry.lower(), {})

            if cat_entry.get("source"):
                manifest.install_source = cat_entry["source"]
            if cat_entry.get("is_pre_release"):
                manifest.is_pre_release = True

            candidates.append(ExtensionInfo(
                extension_id=f"{manifest.publisher}.{manifest.name}".lower(),
                uuid=cat_entry.get("uuid", ""),
                directory=os.path.join(ext_dir, entry),
                manifest=manifest,
            ))

        # Deduplicate by extension_id keeping the highest version - guards
        # against multiple installs when no catalog is available.
        if active_dirs is None:
            return self._deduplicate(candidates)
        return candidates

    @staticmethod
    def _deduplicate(extensions: list) -> list:
        from packaging.version import Version, InvalidVersion
        best: dict = {}
        for ext in extensions:
            eid = ext.extension_id
            if eid not in best:
                best[eid] = ext
                continue
            try:
                if Version(ext.manifest.version) > Version(best[eid].manifest.version):
                    best[eid] = ext
            except InvalidVersion:
                pass
        return list(best.values())

    def _load_catalog(self) -> dict:
        catalog_path = os.path.join(self._paths.extensions_dir, "extensions.json")
        if not self._platform.path_exists(catalog_path):
            return {}
        try:
            entries = self._platform.read_json_file(catalog_path)
        except (json.JSONDecodeError, OSError):
            return {}

        result = {}
        for e in entries:
            rel = e.get("relativeLocation", "")
            if not rel:
                continue
            ident = e.get("identifier", {})
            meta = e.get("metadata", {})
            result[rel.lower()] = {
                "uuid": ident.get("uuid", ""),
                "source": meta.get("source", ""),
                "updated": meta.get("updated", False),
                "is_pre_release": meta.get("isPreReleaseVersion", False),
                "publisher_display_name": meta.get("publisherDisplayName", ""),
            }
        return result

    def _parse_manifest(self, raw: dict) -> ExtensionManifest:
        repo = raw.get("repository", "")
        if isinstance(repo, dict):
            repo = repo.get("url", "")

        raw_display = raw.get("displayName", "") or ""
        name = raw.get("name", "")
        # VS Code uses %variable% placeholders for localized strings - fall back to name
        display_name = raw_display if raw_display and not raw_display.startswith("%") else name

        meta = raw.get("__metadata", {})
        contributes = raw.get("contributes", {})

        cfg = contributes.get("configuration", {})
        if isinstance(cfg, list):
            cfg_keys = []
            for c in cfg:
                if isinstance(c, dict):
                    cfg_keys.extend(c.get("properties", {}).keys())
        elif isinstance(cfg, dict):
            cfg_keys = list(cfg.get("properties", {}).keys())
        else:
            cfg_keys = []

        has_mcp = bool(
            contributes.get("mcpServerDefinitionProviders")
            or contributes.get("modelContextProtocol")
        )

        return ExtensionManifest(
            name=name,
            display_name=display_name,
            version=raw.get("version", ""),
            publisher=raw.get("publisher", ""),
            description=raw.get("description", ""),
            categories=raw.get("categories", []) or [],
            enabled_api_proposals=raw.get("enabledApiProposals", []) or [],
            contributes_config_keys=cfg_keys,
            repository_url=repo or "",
            license=raw.get("license", "") or "",
            engines_vscode=raw.get("engines", {}).get("vscode", ""),
            extension_dependencies=raw.get("extensionDependencies", []) or [],
            has_mcp_providers=has_mcp,
            install_source=meta.get("source", "unknown"),
            is_pre_release=meta.get("isPreReleaseVersion", False),
            installed_timestamp=meta.get("installedTimestamp", 0),
            raw=raw,
        )
