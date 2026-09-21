#!/usr/bin/env python3
"""Inventory GitHub community-health files and detect versioned upstream drift."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


API_ROOT = "https://api.github.com"
CONTRIBUTOR_COVENANT_REPOSITORY = "EthicalSource/contributor_covenant"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_POLICY_BYTES = 1024 * 1024
MAX_REGISTRY_BYTES = 1024 * 1024
MAX_REGISTRY_ENTRIES = 256
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
VERSION_PATTERN = re.compile(r"\d+(?:\.\d+){1,2}\Z")
CONTRIBUTOR_COVENANT_PATH = re.compile(
    r"content/version/(?P<path_version>\d+(?:/\d+){1,2})/code_of_conduct\.md\Z"
)
CONTRIBUTOR_COVENANT_ATTRIBUTION = re.compile(
    r"Contributor Covenant, version (?P<version>\d+(?:\.\d+){1,2})",
    re.IGNORECASE,
)
ALLOWED_KINDS = {"file", "directory", "any"}
ALLOWED_TRACKERS = {"none", "contributor-covenant"}
ALLOWED_SCOPES = {
    "github-community-health",
    "github-community-profile",
    "repo-scaffold-extension",
}


class AuditError(RuntimeError):
    """Raised when an audit input or upstream response is unsafe or invalid."""


class DuplicateJsonMember(ValueError):
    """Raised when a registry uses ambiguous duplicate JSON members."""


class RejectRedirectHandler(HTTPRedirectHandler):
    """Reject redirects so an optional workflow token stays on the API host."""

    def redirect_request(
        self,
        request: Any,
        response: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> Request | None:
        raise AuditError("GitHub API redirects are not allowed")


GITHUB_API_OPENER = build_opener(RejectRedirectHandler())


@dataclass(frozen=True)
class RegistryEntry:
    """One logical community-health surface and its supported local locations."""

    identifier: str
    label: str
    scope: str
    kind: str
    candidates: tuple[str, ...]
    tracker: str
    allow_multiple: bool = False


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while rejecting ambiguous duplicate member names."""
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise DuplicateJsonMember(f"duplicate JSON member {key!r}")
        document[key] = value
    return document


class GitHubClient:
    """Small bounded client for read-only GitHub API requests."""

    def __init__(self, token: str | None = None, timeout: float = 30.0) -> None:
        self.token = token
        self.timeout = timeout

    def get_json(self, endpoint: str) -> Any:
        if endpoint.startswith(("/", "http:")) or ".." in endpoint.split("/"):
            raise AuditError(f"unsafe GitHub API endpoint: {endpoint!r}")
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "repo-scaffold-community-health-checker",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = Request(f"{API_ROOT}/{endpoint}", headers=headers)
        try:
            with GITHUB_API_OPENER.open(request, timeout=self.timeout) as response:
                payload = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            raise AuditError(
                f"GitHub API returned HTTP {error.code} for {endpoint}"
            ) from error
        except (OSError, URLError) as error:
            raise AuditError(
                f"GitHub API request failed for {endpoint}: {error}"
            ) from error
        if len(payload) > MAX_RESPONSE_BYTES:
            raise AuditError(f"GitHub API response is too large for {endpoint}")
        try:
            return json.loads(
                payload.decode("utf-8"), object_pairs_hook=unique_json_object
            )
        except (
            UnicodeError,
            ValueError,
            RecursionError,
        ) as error:
            raise AuditError(
                f"GitHub API returned invalid JSON for {endpoint}"
            ) from error


def _require_string(document: dict[str, object], key: str, location: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AuditError(f"{location}.{key} must be a non-empty string")
    return value


def _safe_relative_path(value: object, location: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuditError(f"{location} must be a non-empty relative path")
    path = PurePosixPath(value)
    if (
        not path.parts
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in value
        or any(PureWindowsPath(part).drive for part in path.parts)
        or path.as_posix() != value
    ):
        raise AuditError(f"{location} must be a safe POSIX repository path")
    return value


def parse_registry(document: object) -> list[RegistryEntry]:
    if not isinstance(document, dict) or document.get("schema-version") != 1:
        raise AuditError("tracker registry must use schema-version 1")
    raw_files = document.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise AuditError("tracker registry files must be a non-empty list")
    if len(raw_files) > MAX_REGISTRY_ENTRIES:
        raise AuditError("tracker registry files exceeds the entry limit")
    entries: list[RegistryEntry] = []
    seen: set[str] = set()
    for index, value in enumerate(raw_files):
        location = f"files[{index}]"
        if not isinstance(value, dict):
            raise AuditError(f"{location} must be an object")
        identifier = _require_string(value, "id", location)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", identifier) or identifier in seen:
            raise AuditError(f"{location}.id must be unique snake_case")
        label = _require_string(value, "label", location)
        scope = _require_string(value, "scope", location)
        kind = _require_string(value, "kind", location)
        tracker = _require_string(value, "tracker", location)
        candidates = value.get("candidates")
        allow_multiple = value.get("allow_multiple", False)
        if scope not in ALLOWED_SCOPES:
            raise AuditError(f"{location}.scope is unsupported: {scope}")
        if kind not in ALLOWED_KINDS:
            raise AuditError(f"{location}.kind is unsupported: {kind}")
        if tracker not in ALLOWED_TRACKERS:
            raise AuditError(f"{location}.tracker is unsupported: {tracker}")
        if not isinstance(allow_multiple, bool):
            raise AuditError(f"{location}.allow_multiple must be a boolean")
        if not isinstance(candidates, list) or not candidates:
            raise AuditError(f"{location}.candidates must be a non-empty list")
        parsed_candidates = tuple(
            _safe_relative_path(candidate, f"{location}.candidates[{candidate_index}]")
            for candidate_index, candidate in enumerate(candidates)
        )
        if len(set(parsed_candidates)) != len(parsed_candidates):
            raise AuditError(f"{location}.candidates must not contain duplicates")
        seen.add(identifier)
        entries.append(
            RegistryEntry(
                identifier,
                label,
                scope,
                kind,
                parsed_candidates,
                tracker,
                allow_multiple,
            )
        )
    return entries


def load_registry(path: Path) -> list[RegistryEntry]:
    try:
        if path.stat().st_size > MAX_REGISTRY_BYTES:
            raise AuditError(f"tracker registry exceeds the size limit: {path}")
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=unique_json_object
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        RecursionError,
    ) as error:
        raise AuditError(f"could not read tracker registry {path}: {error}") from error
    return parse_registry(document)


def is_link_or_reparse(path: Path) -> bool:
    metadata = path.lstat()
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def checked_repository_path(root: Path, relative: str) -> Path:
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    current = root
    for part in PurePosixPath(relative).parts:
        current /= part
        if os.path.lexists(current) and is_link_or_reparse(current):
            raise AuditError(f"refusing linked or reparse-point path: {relative}")
    return candidate


def _directory_files(root: Path, directory: Path) -> list[str]:
    try:
        candidates = sorted(directory.rglob("*"))
    except OSError as error:
        raise AuditError(
            f"could not enumerate community-health directory: {directory}"
        ) from error
    files: list[str] = []
    for path in candidates:
        relative = path.relative_to(root).as_posix()
        if is_link_or_reparse(path):
            raise AuditError(f"refusing linked or reparse-point path: {relative}")
        if path.is_file():
            files.append(relative)
    return files


def inventory_entry(root: Path, entry: RegistryEntry) -> dict[str, Any]:
    matches: list[list[str]] = []
    for relative in entry.candidates:
        candidate = checked_repository_path(root, relative)
        if not candidate.exists():
            continue
        if entry.kind == "file" and candidate.is_file():
            matches.append([relative])
        elif entry.kind == "directory" and candidate.is_dir():
            matches.append(_directory_files(root, candidate))
        elif entry.kind == "any":
            matches.append(
                [relative] if candidate.is_file() else _directory_files(root, candidate)
            )
    paths = [path for match in matches for path in match]
    multiple_locations = len(matches) > 1
    status = (
        "absent"
        if not matches
        else "ambiguous"
        if multiple_locations and not entry.allow_multiple
        else "present"
    )
    return {
        "id": entry.identifier,
        "label": entry.label,
        "scope": entry.scope,
        "tracker": entry.tracker,
        "status": status,
        "paths": paths,
        "details": (
            "No supported local path exists."
            if status == "absent"
            else "Multiple supported locations exist and may shadow one another."
            if status == "ambiguous"
            else "Multiple supported local locations are explicitly allowed."
            if multiple_locations
            else "Local file inventory only; no versioned upstream exists."
        ),
    }


def version_tuple(value: str) -> tuple[int, int, int]:
    if not VERSION_PATTERN.fullmatch(value):
        raise AuditError(f"invalid semantic version: {value!r}")
    components = [int(component) for component in value.split(".")]
    major, minor, patch = (components + [0, 0])[:3]
    return major, minor, patch


def local_contributor_covenant_version(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_POLICY_BYTES:
            raise AuditError(f"Code of Conduct is too large: {path}")
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise AuditError(f"could not read Code of Conduct {path}: {error}") from error
    match = CONTRIBUTOR_COVENANT_ATTRIBUTION.search(text)
    return match.group("version") if match else None


def latest_contributor_covenant(client: GitHubClient) -> dict[str, str]:
    branch = client.get_json(
        f"repos/{CONTRIBUTOR_COVENANT_REPOSITORY}/branches/release"
    )
    try:
        commit = branch["commit"]["sha"]
    except (KeyError, TypeError) as error:
        raise AuditError(
            "Contributor Covenant release branch response lacks a SHA"
        ) from error
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise AuditError("Contributor Covenant release branch SHA is invalid")
    tree = client.get_json(
        f"repos/{CONTRIBUTOR_COVENANT_REPOSITORY}/git/trees/{commit}?recursive=1"
    )
    raw_entries = tree.get("tree") if isinstance(tree, dict) else None
    if not isinstance(raw_entries, list) or tree.get("truncated") is not False:
        raise AuditError("Contributor Covenant source tree is missing or truncated")
    candidates: list[tuple[tuple[int, ...], str, str]] = []
    for value in raw_entries:
        path = value.get("path") if isinstance(value, dict) else None
        if not isinstance(path, str):
            continue
        match = CONTRIBUTOR_COVENANT_PATH.fullmatch(path)
        if match:
            version = match.group("path_version").replace("/", ".")
            candidates.append((version_tuple(version), version, path))
    if not candidates:
        raise AuditError(
            "Contributor Covenant source tree has no stable English policy"
        )
    _, version, path = max(candidates)
    return {
        "version": version,
        "commit": commit,
        "path": path,
        "url": f"https://github.com/{CONTRIBUTOR_COVENANT_REPOSITORY}/blob/{commit}/{path}",
    }


def _check_contributor_covenant(
    root: Path, result: dict[str, Any], upstream: dict[str, str]
) -> None:
    paths = result["paths"]
    if result["status"] != "present" or not isinstance(paths, list) or len(paths) != 1:
        return
    current = local_contributor_covenant_version(root / paths[0])
    if current is None:
        result["status"] = "unversioned"
        result["details"] = (
            "The policy is custom or its Contributor Covenant version is not detectable."
        )
        return
    latest = upstream["version"]
    result["current-version"] = current
    result["latest-version"] = latest
    result["upstream-url"] = upstream["url"]
    if version_tuple(current) < version_tuple(latest):
        result["status"] = "outdated"
        result["details"] = f"Contributor Covenant {current} is older than {latest}."
    elif version_tuple(current) == version_tuple(latest):
        result["status"] = "current"
        result["details"] = f"Contributor Covenant {current} matches upstream."
    else:
        result["status"] = "indeterminate"
        result["details"] = (
            f"Local version {current} is newer than upstream {latest}; verify provenance."
        )


def audit(
    root: Path,
    entries: list[RegistryEntry],
    repository: str,
    client: GitHubClient,
    checked_at: str,
) -> dict[str, Any]:
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise AuditError("repository must use OWNER/REPO syntax")
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    for entry in entries:
        try:
            results.append(inventory_entry(root, entry))
        except AuditError as error:
            errors.append(str(error))
            results.append(
                {
                    "id": entry.identifier,
                    "label": entry.label,
                    "scope": entry.scope,
                    "tracker": entry.tracker,
                    "status": "indeterminate",
                    "paths": [],
                    "details": str(error),
                }
            )
    profile: dict[str, object]
    try:
        raw_profile = client.get_json(f"repos/{repository}/community/profile")
        health = (
            raw_profile.get("health_percentage")
            if isinstance(raw_profile, dict)
            else None
        )
        if type(health) is not int or not 0 <= health <= 100:
            raise AuditError(
                "GitHub community profile response has invalid health_percentage"
            )
        profile = {
            "health-percentage": health,
            "status": "current" if health == 100 else "incomplete",
        }
    except AuditError as error:
        errors.append(str(error))
        profile = {"status": "indeterminate", "details": str(error)}
    covenant_results = [
        result for result in results if result["tracker"] == "contributor-covenant"
    ]
    if covenant_results:
        try:
            upstream = latest_contributor_covenant(client)
            for result in covenant_results:
                _check_contributor_covenant(root, result, upstream)
        except AuditError as error:
            errors.append(str(error))
            for result in covenant_results:
                if result["status"] == "present":
                    result["status"] = "indeterminate"
                    result["details"] = str(error)
    attention = profile.get("status") == "incomplete" or any(
        result["status"] in {"ambiguous", "outdated"} for result in results
    )
    indeterminate = bool(errors) or any(
        result["status"] == "indeterminate" for result in results
    )
    overall = (
        "indeterminate" if indeterminate else "attention" if attention else "current"
    )
    counts = {
        status: sum(result["status"] == status for result in results)
        for status in sorted({str(result["status"]) for result in results})
    }
    return {
        "schema-version": 1,
        "repository": repository,
        "checked-at": checked_at,
        "summary": {"status": overall, "counts": counts},
        "community-profile": profile,
        "files": results,
        "errors": errors,
    }


def markdown_table_cell(value: object) -> str:
    """Render one value without permitting it to add Markdown table cells/rows."""
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def markdown_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    profile = report["community-profile"]
    lines = [
        "<!-- repo-scaffold-community-health-drift -->",
        "# Community-health upstream report",
        "",
        f"- Repository: `{report['repository']}`",
        f"- Checked: `{report['checked-at']}`",
        f"- Overall status: **{summary['status']}**",
        f"- GitHub Community Profile: **{profile['status']}**"
        + (
            f" ({profile['health-percentage']}%)"
            if "health-percentage" in profile
            else ""
        ),
        "",
        "| Surface | Local path(s) | Upstream tracking | Status | Details |",
        "| --- | --- | --- | --- | --- |",
    ]
    for result in report["files"]:
        paths = result["paths"]
        path_text = (
            ", ".join(f"`{markdown_table_cell(path)}`" for path in paths)
            if paths
            else "_absent_"
        )
        tracker = result["tracker"] if result["tracker"] != "none" else "not versioned"
        lines.append(
            "| {label} | {paths} | {tracker} | {status} | {details} |".format(
                label=markdown_table_cell(result["label"]),
                paths=path_text,
                tracker=markdown_table_cell(tracker),
                status=markdown_table_cell(result["status"]),
                details=markdown_table_cell(result["details"]),
            )
        )
    errors = report["errors"]
    if errors:
        lines.extend(["", "## Indeterminate checks", ""])
        lines.extend(f"- {str(error).replace(chr(10), ' ')}" for error in errors)
    lines.extend(
        [
            "",
            "Project-authored policies without a versioned canonical upstream are inventoried as `not versioned`; they are not falsely treated as outdated.",
            "",
        ]
    )
    return "\n".join(lines)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(path) and is_link_or_reparse(path):
        raise AuditError(f"refusing linked or reparse-point output: {path}")
    path.write_text(text, encoding="utf-8", newline="\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--registry", type=Path, default=Path(".github/community-health-trackers.json")
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.repository_root.resolve()
    registry_path = (
        args.registry if args.registry.is_absolute() else root / args.registry
    )
    try:
        entries = load_registry(registry_path)
        report = audit(
            root,
            entries,
            args.repository,
            GitHubClient(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")),
            datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        )
        write_text(
            args.json_output, json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        )
        write_text(args.markdown_output, markdown_report(report))
    except AuditError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    status = report["summary"]["status"]
    print(f"Community-health upstream status: {status}")
    return 0 if status == "current" else 1 if status == "attention" else 2


if __name__ == "__main__":
    raise SystemExit(main())
