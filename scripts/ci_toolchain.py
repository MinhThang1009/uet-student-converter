#!/usr/bin/env python3
"""Validate centralized CI tool pins, run them, and detect release drift."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener


POLICY_FIELDS = {
    "schema-version",
    "documentation-python",
    "tooling-python-minimum",
    "npm-tools",
    "standalone-tools",
}
NPM_TOOL_FIELDS = {"package", "version"}
TOOL_FIELDS = {
    "repository",
    "version",
    "tag-template",
    "asset-template",
    "archive-format",
    "executable-path-template",
    "sha256",
}
TOOL_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
NPM_PACKAGE = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
PYTHON_FEATURE = re.compile(r"^3\.(0|[1-9]\d*)$")
STABLE_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_RESPONSE_BYTES = 1_000_000
MAX_POLICY_BYTES = 64 * 1024
MAX_POLICY_TOOLS = 32
MARKDOWNLINT_GLOBS = ("**/*.md",)


class ToolchainError(ValueError):
    """Raised when a CI toolchain policy or upstream release is invalid."""


class RejectRedirectHandler(HTTPRedirectHandler):
    """Reject redirects so reviewed upstreams remain fixed destinations."""

    def redirect_request(
        self,
        request: Any,
        response: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> Request | None:
        raise ToolchainError("upstream redirects are not allowed")


GITHUB_API_OPENER = build_opener(RejectRedirectHandler())
NPM_REGISTRY_OPENER = build_opener(RejectRedirectHandler())


@dataclass(frozen=True)
class NpmToolPin:
    """A reviewed npm package used by repository tooling."""

    name: str
    package: str
    version: str


@dataclass(frozen=True)
class ToolPin:
    """A reviewed standalone CI tool release and artifact digest."""

    name: str
    repository: str
    version: str
    tag_template: str
    asset_template: str
    archive_format: str
    executable_path_template: str
    sha256: str

    @property
    def tag_name(self) -> str:
        """Render the expected upstream release tag from the reviewed version."""
        return self.tag_template.replace("{version}", self.version)

    @property
    def asset_name(self) -> str:
        """Render the expected release asset name from the reviewed version."""
        return self.asset_template.replace("{version}", self.version)

    @property
    def executable_path(self) -> str:
        """Render the executable member path inside the reviewed archive."""
        return self.executable_path_template.replace("{version}", self.version)


@dataclass(frozen=True)
class CiToolchainPolicy:
    """Normalized bootstrap runtime, npm-tool, and standalone-tool policy."""

    documentation_python: str
    tooling_python_minimum: str
    npm_tools: tuple[NpmToolPin, ...]
    tools: tuple[ToolPin, ...]


def reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while rejecting duplicate member names."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ToolchainError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def parse_npm_tool(name: str, value: Any) -> NpmToolPin:
    """Validate and normalize one reviewed npm tool entry."""
    if TOOL_NAME.fullmatch(name) is None:
        raise ToolchainError(f"invalid npm tool name: {name!r}")
    if not isinstance(value, dict):
        raise ToolchainError(f"npm-tools.{name} must be an object")
    unexpected = sorted(set(value) - NPM_TOOL_FIELDS)
    missing = sorted(NPM_TOOL_FIELDS - set(value))
    if unexpected:
        raise ToolchainError(
            f"npm-tools.{name} has unknown fields: {', '.join(unexpected)}"
        )
    if missing:
        raise ToolchainError(
            f"npm-tools.{name} is missing fields: {', '.join(missing)}"
        )

    package = value["package"]
    version = value["version"]
    if not isinstance(package, str) or NPM_PACKAGE.fullmatch(package) is None:
        raise ToolchainError(f"npm-tools.{name}.package must be a static npm name")
    if not isinstance(version, str) or STABLE_SEMVER.fullmatch(version) is None:
        raise ToolchainError(
            f"npm-tools.{name}.version must be a stable SemVer release"
        )
    return NpmToolPin(name=name, package=package, version=version)


def parse_tool(name: str, value: Any) -> ToolPin:
    """Validate and normalize one standalone tool entry."""
    if TOOL_NAME.fullmatch(name) is None:
        raise ToolchainError(f"invalid standalone tool name: {name!r}")
    if not isinstance(value, dict):
        raise ToolchainError(f"standalone-tools.{name} must be an object")
    unexpected = sorted(set(value) - TOOL_FIELDS)
    missing = sorted(TOOL_FIELDS - set(value))
    if unexpected:
        raise ToolchainError(
            f"standalone-tools.{name} has unknown fields: {', '.join(unexpected)}"
        )
    if missing:
        raise ToolchainError(
            f"standalone-tools.{name} is missing fields: {', '.join(missing)}"
        )

    repository = value["repository"]
    version = value["version"]
    tag_template = value["tag-template"]
    asset_template = value["asset-template"]
    archive_format = value["archive-format"]
    executable_path_template = value["executable-path-template"]
    sha256 = value["sha256"]
    if not isinstance(repository, str) or REPOSITORY.fullmatch(repository) is None:
        raise ToolchainError(
            f"standalone-tools.{name}.repository must be an owner/repository name"
        )
    if not isinstance(version, str) or STABLE_SEMVER.fullmatch(version) is None:
        raise ToolchainError(
            f"standalone-tools.{name}.version must be a stable SemVer release"
        )
    if (
        not isinstance(tag_template, str)
        or tag_template.count("{version}") != 1
        or re.fullmatch(r"[A-Za-z0-9._-]*\{version\}[A-Za-z0-9._-]*", tag_template)
        is None
    ):
        raise ToolchainError(
            f"standalone-tools.{name}.tag-template must contain exactly one "
            "{version} token and only tag-safe characters"
        )
    if (
        not isinstance(asset_template, str)
        or asset_template.count("{version}") != 1
        or re.fullmatch(r"[A-Za-z0-9._-]*\{version\}[A-Za-z0-9._-]*", asset_template)
        is None
        or asset_template.startswith("-")
    ):
        raise ToolchainError(
            f"standalone-tools.{name}.asset-template must contain exactly one "
            "{version} token and only safe filename characters"
        )
    if archive_format not in {"tar.gz", "tar.xz"}:
        raise ToolchainError(
            f"standalone-tools.{name}.archive-format must be tar.gz or tar.xz"
        )
    if not isinstance(executable_path_template, str):
        raise ToolchainError(
            f"standalone-tools.{name}.executable-path-template must be a string"
        )
    executable_without_token = executable_path_template.replace("{version}", "")
    executable_parts = executable_path_template.split("/")
    rendered_executable_parts = executable_path_template.replace(
        "{version}", version
    ).split("/")
    if (
        executable_path_template.count("{version}") > 1
        or "{" in executable_without_token
        or "}" in executable_without_token
        or "\\" in executable_path_template
        or executable_path_template.startswith("/")
        or any(part in {"", ".", ".."} for part in executable_parts)
        or any(
            part.startswith("-") or re.fullmatch(r"[A-Za-z0-9._-]+", part) is None
            for part in rendered_executable_parts
        )
        or PurePosixPath(executable_path_template).is_absolute()
    ):
        raise ToolchainError(
            f"standalone-tools.{name}.executable-path-template must be a safe "
            "relative archive member with at most one {version} token"
        )
    if not isinstance(sha256, str) or SHA256.fullmatch(sha256) is None:
        raise ToolchainError(
            f"standalone-tools.{name}.sha256 must be 64 lowercase hex characters"
        )
    return ToolPin(
        name=name,
        repository=repository,
        version=version,
        tag_template=tag_template,
        asset_template=asset_template,
        archive_format=archive_format,
        executable_path_template=executable_path_template,
        sha256=sha256,
    )


def parse_policy(document: Any) -> CiToolchainPolicy:
    """Validate and normalize a decoded CI toolchain policy."""
    if not isinstance(document, dict):
        raise ToolchainError("policy root must be an object")
    unexpected = sorted(set(document) - POLICY_FIELDS)
    missing = sorted(POLICY_FIELDS - set(document))
    if unexpected:
        raise ToolchainError(f"unknown fields: {', '.join(unexpected)}")
    if missing:
        raise ToolchainError(f"missing fields: {', '.join(missing)}")
    if type(document["schema-version"]) is not int or document["schema-version"] != 1:
        raise ToolchainError("schema-version must be the integer 1")
    if document["documentation-python"] != "3.x":
        raise ToolchainError(
            "documentation-python must be the rolling stable CPython selector 3.x"
        )
    tooling_python_minimum = document["tooling-python-minimum"]
    if (
        not isinstance(tooling_python_minimum, str)
        or PYTHON_FEATURE.fullmatch(tooling_python_minimum) is None
    ):
        raise ToolchainError(
            "tooling-python-minimum must be a stable CPython 3.x feature release"
        )
    raw_tools = document["standalone-tools"]
    raw_npm_tools = document["npm-tools"]
    if not isinstance(raw_npm_tools, dict):
        raise ToolchainError("npm-tools must be an object")
    if not isinstance(raw_tools, dict):
        raise ToolchainError("standalone-tools must be an object")
    if len(raw_npm_tools) > MAX_POLICY_TOOLS:
        raise ToolchainError(
            f"npm-tools must not contain more than {MAX_POLICY_TOOLS} entries"
        )
    if len(raw_tools) > MAX_POLICY_TOOLS:
        raise ToolchainError(
            f"standalone-tools must not contain more than {MAX_POLICY_TOOLS} entries"
        )
    npm_tools = tuple(
        parse_npm_tool(name, raw_npm_tools[name]) for name in sorted(raw_npm_tools)
    )
    tools = tuple(parse_tool(name, raw_tools[name]) for name in sorted(raw_tools))
    return CiToolchainPolicy(
        documentation_python="3.x",
        tooling_python_minimum=tooling_python_minimum,
        npm_tools=npm_tools,
        tools=tools,
    )


def load_policy(path: Path) -> CiToolchainPolicy:
    """Read a UTF-8 JSON policy with duplicate-member rejection."""
    try:
        with path.open("rb") as policy_file:
            payload = policy_file.read(MAX_POLICY_BYTES + 1)
        if len(payload) > MAX_POLICY_BYTES:
            raise ToolchainError(
                f"policy exceeds the {MAX_POLICY_BYTES}-byte size limit"
            )
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicate_json_pairs,
        )
    except ToolchainError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        raise ToolchainError(f"could not read {path}: {error}") from error
    return parse_policy(document)


def github_output_lines(policy: CiToolchainPolicy) -> list[str]:
    """Render stable single-line outputs for GitHub Actions."""
    lines = [
        f"documentation_python={policy.documentation_python}",
        f"tooling_python_minimum={policy.tooling_python_minimum}",
    ]
    for npm_tool in policy.npm_tools:
        prefix = npm_tool.name.replace("-", "_")
        lines.append(f"{prefix}_package={npm_tool.package}")
        lines.append(f"{prefix}_version={npm_tool.version}")
    for standalone_tool in policy.tools:
        prefix = standalone_tool.name.replace("-", "_")
        lines.append(f"{prefix}_repository={standalone_tool.repository}")
        lines.append(f"{prefix}_version={standalone_tool.version}")
        lines.append(f"{prefix}_tag={standalone_tool.tag_name}")
        lines.append(f"{prefix}_asset={standalone_tool.asset_name}")
        lines.append(f"{prefix}_archive_format={standalone_tool.archive_format}")
        lines.append(f"{prefix}_executable_path={standalone_tool.executable_path}")
        lines.append(f"{prefix}_sha256={standalone_tool.sha256}")
    return lines


def fetch_latest_release(tool: ToolPin, *, opener: Any | None = None) -> Any:
    """Fetch one bounded public GitHub release document without credentials."""
    url = f"https://api.github.com/repos/{tool.repository}/releases/latest"
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "repo-scaffold-ci-toolchain",
        },
    )
    try:
        with (opener or GITHUB_API_OPENER.open)(request, timeout=15) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, OSError) as error:
        raise ToolchainError(
            f"could not query latest release for {tool.repository}: {error}"
        ) from error
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ToolchainError(f"release response for {tool.repository} is too large")
    try:
        return json.loads(payload, object_pairs_hook=reject_duplicate_json_pairs)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ToolchainError(
            f"latest release for {tool.repository} returned invalid JSON: {error}"
        ) from error


def fetch_latest_npm_tool(tool: NpmToolPin, *, opener: Any | None = None) -> Any:
    """Fetch one bounded latest-version document from the public npm registry."""
    url = f"https://registry.npmjs.org/{quote(tool.package, safe='')}/latest"
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "repo-scaffold-ci-toolchain",
        },
    )
    try:
        with (opener or NPM_REGISTRY_OPENER.open)(request, timeout=15) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, OSError) as error:
        raise ToolchainError(
            f"could not query latest npm release for {tool.package}: {error}"
        ) from error
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ToolchainError(f"npm response for {tool.package} is too large")
    try:
        return json.loads(payload, object_pairs_hook=reject_duplicate_json_pairs)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ToolchainError(
            f"latest npm release for {tool.package} returned invalid JSON: {error}"
        ) from error


def verify_latest_npm_tool(tool: NpmToolPin, document: Any) -> None:
    """Compare one reviewed npm pin with the registry's latest stable version."""
    if not isinstance(document, dict) or not isinstance(document.get("version"), str):
        raise ToolchainError(
            f"latest npm release for {tool.package} returned no version"
        )
    if document["version"] != tool.version:
        raise ToolchainError(
            f"{tool.name} policy pins {tool.version}, but latest npm release is "
            f"{document['version']!r}; review the release and update the policy"
        )


def verify_latest_release(tool: ToolPin, document: Any) -> None:
    """Compare one reviewed pin and digest with the latest GitHub release."""
    if not isinstance(document, dict):
        raise ToolchainError(f"latest release for {tool.repository} must be an object")
    expected_tag = tool.tag_name
    if document.get("tag_name") != expected_tag:
        raise ToolchainError(
            f"{tool.name} policy pins {expected_tag}, but latest release is "
            f"{document.get('tag_name')!r}; review the release and update the policy"
        )
    assets = document.get("assets")
    if not isinstance(assets, list):
        raise ToolchainError(f"latest release for {tool.repository} has no asset list")
    matches = [
        asset
        for asset in assets
        if isinstance(asset, dict) and asset.get("name") == tool.asset_name
    ]
    if len(matches) != 1:
        raise ToolchainError(
            f"latest release for {tool.repository} must contain exactly one "
            f"{tool.asset_name!r} asset"
        )
    expected_digest = f"sha256:{tool.sha256}"
    if matches[0].get("digest") != expected_digest:
        raise ToolchainError(
            f"{tool.name} asset digest differs from the reviewed policy"
        )


def verify_latest_releases(policy: CiToolchainPolicy) -> None:
    """Verify every reviewed tool pin against its current upstream release."""
    for npm_tool in policy.npm_tools:
        verify_latest_npm_tool(npm_tool, fetch_latest_npm_tool(npm_tool))
    for standalone_tool in policy.tools:
        verify_latest_release(standalone_tool, fetch_latest_release(standalone_tool))


def resolve_path_executable(name: str, *, forbidden_root: Path) -> str | None:
    """Resolve an executable only from absolute PATH entries outside the repository."""
    forbidden = forbidden_root.resolve(strict=True)
    for raw_directory in os.environ.get("PATH", "").split(os.pathsep):
        if not raw_directory:
            continue
        directory = Path(raw_directory.strip('"'))
        if not directory.is_absolute():
            continue
        candidate = shutil.which(name, path=str(directory))
        if candidate is None:
            continue
        try:
            resolved = Path(candidate).resolve(strict=True)
            resolved.relative_to(forbidden)
        except ValueError:
            return str(resolved)
        except (OSError, RuntimeError):
            continue
    return None


def run_markdownlint(policy: CiToolchainPolicy) -> int:
    """Run the policy-pinned markdownlint package without a shell."""
    matches = [tool for tool in policy.npm_tools if tool.name == "markdownlint-cli2"]
    if len(matches) != 1:
        raise ToolchainError(
            "npm-tools must define exactly one markdownlint-cli2 entry"
        )
    executable_names = ("npx.cmd", "npx") if os.name == "nt" else ("npx",)
    npx = next(
        (
            resolved
            for name in executable_names
            if (resolved := resolve_path_executable(name, forbidden_root=Path.cwd()))
        ),
        None,
    )
    if npx is None:
        raise ToolchainError(
            "npx is unavailable on an absolute PATH entry outside the repository"
        )
    tool = matches[0]
    command = [npx, "--yes", f"{tool.package}@{tool.version}", *MARKDOWNLINT_GLOBS]
    try:
        result = subprocess.run(  # noqa: S603 - executable is resolved safely
            command,
            cwd=Path.cwd(),
            check=False,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ToolchainError(f"could not run markdownlint-cli2: {error}") from error
    return result.returncode


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path(".github/ci-toolchain.json"),
        help="Path to the CI toolchain policy",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate", help="Validate the policy")
    subparsers.add_parser(
        "emit-github-output",
        help="Emit bootstrap runtime and reviewed tool outputs",
    )
    subparsers.add_parser(
        "verify-latest-releases",
        help="Compare reviewed pins and digests with upstream releases",
    )
    subparsers.add_parser(
        "run-markdownlint",
        help="Run the policy-pinned markdownlint-cli2 package",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the selected CI toolchain operation."""
    args = parse_args(argv)
    try:
        policy = load_policy(args.policy)
        if args.command == "validate":
            print(
                "CI toolchain policy is valid: "
                f"{len(policy.npm_tools)} npm tool(s), "
                f"{len(policy.tools)} standalone tool(s)"
            )
        elif args.command == "emit-github-output":
            print("\n".join(github_output_lines(policy)))
        elif args.command == "verify-latest-releases":
            verify_latest_releases(policy)
            print("CI tool pins match the latest upstream releases.")
        else:
            return run_markdownlint(policy)
    except ToolchainError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
