#!/usr/bin/env python3
"""Validate rendered Markdown and GitHub template conventions."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml
from markdown_it import MarkdownIt
from markdown_it.rules_inline.backticks import backtick as parse_backtick
from markdown_it.rules_inline.state_inline import StateInline
from markdown_it.token import Token


SKIPPED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "mutants",
    "node_modules",
    "vendor",
    "venv",
}
SCAFFOLD_MARKER = re.compile(r"\{\{REPO_SCAFFOLD_[A-Z0-9_]+\}\}")
HEADING = re.compile(r"(?m)^(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$")
NUMBERED_SECTION = re.compile(r"^(\d+)\.\s+\S")
NUMBERED_SUBSECTION = re.compile(r"^(\d+)\.(\d+)\s+\S")
COMMONMARK = MarkdownIt("commonmark")
HTML_IMAGE = re.compile(r"<img(?:[ \t\r\n]|/?>)", re.IGNORECASE)
CENTERED_DIV = re.compile(r'<div\s+align=["\']center["\']\s*>', re.IGNORECASE)
LONG_README_SECTION_COUNT = 8
CONTRIBUTOR_COVENANT_ATTRIBUTION = re.compile(
    r"Contributor Covenant,\s*version\s+(\d+)\.(\d+)(?:\.(\d+))?",
    re.IGNORECASE,
)
MINIMUM_CONTRIBUTOR_COVENANT_VERSION = (3, 0, 0)
ISSUE_FORM_ID = re.compile(r"^[0-9A-Za-z_-]+$")
ISSUE_FORM_INPUT_TYPES = {
    "checkboxes",
    "dropdown",
    "input",
    "markdown",
    "textarea",
    "upload",
}
ISSUE_FORM_BODY_KEYS = {"attributes", "id", "type", "validations"}


class UniqueKeyBaseLoader(yaml.BaseLoader):
    """YAML loader that preserves text and rejects duplicate keys."""

    def construct_mapping(
        self, node: yaml.nodes.MappingNode, deep: bool = False
    ) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as error:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable mapping key",
                    key_node.start_mark,
                ) from error
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def load_yaml_text(text: str) -> Any:
    """Parse YAML while converting recursive parser failures into YAML errors."""
    try:
        return yaml.load(text, Loader=UniqueKeyBaseLoader)
    except RecursionError as error:
        raise yaml.YAMLError("YAML nesting exceeds parser limit") from error


def is_project_markdown(path: Path, repository_root: Path) -> bool:
    """Return whether a Markdown file belongs to the project source."""
    relative = path.relative_to(repository_root)
    return not any(part in SKIPPED_DIRECTORIES for part in relative.parts)


def is_link_or_reparse(path: Path) -> bool:
    """Return whether an existing path is a symlink or Windows reparse point."""
    if path.is_symlink():
        return True
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def path_has_link_or_reparse(path: Path, repository_root: Path) -> bool:
    """Return whether a repository-relative path crosses a link-like boundary."""
    boundary = Path(os.path.abspath(repository_root))
    candidate = Path(os.path.abspath(path))
    try:
        relative = candidate.relative_to(boundary)
    except ValueError:
        return True
    current = boundary
    for part in (None, *relative.parts):
        if part is not None:
            current /= part
        if is_link_or_reparse(current):
            return True
        if not os.path.lexists(current):
            break
    return False


def markdown_inventory(repository_root: Path) -> tuple[list[Path], list[Path]]:
    """Return Markdown files and rejected linked paths without traversing links."""
    repository_root = Path(os.path.abspath(repository_root))
    files: list[Path] = []
    rejected: list[Path] = []
    if path_has_link_or_reparse(repository_root, repository_root):
        return files, [repository_root]
    for directory, child_directories, filenames in os.walk(
        repository_root, topdown=True, followlinks=False
    ):
        current = Path(directory)
        safe_children: list[str] = []
        for name in sorted(child_directories):
            child = current / name
            relative = child.relative_to(repository_root)
            if set(relative.parts) & SKIPPED_DIRECTORIES:
                continue
            if is_link_or_reparse(child):
                rejected.append(child)
            else:
                safe_children.append(name)
        child_directories[:] = safe_children
        for name in sorted(filenames):
            if not name.lower().endswith(".md"):
                continue
            path = current / name
            if is_link_or_reparse(path):
                rejected.append(path)
            elif path.is_file():
                files.append(path)
    return sorted(files), sorted(rejected)


def markdown_files(repository_root: Path) -> list[Path]:
    """Return project-owned Markdown files under the repository root."""
    files, _rejected = markdown_inventory(repository_root)
    return files


def read_markdown(
    path: Path, *, label: str, repository_root: Path | None = None
) -> tuple[str | None, str | None]:
    """Read project Markdown without dereferencing symbolic links."""
    if path.is_symlink():
        return None, f"{label}: symbolic-link Markdown is not dereferenced or validated"
    if (
        path_has_link_or_reparse(path, repository_root)
        if repository_root is not None
        else is_link_or_reparse(path)
    ):
        return (
            None,
            f"{label}: linked or reparse-point Markdown is not dereferenced or validated",
        )
    try:
        return path.read_text(encoding="utf-8"), None
    except (OSError, UnicodeError) as error:
        return None, f"{label}: unreadable UTF-8 Markdown: {error}"


OPAQUE_HTML_BLOCK = re.compile(
    r"(?is)^\s*(?:<!--|<\?|<![A-Z]|<!\[CDATA\[|"
    r"<(?:pre|script|style|textarea)(?:[ \t>]|$))"
)


def _source_line_offsets(text: str) -> list[int]:
    """Return source offsets for CommonMark's zero-based line maps."""
    return [
        0,
        *(match.end() for match in re.finditer(r"\r\n|\r|\n", text)),
        len(text),
    ]


def _blank_commonmark_blocks(text: str, token_types: frozenset[str]) -> str:
    """Blank selected CommonMark block tokens while preserving source layout."""
    output = list(text)
    offsets = _source_line_offsets(text)
    for token in COMMONMARK.parse(text):
        if token.type not in token_types or token.map is None:
            continue
        if token.type == "html_block" and not OPAQUE_HTML_BLOCK.match(token.content):
            continue
        start_line, end_line = token.map
        start = offsets[start_line]
        end = offsets[end_line]
        for position in range(start, end):
            if output[position] not in "\r\n":
                output[position] = " "
    return "".join(output)


def without_fenced_code(text: str) -> str:
    """Blank CommonMark fenced code blocks."""
    return _blank_commonmark_blocks(text, frozenset({"fence"}))


def _without_root_indented_code(text: str) -> str:
    """Blank CommonMark indented code blocks."""
    return _blank_commonmark_blocks(text, frozenset({"code_block"}))


def _without_markdown_block_code(text: str) -> str:
    """Blank CommonMark block constructs whose contents are not Markdown."""
    return _blank_commonmark_blocks(
        text, frozenset({"code_block", "fence", "html_block"})
    )


CODE_SPANS_ENV_KEY = "repo_scaffold_code_spans"


def _record_code_span(state: StateInline, silent: bool) -> bool:
    """Record source offsets whenever markdown-it parses a code span."""
    opening = state.pos
    token_count = len(state.tokens)
    matched = parse_backtick(state, silent)
    if len(state.tokens) > token_count:
        state.env.setdefault(CODE_SPANS_ENV_KEY, []).append((opening, state.pos))
    return matched


CODE_SPAN_COMMONMARK = MarkdownIt("commonmark")
CODE_SPAN_COMMONMARK.inline.ruler.at("backticks", _record_code_span)


def _without_inline_code(text: str) -> str:
    """Blank code spans confirmed by the CommonMark parser."""
    output = list(text)
    offsets = _source_line_offsets(text)
    for token in COMMONMARK.parse(text):
        if token.type != "inline" or token.map is None:
            continue
        start_line, end_line = token.map
        block_start = offsets[start_line]
        block_end = offsets[end_line]
        environment: dict[str, Any] = {}
        CODE_SPAN_COMMONMARK.parseInline(text[block_start:block_end], environment)
        spans: list[tuple[int, int]] = environment.get(CODE_SPANS_ENV_KEY, [])
        for opening, closing in spans:
            for position in range(block_start + opening, block_start + closing):
                if output[position] not in "\r\n":
                    output[position] = " "
    return "".join(output)


def without_markdown_code(text: str) -> str:
    """Blank all CommonMark code and opaque HTML constructs."""
    return _without_inline_code(_without_markdown_block_code(text))


def github_anchor(heading: str) -> str:
    """Return the GitHub-style anchor used by numbered project headings."""
    normalized = heading.strip().lower()
    normalized = re.sub(r"[^\w\s-]", "", normalized, flags=re.UNICODE)
    return re.sub(r"\s+", "-", normalized)


def path_is_below(path: Path, parent: Path) -> bool:
    """Return whether path is located at or below parent."""
    try:
        Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(parent)))
    except ValueError:
        return False
    return True


def _parse_commonmark(text: str) -> tuple[list[Token], dict[str, Any]]:
    """Parse Markdown with the CommonMark reference implementation port."""
    environment: dict[str, Any] = {}
    return COMMONMARK.parse(text, environment), environment


def _walk_markdown_tokens(tokens: Iterable[Token]) -> Iterable[Token]:
    """Yield block and nested inline tokens in source order."""
    for token in tokens:
        yield token
        if token.children:
            yield from _walk_markdown_tokens(token.children)


def _links_from_tokens(tokens: Iterable[Token]) -> list[tuple[bool, str]]:
    """Return normalized non-autolink destinations from parsed tokens."""
    links: list[tuple[bool, str]] = []
    for token in _walk_markdown_tokens(tokens):
        if token.type == "image":
            links.append((True, str(token.attrGet("src") or "")))
        elif token.type == "link_open" and token.markup != "autolink":
            links.append((False, str(token.attrGet("href") or "")))
    return links


def inline_markdown_links(text: str) -> list[tuple[bool, str]]:
    """Return CommonMark inline links and images as normalized destinations."""
    tokens, _environment = _parse_commonmark(text)
    return _links_from_tokens(tokens)


def inline_markdown_link_payloads(text: str) -> list[str]:
    """Return normalized destinations for CommonMark inline links and images."""
    return [destination for _is_image, destination in inline_markdown_links(text)]


def markdown_link_destinations(text: str) -> list[str]:
    """Return unique inline and reference-definition CommonMark destinations."""
    tokens, environment = _parse_commonmark(text)
    destinations = [
        destination for _is_image, destination in _links_from_tokens(tokens)
    ]
    references: dict[str, dict[str, str]] = environment.get("references", {})
    destinations.extend(reference["href"] for reference in references.values())
    return list(dict.fromkeys(destinations))


def validate_markdown_sources(
    repository_root: Path, *, marker_exclusions: Iterable[Path] = ()
) -> list[str]:
    """Validate encoding, final newlines, markers, and relative links."""
    exclusions = tuple(Path(os.path.abspath(path)) for path in marker_exclusions)
    problems: list[str] = []
    repository_root = Path(os.path.abspath(repository_root))
    files, rejected = markdown_inventory(repository_root)
    for path in rejected:
        relative = path.relative_to(repository_root).as_posix() or "."
        if path.is_symlink() and path.suffix.lower() == ".md":
            problems.append(
                f"{relative}: symbolic-link Markdown is not dereferenced or validated"
            )
        else:
            problems.append(
                f"{relative}: linked or reparse-point path is not dereferenced or validated"
            )
    if repository_root in rejected:
        return problems
    resolved_root = repository_root.resolve()
    for path in files:
        relative = path.relative_to(repository_root).as_posix()
        text, problem = read_markdown(
            path, label=relative, repository_root=repository_root
        )
        if problem is not None:
            problems.append(problem)
            continue
        assert text is not None
        if not text.endswith("\n"):
            problems.append(f"{relative}: must end with a newline")
        excluded = any(path_is_below(path, prefix) for prefix in exclusions)
        if not excluded and SCAFFOLD_MARKER.search(text):
            problems.append(f"{relative}: contains an unresolved scaffold marker")

        for destination in markdown_link_destinations(text):
            decoded_destination = unquote(destination)
            if (
                not destination
                or destination.startswith("#")
                or SCAFFOLD_MARKER.search(decoded_destination)
                or urlsplit(destination).scheme
                or destination.startswith("//")
            ):
                continue
            decoded_path = unquote(urlsplit(destination).path)
            if "\x00" in decoded_path:
                problems.append(
                    f"{relative}: relative link has an invalid path: {destination}"
                )
                continue
            try:
                target = (path.parent / decoded_path).resolve()
            except (OSError, RuntimeError, ValueError):
                problems.append(
                    f"{relative}: relative link has an invalid path: {destination}"
                )
                continue
            try:
                target.relative_to(resolved_root)
            except ValueError:
                problems.append(f"{relative}: relative link escapes repository")
                continue
            try:
                target_exists = target.exists()
            except (OSError, ValueError):
                problems.append(
                    f"{relative}: relative link has an invalid path: {destination}"
                )
                continue
            if not target_exists:
                problems.append(f"{relative}: relative link is missing: {destination}")
    return problems


def validate_code_of_conduct(repository_root: Path) -> list[str]:
    """Reject obsolete or unfinished Contributor Covenant policies."""
    candidates = (
        repository_root / ".github" / "CODE_OF_CONDUCT.md",
        repository_root / "CODE_OF_CONDUCT.md",
        repository_root / "docs" / "CODE_OF_CONDUCT.md",
    )
    path = next(
        (candidate for candidate in candidates if os.path.lexists(candidate)), None
    )
    if path is None:
        return []

    relative = path.relative_to(repository_root).as_posix()
    text, problem = read_markdown(path, label=relative, repository_root=repository_root)
    if problem is not None:
        return [problem]
    assert text is not None
    if "contributor covenant" not in text.casefold():
        return []

    problems: list[str] = []
    if "[INSERT CONTACT METHOD]" in text:
        problems.append(f"{relative}: contains an unresolved reporting placeholder")
    if "[NOTE:" in text:
        problems.append(f"{relative}: contains an unresolved Contributor Covenant note")

    matches = list(CONTRIBUTOR_COVENANT_ATTRIBUTION.finditer(text))
    if len(matches) != 1:
        problems.append(
            f"{relative}: Contributor Covenant attribution must identify one version"
        )
        return problems

    match = matches[0]
    components = tuple(
        int(component) if component is not None else 0 for component in match.groups()
    )
    if components < MINIMUM_CONTRIBUTOR_COVENANT_VERSION:
        problems.append(
            f"{relative}: Contributor Covenant must be version 3.0 or newer"
        )
    url_components = [match.group(1), match.group(2)]
    if match.group(3) is not None:
        url_components.append(match.group(3))
    permanent_url = (
        "https://www.contributor-covenant.org/version/" + "/".join(url_components) + "/"
    )
    if permanent_url not in text:
        problems.append(
            f"{relative}: attribution URL must match Contributor Covenant "
            f"version {'.'.join(url_components)}"
        )
    return problems


def validate_readme_text(text: str, *, label: str = "README.md") -> list[str]:
    """Validate the centered header and numbered README outline contract."""
    visible = without_markdown_code(text)
    problems: list[str] = []

    openings = list(CENTERED_DIV.finditer(visible))
    opening = openings[0] if len(openings) == 1 else None
    closing_position = visible.lower().find("</div>", opening.end() if opening else 0)
    first_h2 = re.search(r"(?m)^##[ \t]+", visible)
    if opening is None or closing_position < 0:
        problems.append(f'{label}: header must use one <div align="center"> block')
        return problems
    if first_h2 and closing_position > first_h2.start():
        problems.append(f"{label}: centered header must close before the first H2")

    header = visible[opening.end() : closing_position]
    header_h1 = re.findall(r"(?m)^#[ \t]+\S.*$", header)
    if len(header_h1) != 1:
        problems.append(f"{label}: centered header must contain exactly one H1")
    if re.search(
        r"(?m)^#[ \t]+", visible[: opening.start()] + visible[closing_position:]
    ):
        problems.append(f"{label}: H1 must be inside the centered header")
    tagline_lines = [
        line.strip()
        for line in header.splitlines()
        if line.strip()
        and not line.lstrip().startswith(("#", "![", "[![", "<!--", "-->", "<"))
    ]
    if not tagline_lines:
        problems.append(f"{label}: centered header must contain a nonempty tagline")

    header_end = closing_position + len("</div>")
    pre_sections = visible[: first_h2.start()] if first_h2 else visible
    outside_header = pre_sections[: opening.start()] + pre_sections[header_end:]
    if any(
        is_image for is_image, _payload in inline_markdown_links(outside_header)
    ) or HTML_IMAGE.search(outside_header):
        problems.append(
            f"{label}: header badges/images must be inside the centered div"
        )

    headings = [
        (match.group(1), match.group(2).strip(), match.start())
        for match in HEADING.finditer(visible)
    ]
    h2s = [(title, position) for marks, title, position in headings if marks == "##"]
    numbered_h2s: list[tuple[int, str, int]] = []
    unnumbered_h2s: list[tuple[str, int]] = []
    for title, position in h2s:
        match = NUMBERED_SECTION.match(title)
        if match:
            numbered_h2s.append((int(match.group(1)), title, position))
        else:
            unnumbered_h2s.append((title, position))
    expected_sections = list(range(1, len(numbered_h2s) + 1))
    actual_sections = [number for number, _title, _position in numbered_h2s]
    if actual_sections != expected_sections:
        problems.append(f"{label}: H2 sections must be numbered sequentially from 1")
    if not numbered_h2s:
        problems.append(f"{label}: must contain numbered H2 sections")

    toc: tuple[str, int] | None = None
    if unnumbered_h2s:
        first_numbered_position = numbered_h2s[0][2] if numbered_h2s else len(visible)
        candidates = [
            item for item in unnumbered_h2s if item[1] < first_numbered_position
        ]
        if len(unnumbered_h2s) != 1 or len(candidates) != 1:
            problems.append(
                f"{label}: only one unnumbered H2 table of contents is allowed"
            )
        else:
            toc = candidates[0]
    if len(numbered_h2s) >= LONG_README_SECTION_COUNT and toc is None:
        problems.append(f"{label}: long README must include a manual table of contents")

    current_section: int | None = None
    child_counts: dict[int, int] = {}
    numbered_headings: list[tuple[int, str]] = []
    for marks, title, _position in headings:
        if marks == "##":
            section_match = NUMBERED_SECTION.match(title)
            current_section = int(section_match.group(1)) if section_match else None
            if current_section is not None:
                numbered_headings.append((2, title))
        elif marks == "###" and current_section is not None:
            subsection_match = NUMBERED_SUBSECTION.match(title)
            expected_child = child_counts.get(current_section, 0) + 1
            if (
                subsection_match is None
                or int(subsection_match.group(1)) != current_section
                or int(subsection_match.group(2)) != expected_child
            ):
                problems.append(
                    f"{label}: H3 subsections must match their parent and be "
                    "numbered sequentially"
                )
            else:
                child_counts[current_section] = expected_child
                numbered_headings.append((3, title))

    if toc is not None:
        toc_start = toc[1]
        toc_end = numbered_h2s[0][2] if numbered_h2s else len(visible)
        toc_body = visible[toc_start:toc_end]
        for level, title in numbered_headings:
            anchor = github_anchor(title)
            indentation = r"[ \t]{2,}" if level == 3 else r""
            entry = re.compile(
                rf"(?m)^{indentation}[-*+]\s+\[[^\]]+\]\(#{re.escape(anchor)}\)\s*$"
            )
            if not entry.search(toc_body):
                problems.append(f"{label}: table of contents is missing #{anchor}")
    return problems


def validate_readme(repository_root: Path) -> list[str]:
    """Validate the exact root README path."""
    path = repository_root / "README.md"
    if path.is_symlink():
        return ["README.md: symbolic-link Markdown is not dereferenced or validated"]
    if path_has_link_or_reparse(path, repository_root):
        return [
            "README.md: linked or reparse-point Markdown is not dereferenced or validated"
        ]
    if not path.is_file():
        return ["README.md: missing exact root README path"]
    text, problem = read_markdown(
        path, label="README.md", repository_root=repository_root
    )
    if problem is not None:
        return [problem]
    assert text is not None
    return validate_readme_text(text)


def validate_markdown_issue_templates(
    repository_root: Path, *, template_directory: Path | None = None
) -> list[str]:
    """Validate legacy Markdown issue-template front matter and body."""
    template_root = template_directory or (
        repository_root / ".github" / "ISSUE_TEMPLATE"
    )
    problems: list[str] = []
    if path_has_link_or_reparse(template_root, repository_root):
        relative = template_root.relative_to(repository_root).as_posix()
        return [
            f"{relative}: linked or reparse-point path is not dereferenced or validated"
        ]
    for path in sorted(template_root.glob("*.md")):
        relative = path.relative_to(repository_root).as_posix()
        text, problem = read_markdown(
            path, label=relative, repository_root=repository_root
        )
        if problem is not None:
            problems.append(problem)
            continue
        assert text is not None
        match = re.match(r"\A---\r?\n(.*?)\r?\n---\r?\n(.*)\Z", text, re.DOTALL)
        if match is None:
            problems.append(f"{relative}: missing complete YAML front matter")
            continue
        try:
            metadata = load_yaml_text(match.group(1))
        except yaml.YAMLError as error:
            problems.append(f"{relative}: invalid YAML front matter: {error}")
            continue
        required = {"name", "about"}
        supported = required | {"title", "labels", "assignees"}
        if (
            not isinstance(metadata, dict)
            or not required.issubset(metadata)
            or not set(metadata).issubset(supported)
        ):
            problems.append(
                f"{relative}: front matter must contain {sorted(required)} and only "
                f"supported keys {sorted(supported)}"
            )
        elif not all(isinstance(value, str) for value in metadata.values()):
            problems.append(f"{relative}: front matter values must be strings")
        elif not metadata["name"].strip() or not metadata["about"].strip():
            problems.append(f"{relative}: name and about must be nonempty")
        if not match.group(2).strip():
            problems.append(f"{relative}: template body must be nonempty")
    return problems


def validate_issue_forms(
    repository_root: Path, *, template_directory: Path | None = None
) -> list[str]:
    """Validate the core GitHub Issue Form schema for every YAML template."""
    template_root = template_directory or (
        repository_root / ".github" / "ISSUE_TEMPLATE"
    )
    if path_has_link_or_reparse(template_root, repository_root):
        relative = template_root.relative_to(repository_root).as_posix()
        return [
            f"{relative}: linked or reparse-point path is not dereferenced or validated"
        ]

    problems: list[str] = []
    for path in sorted(template_root.glob("*.yaml")):
        relative = path.relative_to(repository_root).as_posix()
        problems.append(f"{relative}: issue forms must use the .yml extension")
    for path in sorted(template_root.glob("*.yml")):
        if path.name in {"config.yml", "config.vi.yml"}:
            continue
        relative = path.relative_to(repository_root).as_posix()
        if path_has_link_or_reparse(path, repository_root):
            problems.append(
                f"{relative}: linked or reparse-point YAML is not dereferenced or validated"
            )
            continue
        try:
            document = load_yaml_text(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            problems.append(f"{relative}: invalid issue form YAML: {error}")
            continue
        if not isinstance(document, dict):
            problems.append(f"{relative}: issue form root must be a mapping")
            continue

        required = {"name", "description", "body"}
        supported = required | {"title", "labels", "assignees", "projects", "type"}
        if not required.issubset(document) or not set(document).issubset(supported):
            problems.append(
                f"{relative}: form must contain {sorted(required)} and only "
                f"supported keys {sorted(supported)}"
            )
        if not all(
            isinstance(document[field], str) and document[field].strip()
            for field in ("name", "description")
        ):
            problems.append(f"{relative}: name and description must be nonempty")
        if "type" in document and (
            not isinstance(document["type"], str) or not document["type"].strip()
        ):
            problems.append(f"{relative}: type must be a nonempty string")

        body = document.get("body")
        if not isinstance(body, list) or not body:
            problems.append(f"{relative}: body must be a nonempty list")
            continue
        seen_ids: set[str] = set()
        seen_labels: set[str] = set()
        has_input = False
        for index, item in enumerate(body):
            prefix = f"{relative}: body[{index}]"
            if not isinstance(item, dict):
                problems.append(f"{prefix} must be a mapping")
                continue
            if set(item) - ISSUE_FORM_BODY_KEYS:
                problems.append(f"{prefix} contains unsupported keys")
            item_type = item.get("type")
            if item_type not in ISSUE_FORM_INPUT_TYPES:
                problems.append(f"{prefix}.type must be a supported input type")
                continue
            if item_type == "markdown":
                required_attribute = "value"
            else:
                has_input = True
                required_attribute = "label"
                item_id = item.get("id")
                if not isinstance(item_id, str) or not ISSUE_FORM_ID.fullmatch(item_id):
                    problems.append(
                        f"{prefix}.id may contain only letters, numbers, -, and _"
                    )
                elif item_id in seen_ids:
                    problems.append(f"{prefix}.id must be unique")
                else:
                    seen_ids.add(item_id)
            attributes = item.get("attributes")
            if not isinstance(attributes, dict):
                problems.append(f"{prefix}.attributes must be a mapping")
                continue
            if (
                not isinstance(attributes.get(required_attribute), str)
                or not attributes[required_attribute].strip()
            ):
                problems.append(
                    f"{prefix}.attributes.{required_attribute} must be nonempty"
                )
            elif item_type != "markdown":
                label = attributes["label"]
                if label in seen_labels:
                    problems.append(f"{prefix}.attributes.label must be unique")
                else:
                    seen_labels.add(label)
            options = attributes.get("options")
            if item_type == "dropdown" and (
                not isinstance(options, list)
                or not options
                or not all(
                    isinstance(option, str) and option.strip() for option in options
                )
            ):
                problems.append(
                    f"{prefix}.attributes.options must be a nonempty string list"
                )
            if item_type == "checkboxes" and (
                not isinstance(options, list)
                or not options
                or not all(
                    isinstance(option, dict)
                    and isinstance(option.get("label"), str)
                    and option["label"].strip()
                    and option.get("required", "false") in {"true", "false"}
                    for option in options
                )
            ):
                problems.append(
                    f"{prefix}.attributes.options must be a nonempty checkbox list"
                )
            elif item_type == "checkboxes":
                assert isinstance(options, list)
                for option in options:
                    assert isinstance(option, dict)
                    label = option["label"]
                    assert isinstance(label, str)
                    if label in seen_labels:
                        problems.append(
                            f"{prefix}.attributes.options labels must be unique "
                            "among form inputs"
                        )
                    else:
                        seen_labels.add(label)
            validations = item.get("validations")
            if validations is not None and (
                not isinstance(validations, dict)
                or validations.get("required", "false") not in {"true", "false"}
            ):
                problems.append(f"{prefix}.validations.required must be a boolean")
        if not has_input:
            problems.append(f"{relative}: body must contain a non-markdown input")
    return problems


def pull_request_templates(repository_root: Path) -> list[Path]:
    """Return supported single and multi-template Markdown paths."""
    candidates = {
        repository_root / "PULL_REQUEST_TEMPLATE.md",
        repository_root / "docs" / "PULL_REQUEST_TEMPLATE.md",
        repository_root / ".github" / "PULL_REQUEST_TEMPLATE.md",
    }
    template_directory = repository_root / ".github" / "PULL_REQUEST_TEMPLATE"
    if not path_has_link_or_reparse(template_directory, repository_root):
        candidates.update(template_directory.glob("*.md"))
    return sorted(
        path
        for path in candidates
        if path_has_link_or_reparse(path, repository_root) or path.is_file()
    )


def validate_pull_request_templates(repository_root: Path) -> list[str]:
    """Require actionable content in every pull-request template."""
    problems: list[str] = []
    for path in pull_request_templates(repository_root):
        relative = path.relative_to(repository_root).as_posix()
        text, problem = read_markdown(
            path, label=relative, repository_root=repository_root
        )
        if problem is not None:
            problems.append(problem)
            continue
        assert text is not None
        if not text.strip():
            problems.append(f"{relative}: template must be nonempty")
        if not re.search(r"(?m)^\s*[-*+]\s+\[ \]\s+\S", text):
            problems.append(f"{relative}: template must contain a checklist item")
    return problems


def validate_template_assets(template_root: Path) -> list[str]:
    """Validate Markdown-specific contracts in the plugin's source assets."""
    problems: list[str] = []
    header_path = template_root / "README-header.md"
    if path_has_link_or_reparse(header_path, template_root):
        problems.append(
            "README-header.md asset: linked or reparse-point Markdown is not "
            "dereferenced or validated"
        )
    elif not header_path.is_file():
        problems.append(f"{header_path}: missing README header asset")
    else:
        header, problem = read_markdown(
            header_path,
            label="README-header.md asset",
            repository_root=template_root,
        )
        if problem is not None:
            problems.append(problem)
        else:
            assert header is not None
            synthetic = header + "\n## 1. Overview\n"
            problems.extend(
                validate_readme_text(synthetic, label="README-header.md asset")
            )
    problems.extend(
        validate_markdown_issue_templates(
            template_root, template_directory=template_root / "ISSUE_TEMPLATE"
        )
    )
    problems.extend(
        validate_issue_forms(
            template_root, template_directory=template_root / "ISSUE_TEMPLATE"
        )
    )
    pull_templates = [("default", template_root / "PULL_REQUEST_TEMPLATE.md")]
    for directory_name in ("PULL_REQUEST_TEMPLATE", "PULL_REQUEST_TEMPLATE.vi"):
        template_directory = template_root / directory_name
        if path_has_link_or_reparse(template_directory, template_root):
            problems.append(
                f"{directory_name} asset directory: linked or reparse-point Markdown "
                "is not dereferenced or validated"
            )
            continue
        if template_directory.is_dir():
            pull_templates.extend(
                (path.stem, path) for path in sorted(template_directory.glob("*.md"))
            )

    marker_pattern = re.compile(
        r"^<!-- repo-scaffold:pr-template=([a-z][a-z0-9-]*) -->[ \t]*$",
        re.MULTILINE,
    )
    required_section_marker = "repo-scaffold:required-checklist"
    optional_section_marker = "repo-scaffold:optional-checklist"
    checklist_pattern = re.compile(r"(?m)^\s*[-*+]\s+\[ \]\s+\S")
    optional_section_pattern = re.compile(
        r"^##[ \t]+(?:If applicable|Khi phù hợp|Danh sách tùy chọn)[ \t]*$\s*"
        r"<!-- repo-scaffold:optional-checklist:start -->",
        re.MULTILINE,
    )
    for template_id, pull_template in pull_templates:
        relative = pull_template.relative_to(template_root).as_posix()
        label = f"{relative} asset"
        if path_has_link_or_reparse(pull_template, template_root):
            problems.append(
                f"{label}: linked or reparse-point Markdown is not dereferenced or "
                "validated"
            )
            continue
        if not pull_template.is_file():
            continue
        text, problem = read_markdown(
            pull_template,
            label=label,
            repository_root=template_root,
        )
        if problem is not None:
            problems.append(problem)
            continue
        assert text is not None
        if marker_pattern.findall(text) != [template_id]:
            problems.append(
                f"{label} must contain exactly one matching repo-scaffold template marker"
            )
        if (
            text.count(f"{required_section_marker}:start") != 1
            or text.count(f"{required_section_marker}:end") != 1
        ):
            problems.append(
                f"{label} must contain exactly one required checklist section"
            )
        if (
            text.count(f"{optional_section_marker}:start") != 1
            or text.count(f"{optional_section_marker}:end") != 1
        ):
            problems.append(
                f"{label} must contain exactly one optional checklist section"
            )
        elif optional_section_pattern.search(text) is None:
            problems.append(
                f"{label} must label the optional checklist `If applicable`, `Khi phù hợp`, "
                "or `Danh sách tùy chọn`"
            )
        required_start = f"<!-- {required_section_marker}:start -->"
        required_end = f"<!-- {required_section_marker}:end -->"
        required_checklist = text
        if required_start in text and required_end in text:
            required_checklist = text.split(required_start, maxsplit=1)[1].split(
                required_end, maxsplit=1
            )[0]
        if checklist_pattern.search(required_checklist) is None:
            if relative == "PULL_REQUEST_TEMPLATE.md":
                problems.append(f"{label} must contain a checklist item")
            else:
                problems.append(f"{label} must contain a required checklist item")
    return list(dict.fromkeys(problems))


def validate_scaffold(
    repository_root: Path, *, template_root: Path | None = None
) -> list[str]:
    """Run every deterministic rendered-document validation."""
    exclusions = (template_root.parent,) if template_root else ()
    problems = validate_markdown_sources(repository_root, marker_exclusions=exclusions)
    problems.extend(validate_code_of_conduct(repository_root))
    problems.extend(validate_readme(repository_root))
    problems.extend(validate_markdown_issue_templates(repository_root))
    problems.extend(validate_issue_forms(repository_root))
    problems.extend(validate_pull_request_templates(repository_root))
    if template_root is not None:
        problems.extend(validate_template_assets(template_root))
    return list(dict.fromkeys(problems))


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path.cwd(),
        help="Rendered repository root (default: current directory)",
    )
    parser.add_argument(
        "--template-root",
        type=Path,
        help="Optional internal repo-scaffold asset root allowed to contain markers",
    )
    return parser.parse_args()


def main() -> int:
    """Validate the selected repository and report every problem."""
    args = parse_args()
    root = Path(os.path.abspath(args.repository_root))
    if not root.exists():
        raise FileNotFoundError(root)
    if not root.is_dir():
        raise ValueError(f"repository root is not a directory: {root}")
    template_root = (
        Path(os.path.abspath(args.template_root)) if args.template_root else None
    )
    if template_root is not None:
        if not template_root.exists():
            raise FileNotFoundError(template_root)
        if not template_root.is_dir():
            raise ValueError(f"template root is not a directory: {template_root}")
    problems = validate_scaffold(root, template_root=template_root)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    print("Rendered Markdown and GitHub templates satisfy the scaffold contract.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
