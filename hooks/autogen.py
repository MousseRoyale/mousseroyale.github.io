"""
Build-time content generators for mousseroyale.github.io.

Registered in mkdocs.yml under `hooks:`. MkDocs calls the on_* functions
below at the appropriate build phase — no extra plugins needed.

HOW IT WORKS
------------
Pages that want generated content include HTML comment markers:

    <!-- autogen:TAG -->
    <!-- /autogen:TAG -->

on_page_markdown fires for every page.  If a page's source path matches a
known generator, that generator scans the filesystem and replaces the tagged
block in-memory.  Source files on disk are never rewritten; the substitution
only exists in the rendered output.

on_pre_build runs once before the build and handles filesystem mutations —
currently only auto-creating category .nav.yml files that awesome-nav needs.

EXTENDING
---------
To add a new generator:
  1. Write a function  _gen_<name>(markdown, ...) -> str
     that calls _inject(markdown, "your-tag", content) and returns markdown.
  2. Add a routing clause in on_page_markdown keyed on the page's src_path.

Nothing else needs to change.  The hook file itself is build tooling; it lives
in the repo root and is never deployed to the site.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Category metadata
# ---------------------------------------------------------------------------

# Maps folder name → label used in data-category (drives the JS filter chips)
CATEGORY_DISPLAY: dict[str, str] = {
    "misc":       "Misc",
    "web":        "Web",
    "rev":        "Rev",
    "pwn":        "Pwn",
    "crypto":     "Crypto",
    "forensics":  "Forensics",
    "osint":      "OSINT",
    "blockchain": "Blockchain",
    "hardware":   "Hardware",
    "mobile":     "Mobile",
    "stego":      "Stego",
    "ppc":        "PPC",
    "network":    "Network",
    "jail":       "Jail",
}

# Maps folder name → human title written into auto-created .nav.yml files
CATEGORY_NAV_TITLE: dict[str, str] = {
    "misc":       "Miscellaneous",
    "web":        "Web",
    "rev":        "Reverse Engineering",
    "pwn":        "Pwn / Binary Exploitation",
    "crypto":     "Cryptography",
    "forensics":  "Forensics",
    "osint":      "OSINT",
    "blockchain": "Blockchain",
    "hardware":   "Hardware",
    "mobile":     "Mobile",
    "stego":      "Steganography",
    "ppc":        "PPC / Programming",
    "network":    "Network",
    "jail":       "Jail / Sandbox",
}


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------

def _read_frontmatter(path: Path) -> dict:
    """Return the parsed YAML frontmatter dict from a markdown file, or {}."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    try:
        return yaml.safe_load(text[3:end]) or {}
    except yaml.YAMLError:
        return {}


def _read_first_h1(path: Path) -> str:
    """Return the text of the first # heading in a file, or a title-cased stem."""
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("# "):
                return line[2:].strip()
    except OSError:
        pass
    return path.stem.replace("-", " ").title()


def _inject(markdown: str, tag: str, content: str) -> str:
    """
    Replace the content of an <!-- autogen:TAG --> ... <!-- /autogen:TAG --> block.
    Preserves any leading indentation on the opening marker (so markers inside
    tabbed content or admonitions keep the block correctly indented).
    Returns the original string unchanged if no matching block is found.
    """
    pattern = rf"([ \t]*)<!-- autogen:{re.escape(tag)} -->.*?<!-- /autogen:{re.escape(tag)} -->"

    found = [False]

    def _replace(m: re.Match) -> str:
        found[0] = True
        indent = m.group(1)
        if indent:
            indented = "\n".join(
                indent + line if line.strip() else line
                for line in content.splitlines()
            )
        else:
            indented = content
        return f"{indent}<!-- autogen:{tag} -->\n\n{indented}\n\n{indent}<!-- /autogen:{tag} -->"

    result = re.sub(pattern, _replace, markdown, flags=re.DOTALL)
    return result if found[0] else markdown


# ---------------------------------------------------------------------------
# MkDocs hook entry points
# ---------------------------------------------------------------------------

def on_pre_build(config) -> None:
    """Filesystem mutations — runs once before MkDocs processes any files."""
    docs_dir = Path(config["docs_dir"])
    _ensure_category_navs(docs_dir)


def on_page_markdown(markdown: str, page, config, files) -> str:
    """
    In-memory content injection — runs per-page, before markdown → HTML.
    Only pages that contain at least one autogen marker are touched.
    """
    if "<!-- autogen:" not in markdown:
        return markdown

    src = page.file.src_path.replace("\\", "/")
    docs_dir = Path(config["docs_dir"])
    parts = src.split("/")

    # ctfs/index.md — master event grid + global explorer
    if src == "ctfs/index.md":
        markdown = _gen_ctf_grid(markdown, docs_dir)
        markdown = _gen_ctf_explorer(markdown, docs_dir)

    # ctfs/<event>/index.md — per-event writeup list
    elif len(parts) == 3 and parts[0] == "ctfs" and parts[2] == "index.md":
        event_dir = docs_dir / parts[1]  # docs_dir already ends in 'ctfs'... wait
        # src_path is relative to docs_dir, so parts[0]='ctfs', parts[1]=event slug
        event_dir = docs_dir / parts[0] / parts[1]
        markdown = _gen_event_writeup_list(markdown, event_dir)

    return markdown


# ---------------------------------------------------------------------------
# CTF generators
# ---------------------------------------------------------------------------

def _ensure_category_navs(docs_dir: Path) -> None:
    """
    Create a .nav.yml for every CTF category folder that doesn't have one.
    awesome-nav uses these to set the sidebar section title.
    """
    ctfs_dir = docs_dir / "ctfs"
    if not ctfs_dir.is_dir():
        return
    for event_dir in ctfs_dir.iterdir():
        if not event_dir.is_dir():
            continue
        for cat_dir in event_dir.iterdir():
            if not cat_dir.is_dir():
                continue
            nav_path = cat_dir / ".nav.yml"
            if not nav_path.exists():
                title = CATEGORY_NAV_TITLE.get(cat_dir.name, cat_dir.name.title())
                nav_path.write_text(f"title: {title}\n", encoding="utf-8")


def _gen_ctf_grid(markdown: str, docs_dir: Path) -> str:
    """
    Build the Material grid-cards block for ctfs/index.md.

    Each event directory's index.md must have a `ctf_meta:` frontmatter block:

        ctf_meta:
          title:    GPN CTF 2026
          date:     "2026-06-06"      # ISO end-date, used for sort order
          icon:     material-flag-checkered
          subtitle: "Jeopardy · June 2026 · Solo"
    """
    ctfs_dir = docs_dir / "ctfs"

    # Collect events that have ctf_meta, sorted newest-first by date
    events: list[tuple[Path, dict]] = []
    for event_dir in ctfs_dir.iterdir():
        if not event_dir.is_dir():
            continue
        idx = event_dir / "index.md"
        if not idx.exists():
            continue
        meta = _read_frontmatter(idx).get("ctf_meta")
        if meta:
            events.append((event_dir, meta))

    events.sort(key=lambda x: x[1].get("date", ""), reverse=True)

    cards: list[str] = []
    for event_dir, meta in events:
        icon     = meta.get("icon",     "material-flag-checkered")
        title    = meta.get("title",    event_dir.name)
        subtitle = meta.get("subtitle", "")
        slug     = event_dir.name

        cards.append(
            f"-   :{icon}: __{title}__\n\n"
            f"    ---\n\n"
            f"    {subtitle}\n\n"
            f"    [:octicons-arrow-right-24: View]({slug}/index.md)"
        )

    if not cards:
        return markdown

    grid = '<div class="grid cards" markdown>\n\n' + "\n\n".join(cards) + "\n\n</div>"
    return _inject(markdown, "ctf-grid", grid)


def _gen_ctf_explorer(markdown: str, docs_dir: Path) -> str:
    """
    Build the global challenge explorer for ctfs/index.md.

    Produces a flat .ctf-explorer list of every challenge across all events,
    with data-event / data-event-title / data-category attributes so the
    ctf-explorer.js can build search + event chips + category chips in-browser.
    """
    ctfs_dir = docs_dir / "ctfs"

    # Collect events newest-first (same ordering as ctf-grid)
    events: list[tuple[Path, dict]] = []
    for event_dir in ctfs_dir.iterdir():
        if not event_dir.is_dir():
            continue
        idx = event_dir / "index.md"
        if not idx.exists():
            continue
        meta = _read_frontmatter(idx).get("ctf_meta")
        if meta:
            events.append((event_dir, meta))
    events.sort(key=lambda x: x[1].get("date", ""), reverse=True)

    items: list[str] = []

    for event_dir, meta in events:
        slug        = event_dir.name
        event_title = meta.get("title", slug)

        for cat_dir in sorted(event_dir.iterdir()):
            if not cat_dir.is_dir():
                continue
            display = CATEGORY_DISPLAY.get(cat_dir.name, cat_dir.name.title())

            for wf in sorted(cat_dir.glob("*.md")):
                fm    = _read_frontmatter(wf)
                title = fm.get("title") or _read_first_h1(wf)
                desc  = fm.get("description", "")
                rel   = f"{slug}/{cat_dir.name}/{wf.name}"

                line = (
                    f'- [{title}]({rel})'
                    f'{{ data-event="{slug}" data-event-title="{event_title}"'
                    f' data-category="{display}" }}'
                )
                items.append(line)

    if not items:
        return markdown

    body = (
        '<div class="ctf-explorer" markdown>\n\n'
        + "\n\n".join(items)
        + "\n\n</div>"
    )
    return _inject(markdown, "ctf-explorer", body)


def _gen_event_writeup_list(markdown: str, event_dir: Path) -> str:
    """
    Build the ctf-index writeup list for a single event page.

    Each writeup .md file should have frontmatter:

        description: one-line summary of the solve approach

    The challenge title is taken from a `title:` frontmatter field if present,
    otherwise extracted from the first # heading in the file.
    The category label is derived from the parent folder name via CATEGORY_DISPLAY.
    """
    items: list[str] = []

    for cat_dir in sorted(event_dir.iterdir()):
        if not cat_dir.is_dir():
            continue
        display = CATEGORY_DISPLAY.get(cat_dir.name, cat_dir.name.title())

        for wf in sorted(cat_dir.glob("*.md")):
            meta  = _read_frontmatter(wf)
            title = meta.get("title") or _read_first_h1(wf)
            rel   = f"{cat_dir.name}/{wf.name}"

            line = f'- [{title}]({rel}){{ data-category="{display}" }}'
            items.append(line)

    if not items:
        return markdown

    body = '<div class="ctf-index" markdown>\n\n' + "\n\n".join(items) + "\n\n</div>"
    return _inject(markdown, "writeup-list", body)
