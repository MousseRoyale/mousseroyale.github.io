# mousseroyale-site — Architecture & Contributor Guide

MkDocs Material site deployed to GitHub Pages at https://mousseroyale.github.io/.
Source lives in `docs/`; the built output in `site/` is never committed (it's deployed via `mkdocs gh-deploy`).

---

## Site sections

| URL path       | Source dir            | Purpose                                 |
|----------------|-----------------------|-----------------------------------------|
| `/`            | `docs/index.md`       | Terminal-animation landing page         |
| `/ctfs/`       | `docs/ctfs/`          | CTF event writeups                      |
| `/writeups/`   | `docs/writeups/`      | HTB/THM machine writeups                |
| `/cheatsheets/`| `docs/cheatsheets/`   | Quick-reference tool sheets             |
| `/labs/`       | `docs/labs/`          | Structured lab exercises                |
| `/explanations/`| `docs/explanations/` | Concept deep-dives                      |
| `/tags/`       | `docs/tags.md`        | Auto-generated tag index (MkDocs plugin)|

Navigation order is set by `docs/.nav.yml` (awesome-nav plugin).

---

## Key technology

- **MkDocs Material** — theme, grid cards, admonitions, tabbed content
- **mkdocs-awesome-nav** — sidebar nav driven by `.nav.yml` files in each directory
- **MkDocs `tags` plugin** — `tags:` frontmatter on any page auto-populates `/tags/`
- **`hooks/autogen.py`** — build-time Python hook for autogenerating index content (see below)

---

## Autogen system

### Why it exists

Index pages (CTF event grids, per-event writeup lists) were previously maintained by hand. The autogen hook eliminates that: drop a new file in the right directory and rebuild — it appears automatically.

### How it works

The hook (`hooks/autogen.py`) is registered in `mkdocs.yml` under `hooks:`. MkDocs calls it at two build phases:

**`on_pre_build`** — filesystem mutations (runs once before any pages are processed)
- Creates missing category `.nav.yml` files so awesome-nav gets the right sidebar title

**`on_page_markdown`** — in-memory injection (runs per page, before markdown → HTML)
- Finds `<!-- autogen:TAG -->` / `<!-- /autogen:TAG -->` block pairs in the source
- Scans the filesystem and regenerates the block content
- Returns the modified markdown; source files on disk are **never rewritten**

### Autogen markers

Place a pair of HTML comments anywhere in a markdown file:

```html
<!-- autogen:ctf-grid -->
<!-- /autogen:ctf-grid -->
```

On build the hook replaces everything between the markers. The static content above and below the block is untouched.

### Available tags

| Tag              | Page               | Generates                                    |
|------------------|--------------------|----------------------------------------------|
| `ctf-grid`       | `ctfs/index.md`    | Material grid cards, one per CTF event       |
| `writeup-list`   | `ctfs/*/index.md`  | Filtered challenge list with category chips  |

### Public repo note

`hooks/` is build tooling — the Python scripts run during `mkdocs build` and are never deployed to the website. Having them in a public repo is completely standard practice for MkDocs sites. Nothing sensitive lives here.

---

## Adding a new CTF event

1. **Create the directory**: `docs/ctfs/<event-slug>/`

2. **Create `index.md`** with `ctf_meta` frontmatter:
   ```yaml
   ---
   ctf_meta:
     title: Event Name 2026
     date: "2026-MM-DD"      # ISO end-date — controls sort order on /ctfs/
     icon: material-flag-checkered
     subtitle: "Jeopardy · Month Year · Solo"
   ---
   ```
   Add the `## Writeups` section with the autogen marker:
   ```html
   ## Writeups

   <!-- autogen:writeup-list -->
   <!-- /autogen:writeup-list -->
   ```

3. **Create `.nav.yml`** in the event dir:
   ```yaml
   title: Event Name 2026
   ```

4. **Add category directories** (e.g. `web/`, `rev/`, `misc/`). The hook auto-creates their `.nav.yml` files on the next build.

5. **Add writeups** using `templates/ctf-challenge.md`. The hook picks them up automatically.

The event card on `ctfs/index.md` and the writeup list on the event page both update on the next `mkdocs build` — no manual edits to index files needed.

---

## Writeup frontmatter schema

### CTF challenge (`docs/ctfs/<event>/<category>/<slug>.md`)

```yaml
---
description: one-line summary of the solve approach
tags:
  - category-slug   # web | pwn | crypto | rev | forensics | osint | misc | ...
  - technique-tag   # e.g. sqli, bof, xor
  - event-slug      # e.g. gpn-ctf-2026
---
```

- `description` — shown as the summary blurb in the event's writeup list (autogen)
- First tag should be the category slug — it maps to the `data-category` filter chip
- `event-slug` tag links the page into the global `/tags/` index

### Machine writeup (`docs/writeups/<slug>/index.md`)

```yaml
---
tags:
  - linux            # os
  - web              # technique tags
  - privesc
---
```

---

## Category folder name → display mapping

The hook maps folder names to display labels. To add a new category, add it to both
`CATEGORY_DISPLAY` and `CATEGORY_NAV_TITLE` in `hooks/autogen.py`.

| Folder      | Filter chip label | Sidebar title              |
|-------------|-------------------|----------------------------|
| `misc`      | Misc              | Miscellaneous               |
| `web`       | Web               | Web                         |
| `rev`       | Rev               | Reverse Engineering         |
| `pwn`       | Pwn               | Pwn / Binary Exploitation   |
| `crypto`    | Crypto            | Cryptography                |
| `forensics` | Forensics         | Forensics                   |
| `osint`     | OSINT             | OSINT                       |
| `stego`     | Stego             | Steganography               |
| `ppc`       | PPC               | PPC / Programming           |
| `jail`      | Jail              | Jail / Sandbox              |

---

## Extending autogen to other sections

To add a new autogenerated block (e.g. cheatsheet cards, writeup grid):

1. Add the `<!-- autogen:your-tag -->` marker to the target page
2. Write a `_gen_your_tag(markdown, ...)` function in `hooks/autogen.py` that calls `_inject()`
3. Add a routing clause in `on_page_markdown` keyed on the page's `src` path

The shared utilities (`_read_frontmatter`, `_read_first_h1`, `_inject`) are available to all generators.

---

## Templates

`templates/` (project root, not inside `docs/`) contains starter files:

| File                  | Use for                    |
|-----------------------|----------------------------|
| `ctf-challenge.md`    | New CTF writeup            |
| `new-writeup.md`      | New machine writeup (HTB/THM) |

Copy the relevant template into the correct `docs/` subdirectory and fill in the placeholders.
