# notes

Personal security notes built with [MkDocs](https://www.mkdocs.org/) and the Material theme.

## Develop

```bash
pip install -r requirements.txt
mkdocs serve
```

Live at http://127.0.0.1:8000 with hot reload.

## Adding content

Navigation is generated from the folder structure (awesome-nav), so you never edit `mkdocs.yml` to add pages — just drop files in `docs/`.

**A writeup:** copy `_new-writeup-template.md` to `docs/writeups/<name>/index.md`, fill it in, keep images in an `images/` folder beside it.

**A CTF:** create `docs/ctfs/<event>/`, add an `index.md` (the event overview), and add a `.nav.yml` containing one line — `title: <Event Name>` — so the section shows with proper casing. Each challenge is its own folder inside it (`docs/ctfs/<event>/<challenge>/index.md`); use `_ctf-challenge-template.md` as the starting point. New challenge folders appear under the event automatically.

Tag every writeup in its front matter (`tags:`) — by category and, for CTFs, the event slug. Tags collect on the Tags page and feed search.

## Theming

All styling is in `docs/stylesheets/extra.css`. The palette variables at the top control the whole site.

## Code blocks

- Labelled block with copy button: ```` ```bash title="enum.sh" ````
- Terminal session (highlighted prompt, dimmed output): ```` ```console ````

## Build

```bash
mkdocs build
```

Output is written to `site/`.
