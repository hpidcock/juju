---
myst:
  html_meta:
    description: "Reference for charm patches: Starlark scripts that modify charm archives in memory at deploy and upgrade time using the charm-patches model configuration key."
---

(charm-patches)=
# Charm patches

A **charm patch** is a Starlark script that modifies a charm's files in
memory immediately after the charm archive is downloaded and before it is
unpacked to disk. Patch scripts allow operators to customise third-party
charms without forking them.

Patches are configured through the {ref}`model-config-charm-patches` model
configuration key, which points to a zip archive of Starlark scripts.

## Patch zip format

The charm-patches URL must point to a zip file. Every file in the zip whose
name ends in `.star` is treated as a patch script. Files with other
extensions are ignored. Scripts inside subdirectories are supported; the full
zip entry path (e.g. `subdir/my-patch.star`) is used as the script's
display name in log messages.

All scripts are run for every charm deployment and upgrade in the model.
Each script decides for itself — by inspecting `charm_url` or the charm's
files — whether it should apply any changes.

Scripts are executed in alphabetical order of their zip entry path, so
execution order is deterministic.

## Starlark execution environment

Each script runs in a sandboxed Starlark interpreter with no access to the
host file system or network. Scripts cannot use `load()` to import external
modules.

The following names are predeclared for every script:

### `charm_url`

`str` — The URL of the charm being deployed or upgraded, e.g.
`ch:amd64/jammy/postgresql-14`.

### `charm_read(path) -> bytes`

Returns the raw content of a file in the charm archive.

| Parameter | Type | Description |
|-----------|------|-------------|
| `path`    | `str` | Zip-relative path, e.g. `"hooks/install"` |

Raises an error if the file does not exist. Call `.decode("utf-8")` on the
result to obtain a text string.

### `charm_write(path, content)`

Creates or overwrites a file in the charm archive.

| Parameter | Type | Description |
|-----------|------|-------------|
| `path`    | `str` | Zip-relative path |
| `content` | `str` or `bytes` | File content |

Writing to a path that does not yet exist creates the file. Writing to an
existing path replaces its content.

### `charm_delete(path)`

Removes a file from the charm archive.

| Parameter | Type | Description |
|-----------|------|-------------|
| `path`    | `str` | Zip-relative path of an existing file |

Raises an error if the file does not exist.

### `charm_list(prefix="") -> list[str]`

Returns a sorted list of file paths present in the charm archive.

| Parameter | Type | Description |
|-----------|------|-------------|
| `prefix`  | `str` | Optional directory prefix to filter results, e.g. `"hooks"` |

When `prefix` is given, only paths equal to `prefix` or whose components
start with `prefix/` are returned.

### `charm_exists(path) -> bool`

Reports whether a file exists in the charm archive.

| Parameter | Type | Description |
|-----------|------|-------------|
| `path`    | `str` | Zip-relative path |

### `sha256(content) -> str`

Returns the hex-encoded SHA-256 digest of `content`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `content` | `str` or `bytes` | Data to hash |

### `diff(old, new) -> str`

Computes a patch string (diff-match-patch format) that transforms `old`
into `new`. The result can be stored and later applied with `patch()`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `old`     | `str` | Original text |
| `new`     | `str` | Revised text |

### `patch(original, patch_text) -> str`

Applies a patch string produced by `diff()` to `original` and returns the
patched text. Raises an error if any hunk fails to apply cleanly.

| Parameter    | Type | Description |
|--------------|------|-------------|
| `original`   | `str` | Text to patch |
| `patch_text` | `str` | Patch string from `diff()` |

### `log(message)`

Writes `message` to the Juju agent log at info level, prefixed with the
script name.

| Parameter | Type | Description |
|-----------|------|-------------|
| `message` | `str` | Message to log |

## Error handling

If a patch script raises a Starlark error (e.g. calls `fail()` or performs
an illegal operation), the error is logged as a warning and the script is
skipped. The unmodified original charm archive continues to be used.

If the patch scripts zip cannot be downloaded, all patching is skipped and
the charm is deployed from the original archive.

## Example scripts

### Inject a file into every charm

```python
# inject-version.star — write a VERSION file into every deployed charm
charm_write("VERSION", "patched-by-operator\n")
```

### Conditionally patch a specific charm

```python
# patch-postgresql.star
if "postgresql" not in charm_url:
    pass  # not our charm
else:
    if charm_exists("hooks/install"):
        original = charm_read("hooks/install").decode("utf-8")
        modified = original + "\n# added by operator\n"
        charm_write("hooks/install", modified)
        log("patched hooks/install in " + charm_url)
```

### Patch a file using diff/patch

```python
# patch-config.star — apply a pre-computed patch
PATCH = """@@ -1,4 +1,4 @@
 option: default
-timeout: 30
+timeout: 60
"""
if "myapp" in charm_url and charm_exists("config.yaml"):
    original = charm_read("config.yaml").decode("utf-8")
    patched = patch(original, PATCH)
    charm_write("config.yaml", patched)
```

### Verify a file's integrity before patching

```python
# verify-and-patch.star
EXPECTED_SHA = "abc123..."
if charm_exists("lib/core.py"):
    h = sha256(charm_read("lib/core.py"))
    if h == EXPECTED_SHA:
        charm_write("lib/core.py", charm_read("lib/core.py") + b"\n# ok")
    else:
        log("unexpected sha256 for lib/core.py: " + h + ", skipping")
```

## Setting charm-patches

```text
juju model-config charm-patches=https://example.com/patches.zip
```

The URL must be reachable from the Juju unit agent. HTTPS is strongly
recommended to prevent tampering.

To clear the configuration:

```text
juju model-config --reset charm-patches
```

See {ref}`model-config-charm-patches` for the full configuration reference.
