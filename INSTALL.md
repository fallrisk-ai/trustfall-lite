# Installing Trustfall Lite

This document covers how to install Trustfall Lite v0.3.0, how to
verify the install worked, and the basic usage shapes needed for
first use. For what the tool does in depth, see `README.md`. For the
trust model behind verification, see `TRUST_MODEL.md`.

## Requirements

- Python 3.10 or later
- `pipx` (recommended) or `pip`
- Network access for the default install (PyPI download)
- Network access for the default scan workflow, OR a one-time
  registry snapshot download for the local-only workflow

Trustfall Lite is distributed as a Python package and installs on
Linux, macOS, and Windows.

---

## Install

```bash
pipx install fallrisk-trustfall
```

`pipx` installs Trustfall Lite into its own isolated Python
environment and exposes the `trustfall` command on your PATH. This
avoids dependency conflicts with other Python projects on your
machine.

If you do not have `pipx`:

```bash
# macOS
brew install pipx
pipx ensurepath

# Linux (Debian/Ubuntu)
sudo apt install pipx
pipx ensurepath

# Other systems
python3 -m pip install --user pipx
python3 -m pipx ensurepath
```

After `pipx ensurepath`, restart your shell so the `trustfall` command
is on your PATH.

If you have a specific reason not to use pipx (importing as a library,
embedding in another tool), use pip in a virtualenv instead:

```bash
pip install fallrisk-trustfall
```

---

## Verify the install

```bash
trustfall version
```

Expected output: a version string like `trustfall-lite 0.3.0`.

For an end-to-end smoke test, verify a single hash known to be in the
public registry:

```bash
trustfall verify b477be7572f0ab3ae3cbba38d508cc33e70600b2045669c4ad848051c3432094
```

Expected output:

```
✓ verified
  sha256: b477be7572f0ab3ae3cbba38d508cc33e70600b2045669c4ad848051c3432094
  model_id: Qwen/Qwen2.5-14B-Instruct
  publisher: Alibaba
  license: Apache-2.0
  enrollment_id: enroll-c4d9b64757f3
  enrollment_date: 2026-03-21T08:30:24+00:00
  registry_kid: fallrisk-96cd5e6a01e1
```

If that returns `✓ verified`, the install is working end-to-end —
network reachable, registry accessible, signature verification
working. The `registry_kid` field shows which issuer key signed the
record; for the v0.3 release, it should always read
`fallrisk-96cd5e6a01e1`.

This example hash was verified live on April 27, 2026 against the
production registry at `https://attest.fallrisk.ai/registry.json`
(issuer kid `fallrisk-96cd5e6a01e1`). Fall Risk verifies example
hashes in user-facing documentation against the live registry at
write time and dates the verification. If the registry is updated
such that this hash no longer resolves, this section will be
re-verified and the example replaced.

---

## Usage shapes

```bash
trustfall scan                        # scan default cache locations
trustfall scan ~/models               # scan a specific path
trustfall scan ./model.safetensors    # scan a single file
trustfall scan --json                 # machine-readable output
trustfall scan --include-paths        # include filesystem paths in output (opt-in)
```

The default scan looks at both your Hugging Face cache and your Ollama
store. The right adapter is auto-detected for arbitrary paths:
Hugging Face cache layout, Ollama layout, or generic file walk.

To compare a current scan against a prior one:

```bash
trustfall scan --json > baseline.json
# ... time passes, you install or remove some models ...
trustfall diff baseline.json                       # implicit current scan
trustfall diff baseline.json current.json          # explicit comparison
```

`trustfall diff` shows what changed: new artifacts, removed artifacts,
artifacts whose verification status changed, and sources added or
removed. The implicit form runs a fresh scan and compares to the
baseline; the explicit form compares two saved scans without running
a new one (useful for CI and audit).

The implicit form (one argument) is only safe for default-location
baselines — that is, baselines created by `trustfall scan --json`
with no explicit path arguments. If the baseline was created from an
explicit path, create a current scan from the same path and pass both
files to `trustfall diff`. The tool refuses (exit 64) rather than
silently scanning the wrong place.

```bash
# If the baseline used explicit paths, do this instead:
trustfall scan ~/models --json > current.json
trustfall diff baseline.json current.json
```

For CI integration, two opt-in flags control exit codes:

```bash
trustfall diff baseline.json current.json --exit-code
# exit 1 if any change is detected

trustfall diff baseline.json current.json --exit-code-on-status-regression
# exit 2 only if a previously verified artifact is no longer verified
```

Without these flags, `trustfall diff` always exits 0 on a successful
comparison regardless of what changed (inspection-first default).
Errors (file not found, malformed JSON, schema mismatch) always take
precedence and return codes 64-66.

---

## Privacy-conscious install — local-only mode

By default, `trustfall scan` sends artifact SHA-256 hashes to the Fall
Risk verification API. These hashes can reveal which model artifacts
you have. If you do not want hashes sent over the network, use
local-only mode:

```bash
trustfall registry --refresh         # one-time signed snapshot download
trustfall scan --local-only          # subsequent scans send no hashes
```

`registry --refresh` downloads the signed registry snapshot from
`https://attest.fallrisk.ai/registry.json` and caches it locally. The
snapshot is signature-verified at fetch time and again at scan time.
Refresh whenever you want the latest registry coverage.

For the full privacy posture, see `PRIVACY.md`. For independent
cryptographic verification of the snapshot, see `VERIFYING.md`.

---

## Ollama: default vs fast path

By default, Trustfall content-hashes every Ollama blob during a scan.
The fast path skips that and trusts the digest in the blob's
content-addressed filename:

```bash
trustfall scan --trust-ollama-filenames
```

The fast path is meaningfully faster on large Ollama installs (350+ GB)
but assumes the local filesystem is honest about filename ↔ content
mapping. JSON output records which mode was used per artifact
(`digest_verified`, `digest_source`).

The default mode catches local corruption, partial downloads, and
filename-mismatch issues that the fast path cannot. For most users,
the default is the right choice.

---

## Common installation issues

### `trustfall: command not found` after pipx install

`pipx ensurepath` may not have run, or the shell may not have been
restarted. Try:

```bash
pipx ensurepath
exec $SHELL
trustfall version
```

If still not found:

```bash
pipx environment --value PIPX_BIN_DIR
echo $PATH
```

The bin directory should be on your PATH.

### Python version too old

```bash
python3 --version
```

Trustfall Lite requires Python 3.10 or later. If you are on an older
Python, install a current version through your system's package
manager, or use `pyenv`, `asdf`, or another version manager.

### Registry snapshot won't refresh

If `trustfall registry --refresh` fails, check that the registry is
reachable:

```bash
curl -sI https://attest.fallrisk.ai/registry.json
```

A `200 OK` response indicates the registry is up. The registry is
publicly served with no authentication required; failures here are
network issues (firewall, proxy, DNS) between your machine and the
public internet.

### Cryptography compilation errors during pip install

In rare cases on minimal Python installs without pre-built wheels:

```bash
# Debian/Ubuntu
sudo apt install build-essential libssl-dev libffi-dev python3-dev

# macOS
xcode-select --install
```

Modern pipx and pip pick up pre-built wheels from PyPI for almost all
common platforms, so this is rarely needed.

---

## Uninstall

```bash
pipx uninstall fallrisk-trustfall
```

Or, if installed via pip:

```bash
pip uninstall fallrisk-trustfall
```

Cached registry snapshots and any local state:

```bash
rm -rf ~/.cache/fallrisk-trustfall/
```

Trustfall Lite does not write outside `~/.cache/fallrisk-trustfall/`
and the Python install location. There are no system-level services,
autostart hooks, or telemetry callbacks to clean up.

---

## Build from source

The Trustfall Lite source is at
`https://github.com/fallrisk-ai/trustfall-lite`.

```bash
git clone https://github.com/fallrisk-ai/trustfall-lite.git
cd trustfall-lite
pip install .
```

For development:

```bash
pip install -e ".[dev]"
pytest                              # run the test suite
```

---

## Next steps

- `README.md` — what the tool does
- `TRUST_MODEL.md` — what the cryptographic claims are
- `VERIFYING.md` — how to verify them independently
- `PRIVACY.md` — what data is and is not sent
- `LIMITATIONS.md` — what the tool does not claim
- `SECURITY.md` — how to report security issues
