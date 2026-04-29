# Trustfall Lite — Release Runbook

**This document is run for every release.** It assumes `SETUP.md`
has been completed at least once. If you're not sure, run the
verification block at the end of `SETUP.md` first.

The release ceremony has four phases:

1. **Phase 1 — Private dry-run.** Manual workflow trigger. Builds
   wheel + sdist, generates SBOM, generates attestation. **Does not
   publish.** Catches packaging issues before you push a tag.
2. **Phase 2 — Public RC rehearsal.** Push an RC tag (e.g.,
   `v0.3.0rc1`). Routes to TestPyPI. Verify install. If anything is
   wrong, fix and retag. RC tags are cheap.
3. **Phase 3 — Production release.** Push the production tag
   (e.g., `v0.3.0`). Routes to PyPI. Manual approval gate fires.
   Approve, watch publish, verify.
4. **Phase 4 — Post-release verification.** Confirm the published
   wheel installs cleanly via `pip install`, the GitHub Release
   has all artifacts attached, and the attestation verifies.

Each phase has explicit stop conditions. **Do not advance past a
failed phase.**

---

## Before you start

Run from your local checkout, on the branch you intend to release.

```bash
# You are on the release branch (usually main)
git status --short
git rev-parse --abbrev-ref HEAD

# The tree is clean (no uncommitted changes)
test -z "$(git status --porcelain)" && echo "clean" || echo "DIRTY — commit or stash before releasing"

# pyproject.toml version matches the tag you intend to push
grep '^version' pyproject.toml
```

The version in `pyproject.toml` MUST match the tag you intend to push,
following PEP 440 normalization rules (no hyphens, no dots inside
pre-release suffixes).

| Tag | pyproject.toml version |
|---|---|
| `v0.3.0rc1` | `0.3.0rc1` |
| `v0.3.0rc2` | `0.3.0rc2` |
| `v0.3.0` | `0.3.0` |
| `v0.3.1.post1` | `0.3.1.post1` |
| `v0.4.0.dev1` | `0.4.0.dev1` |

If they don't match, the release workflow's wheel-version sanity check
fails before publish. Fix the `pyproject.toml` version first, commit,
and verify the test suite still passes:

```bash
pytest -q
```

---

## Phase 1 — Private dry-run

**Goal:** exercise the full build chain (wheel + sdist + smoke test +
SBOM + attestation) without publishing anything. Catches packaging
issues before you commit to a tag.

### Trigger the dry-run

Open: `https://github.com/fallrisk-ai/trustfall-lite/actions/workflows/release-dry-run.yml`

Click **Run workflow**. Optional: enter a specific git ref to build
(branch name, tag name, or SHA). If left blank, builds the workflow's
default ref.

Click the green **Run workflow** button.

### Watch it run

The workflow takes ~5 minutes. You can watch the live log or come
back later. Successful completion produces a workflow-run artifact
named `release-dry-run-<RUN_ID>` containing four files:

- `fallrisk_trustfall-<VERSION>-py3-none-any.whl`
- `fallrisk_trustfall-<VERSION>.tar.gz`
- `SHA256SUMS`
- `sbom.cdx.json`

### Verify

Download the artifact (button at the bottom of the workflow run page)
and inspect:

```bash
unzip release-dry-run-<RUN_ID>.zip -d /tmp/dryrun
ls /tmp/dryrun

# Wheel filename matches expected version
ls /tmp/dryrun/*.whl

# SHA256SUMS verifies (portable across Linux and macOS)
cd /tmp/dryrun
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c SHA256SUMS
else
  shasum -a 256 -c SHA256SUMS
fi
cd -

# SBOM parses and contains the expected runtime deps (NO pytest, NO cyclonedx-bom)
python -c "
import json
sbom = json.load(open('/tmp/dryrun/sbom.cdx.json'))
names = sorted({c['name'].lower() for c in sbom['components']})
print(f'Components ({len(names)}):')
for n in names: print(f'  - {n}')
forbidden = {'pytest', 'cyclonedx-bom', 'jsonschema', 'lxml', 'build', 'respx'}
contam = forbidden & set(names)
if contam:
    print(f'CONTAMINATION: {contam}')
else:
    print('SBOM clean.')
"
```

### Stop conditions for Phase 1

Do **not** advance to Phase 2 if any of these failed:

- [ ] The dry-run workflow exited non-zero
- [ ] The wheel filename version doesn't match `pyproject.toml`
- [ ] The wheel smoke test (in the workflow log) failed any CLI subcommand
- [ ] `SHA256SUMS` doesn't verify
- [ ] The SBOM contains any of: `pytest`, `cyclonedx-bom`, `jsonschema`,
  `lxml`, `build`, `respx`
- [ ] The SBOM is missing the expected runtime deps (e.g., `click`,
  `pydantic`, `httpx`, etc. — whatever is in your declared deps)
- [ ] The attestation step in the workflow log failed

If any check failed, fix the underlying issue locally, push the fix,
and re-trigger the dry-run.

---

## Phase 2 — Public RC rehearsal

**Goal:** publish to TestPyPI, install from TestPyPI, verify the
install works end-to-end. RC tags are cheap; iterate as needed.

### Tag the RC

Pick the next RC number. For the very first release, this is `rc1`.
For subsequent retries, increment.

```bash
# Verify pyproject.toml is at the matching RC version
grep '^version' pyproject.toml
# Should read: version = "0.3.0rc1"

# Final test pass
pytest -q

# Tag and push (annotated tag, not lightweight — gives you a tag message and timestamp)
git tag -a v0.3.0rc1 -m "Trustfall Lite v0.3.0rc1 — release candidate 1"
git push origin v0.3.0rc1
```

### Watch the workflow

Open: `https://github.com/fallrisk-ai/trustfall-lite/actions`

The `release` workflow should fire automatically on the tag push.
Five jobs run:

1. **build** — builds wheel + sdist, runs tests, smoke-tests the
   wheel, generates SBOM with two-venv split
2. **attest** — generates build provenance attestations
3. **publish-testpypi** — publishes to TestPyPI (this fires; the
   `publish-pypi` job skips because the tag is a pre-release)
4. **publish-pypi** — skipped for RC tags
5. **github-release** — creates a prerelease GitHub Release

For RC tags, no manual approval is required (the `testpypi`
environment has no required-reviewer gate per `SETUP.md`).

### Verify TestPyPI publish

Once the workflow shows green, the package is live at
`https://test.pypi.org/project/fallrisk-trustfall/`.

Install it from TestPyPI in a clean environment:

```bash
# Use pipx for a fresh isolated install. The --pip-args ensures
# pipx pulls non-Trustfall dependencies from real PyPI (TestPyPI
# does not mirror the full dep ecosystem).
pipx install \
  --index-url https://test.pypi.org/simple/ \
  --pip-args="--pre --extra-index-url https://pypi.org/simple/" \
  fallrisk-trustfall

# Verify it works
trustfall --version
trustfall version
trustfall scan --help
trustfall verify --help
trustfall registry --help
trustfall diff --help

# A real scan against a small directory
mkdir -p /tmp/trustfall-test-scan
trustfall scan /tmp/trustfall-test-scan
```

If install or any command fails, **stop**. Find the issue, fix it,
bump `pyproject.toml` to the next RC version (`0.3.0rc1` → `0.3.0rc2`),
commit, push, then tag `v0.3.0rc2`. The release workflow checks that
the tag version matches `pyproject.toml`; retagging without bumping
the file will fail at the version-check step.

### Verify GitHub Release for RC

Open: `https://github.com/fallrisk-ai/trustfall-lite/releases`

The `v0.3.0rc1` release should be marked as **Pre-release**, with
all four artifacts attached:

- `fallrisk_trustfall-0.3.0rc1-py3-none-any.whl`
- `fallrisk_trustfall-0.3.0rc1.tar.gz`
- `SHA256SUMS`
- `sbom.cdx.json`

### Verify the build attestation

```bash
# Download the wheel from the GitHub Release page
gh release download v0.3.0rc1 --repo fallrisk-ai/trustfall-lite

# Verify the attestation
gh attestation verify \
  fallrisk_trustfall-0.3.0rc1-py3-none-any.whl \
  --owner fallrisk-ai
```

Expected output: `Loaded N attestations from GitHub API` followed by
verification success.

### Clean up the local pipx install

```bash
pipx uninstall fallrisk-trustfall
```

### Stop conditions for Phase 2

Do **not** advance to Phase 3 if any of these failed:

- [ ] The `release` workflow exited non-zero
- [ ] `pipx install` from TestPyPI failed
- [ ] Any of the `trustfall <subcommand> --help` invocations failed
- [ ] A real `trustfall scan` failed
- [ ] The GitHub Release is missing any of the four artifacts
- [ ] `gh attestation verify` failed
- [ ] The Trusted Publisher identity in the workflow log doesn't
  match what's configured on TestPyPI

If anything failed, fix it, commit, push, increment the RC number,
and re-tag. Do not reuse an RC number that already published.

---

## Phase 3 — Production release

**Goal:** publish to real PyPI. The manual approval gate on the `pypi`
environment forces a deliberate pause before the artifact reaches the
public mirror.

**Note on the RC→stable transition:** Phase 3 examples assume the
preceding RC was `0.3.0rc1`. If the path through Phase 2 took multiple
RC iterations (e.g., you ended on `0.3.0rc3`), the production PR must
change `pyproject.toml` from the **last RC version you actually
shipped** (whatever number that is) to the stable version `0.3.0`.
Don't copy the literal `0.3.0rc1` from the example below if your
last RC was something else.

### Bump pyproject.toml to the production version

The version bump must go through a PR because branch protection blocks
direct pushes to `main`. Use a release branch:

```bash
# Create a release branch off latest main
git checkout main
git pull origin main
git checkout -b release/v0.3.0

# Edit pyproject.toml: change "0.3.0rc1" to "0.3.0"
$EDITOR pyproject.toml

# Confirm
grep '^version' pyproject.toml
# Should read: version = "0.3.0"

# Commit and push the release branch
git add pyproject.toml
git commit -m "release: bump version to 0.3.0"
git push -u origin release/v0.3.0

# Open a PR from release/v0.3.0 → main
gh pr create \
  --title "release: bump version to 0.3.0" \
  --body "Production version bump for v0.3.0 release per RELEASE.md Phase 3." \
  --base main \
  --head release/v0.3.0
```

Wait for all required status checks (12 pytest matrix entries +
CodeQL) to pass on the PR. Then merge:

```bash
gh pr merge --squash --delete-branch
git checkout main
git pull origin main

# Confirm the bump landed
grep '^version' pyproject.toml
# Should read: version = "0.3.0"
```

### Tag the production release

```bash
# Final test pass
pytest -q

# Annotated tag with release notes preview
git tag -a v0.3.0 -m "Trustfall Lite v0.3.0 — initial public release"
git push origin v0.3.0
```

### Approve the deployment

Open: `https://github.com/fallrisk-ai/trustfall-lite/actions`

The `release` workflow fires. Watch it through the `build` and
`attest` jobs. When it reaches `publish-pypi`, the workflow **pauses**
waiting for your approval.

Click into the workflow run, find the `publish-pypi` job, and click
**Review deployments**. Check the box for `pypi`, optionally enter a
comment ("v0.3.0 production release"), and click **Approve and deploy**.

This is the deliberate pause. Take a moment. Confirm the wheel version
in the `build` job log matches the tag. Confirm SBOM cleanliness in
the `build` job log. Then approve.

After approval, the publish proceeds. ~30 seconds.

### Verify PyPI publish

Once the workflow shows green, the package is live at
`https://pypi.org/project/fallrisk-trustfall/`.

Install in a clean environment from real PyPI:

```bash
pipx install fallrisk-trustfall

# Verify
trustfall --version
trustfall version
trustfall scan --help
trustfall verify --help
trustfall registry --help
trustfall diff --help

# Real scan
mkdir -p /tmp/trustfall-prod-test
trustfall scan /tmp/trustfall-prod-test
```

### Verify GitHub Release for production

Open: `https://github.com/fallrisk-ai/trustfall-lite/releases`

The `v0.3.0` release should be marked as a normal release (not
pre-release), with all four artifacts attached.

### Verify the build attestation

```bash
gh release download v0.3.0 --repo fallrisk-ai/trustfall-lite

gh attestation verify \
  fallrisk_trustfall-0.3.0-py3-none-any.whl \
  --owner fallrisk-ai
```

### Clean up

```bash
pipx uninstall fallrisk-trustfall
```

### Stop conditions for Phase 3

These are higher-stakes than Phase 2 stop conditions because the
artifact is now public. If any of these fail, the response is
"yank the release, publish a fix as the next patch version" — there
is no "untag and retry" once the wheel is on PyPI.

- [ ] The `release` workflow exited non-zero before approval
- [ ] You approved the deployment but the publish failed (most likely
  a Trusted Publisher misconfiguration — see SETUP.md Step 6)
- [ ] `pipx install fallrisk-trustfall` from real PyPI failed
- [ ] Any `trustfall <subcommand> --help` failed
- [ ] `trustfall scan` failed on the production install
- [ ] The GitHub Release is missing artifacts
- [ ] `gh attestation verify` failed against the production wheel

If a stop condition fires after the wheel is already on PyPI, you
cannot delete the version. The fix is:

1. Yank the broken version via the PyPI web UI: open
   `https://pypi.org/manage/project/fallrisk-trustfall/release/0.3.0/`,
   scroll to "Yank release", confirm. (CLI tools for yanking exist
   but verify the tool name and command syntax against current
   docs before relying on one.)
2. Bump `pyproject.toml` to `0.3.1` (or `0.3.0.post1` if the underlying code is unchanged and only the packaging was wrong)
3. Tag and release the patch as a new ceremony

---

## Phase 4 — Post-release verification

**Goal:** confirm the release is in the state you expect, from outside
your own machine.

### Public install verification

From a different shell session (or even a different machine), confirm
the install works:

```bash
pip install --no-cache-dir fallrisk-trustfall
trustfall --version
trustfall scan --help
trustfall verify --help
trustfall registry --help
trustfall diff --help
```

The subcommand `--help` checks confirm that the console-script
entrypoints (`trustfall.cli:main` and the subcommand dispatch) wire
up correctly when installed via plain `pip` rather than `pipx`. If
any subcommand fails here but worked under the pipx install in
Phase 3, the most likely cause is a missing optional dependency or
a path-resolution issue specific to the user's site-packages layout.

### PyPI page sanity check

Open: `https://pypi.org/project/fallrisk-trustfall/`

Confirm:

- The version shown is the one you just released
- The publisher badge says "Trusted Publisher" (this confirms the OIDC
  publish path was used; no API token was involved)
- The release date is today
- The project description renders correctly (this comes from
  `README.md` via `pyproject.toml`'s `readme` field)

### TestPyPI cleanup (optional)

TestPyPI is a public mirror but it's understood to be ephemeral test
space. You don't need to do anything to TestPyPI after a successful
production release; old RC versions can stay there as historical
record.

If you want to keep TestPyPI clean for some reason, the project page
at `https://test.pypi.org/project/fallrisk-trustfall/` has per-version
delete buttons.

### Update the operator's release log

Keep a personal record of releases. Suggested entries:

```text
v0.3.0 — 2026-MM-DD
  - First public release
  - PyPI: https://pypi.org/project/fallrisk-trustfall/0.3.0/
  - GitHub Release: https://github.com/fallrisk-ai/trustfall-lite/releases/tag/v0.3.0
  - Workflow run: https://github.com/fallrisk-ai/trustfall-lite/actions/runs/<RUN_ID>
  - Approver: fallrisk-ai (self)
  - Stop conditions hit during release: <none / list>
  - Notes: <free-form>
```

This log lives outside the repo (it's operational, not source).

---

## Common failures and fixes

### `invalid-publisher` error during PyPI/TestPyPI publish step

The OIDC token from GitHub doesn't match the Trusted Publisher
configuration. Re-check the four fields per `SETUP.md` Step 6:
owner, repository, workflow filename, environment name. The most
common cause is an environment name typo (e.g., `testpypi` vs
`test-pypi`).

### `fallrisk-trustfall` already exists with a different owner

The pending publisher race condition fired — someone uploaded a
package with the same name between when you registered the pending
publisher and when you tried to publish. PyPI does not allow name
disputes; pick a different name (e.g., `fallrisk-trustfall-lite` or
`trustfall-fr`) and update both `pyproject.toml` and both Trusted
Publisher configurations.

For `fallrisk-trustfall` specifically, the practical risk of this is
near zero because the name is sufficiently obscure.

### Workflow runs the wrong publish job

If a tag like `v0.3.0` accidentally routes to `publish-testpypi`
instead of `publish-pypi` (or vice versa), the tag-shape detection in
`release.yml` is misclassifying. Check the workflow log for the
"Detect tag shape" step output:

```
Detected pre-release tag: v0.3.0rc1 (version 0.3.0rc1)
# OR
Detected stable release tag: v0.3.0 (version 0.3.0)
```

If the classification is wrong, the regex in `release.yml` needs a
fix. Open an issue, do not retag.

### Build wheel version doesn't match tag

The `build` job's "Verify built artifacts match tag version" step
fails. This means `pyproject.toml`'s `version` field doesn't match
the tag you pushed.

The fix depends on whether any publish job already ran:

**If no publish job ran yet** (the workflow failed at `build`):

1. Delete the local and remote tag:

   ```bash
   git tag -d v0.3.0
   git push origin :refs/tags/v0.3.0
   ```

2. Fix `pyproject.toml` through the same release-branch flow described
   in Phase 3 (create `release/v0.3.0`, edit, commit, push, open PR
   via `gh pr create`, wait for required checks, `gh pr merge --squash
   --delete-branch`, pull `main`).

3. From `main` after the merge, retag:

   ```bash
   git tag -a v0.3.0 -m "Trustfall Lite v0.3.0 — initial public release"
   git push origin v0.3.0
   ```

**If the failure was during an RC iteration** (workflow failed during
TestPyPI publish or post-publish verification): follow the RC retry
path in Phase 2 — bump `pyproject.toml` to the next RC number
(`0.3.0rc1` → `0.3.0rc2`), commit through the PR flow, then tag
`v0.3.0rc2`. Do not reuse the failed RC number.

**Note:** Direct push to `main` is blocked by branch protection (per
`SETUP.md` Step 2), so the `git push origin main` shortcut is not
available. All version edits must go through the PR flow.

### SBOM contamination check fails

The two-venv split in `release.yml` is not isolating cleanly. This
should be impossible if the workflow file matches what's in the
canonical repository. Check `.github/workflows/release.yml` for any
local edits and revert to the canonical version. The contamination
assertion lists the exact contaminating component name in the workflow
log — that name identifies whether it's a dev dep leak or a SBOM-tool
leak.

### Manual approval is taking too long

The `pypi` environment requires manual approval. If you forgot to
approve and walked away, the workflow waits indefinitely. Just go
back and approve. There's no timeout penalty.

If you need to cancel a release that's pending approval (e.g., you
realized the version is wrong), click **Cancel workflow** instead of
approving. Then delete the tag locally and remotely, fix, retag.

---

## Summary

The release ceremony is:

1. Dry-run via Actions UI → verify artifacts.
2. RC tag → TestPyPI → install → verify.
3. Production tag → manual approval → PyPI → install → verify.
4. Cross-check from a different shell.

The whole thing takes ~30 minutes for a clean release, more if you
hit stop conditions. Stop conditions are non-negotiable; do not
advance past them.

Future releases use this same runbook. The setup in `SETUP.md` is
done once and never revisited unless the publisher configuration or
repo location changes.
