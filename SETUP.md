# Trustfall Lite — One-Time Setup

**This document is run once.** After it's complete, every release uses
`RELEASE.md` instead. Estimated time end-to-end: 30–45 minutes
of focused work.

The result of completing this document: a private GitHub repository
configured with branch protection, two GitHub Environments (`testpypi`
and `pypi`), a Pending Trusted Publisher on TestPyPI, and a Pending
Trusted Publisher on PyPI. After this is done, publishing is initiated
by a tag push. Production publishes also require manual approval of
the `pypi` environment.

---

## Before you start

- You have admin access to the `fallrisk-ai` GitHub account.
- You have a PyPI account and a TestPyPI account (separate logins —
  TestPyPI is a separate site at `https://test.pypi.org/`). 2FA is
  enabled on both.
- The recovery codes for both PyPI accounts and the GitHub account
  are stored somewhere durable and private. (No tooling is
  prescribed; use whatever password manager or offline storage you
  already trust.)
- The `gh` CLI is installed and authenticated (`gh auth status`).
- You are sitting at a terminal inside the local checkout of
  `trustfall-lite` on the branch you intend to release from.

---

## Step 0 — Resolve the repo state

There are three possible starting states. Identify which one applies
and follow the matching path.

### State A — Repo already exists at `github.com/fallrisk-ai/trustfall-lite`

Skip to Step 1.

### State B — Repo does not exist yet

```bash
gh repo create fallrisk-ai/trustfall-lite \
  --private \
  --description "Identify what you have. Verify what you trust." \
  --homepage "https://fallrisk.ai"
```

Then push your local branch:

```bash
git remote add origin git@github.com:fallrisk-ai/trustfall-lite.git
git push -u origin main
```

### State C — Repo exists under a different name

Rename it via the GitHub web UI (Settings → "Rename") to exactly
`trustfall-lite`. Update your local remote afterward:

```bash
git remote set-url origin git@github.com:fallrisk-ai/trustfall-lite.git
```

### Verification

```bash
gh repo view fallrisk-ai/trustfall-lite --json name,visibility,defaultBranchRef
```

Expected: `name` is `trustfall-lite`, `visibility` is `PRIVATE`,
`defaultBranchRef.name` is `main`.

---

## Step 1 — Repo settings

Open the repo in a browser:
`https://github.com/fallrisk-ai/trustfall-lite/settings`

### General

| Setting | Value |
|---|---|
| Default branch | `main` |
| Allow merge commits | **no** (incompatible with required linear history; see Step 2) |
| Allow squash merging | yes |
| Allow rebase merging | no (squash is the only path; one PR = one clean commit) |
| Always suggest updating pull request branches | yes |
| Automatically delete head branches | yes |

### Pull Requests

| Setting | Value |
|---|---|
| Allow auto-merge | no (single-operator project; auto-merge introduces drift risk) |

### Features

| Setting | Value |
|---|---|
| Issues | enabled |
| Discussions | enabled (the issue template `config.yml` links to Discussions) |
| Projects | optional |
| Wiki | disabled (documentation lives in the repo) |

### Code security and analysis

| Setting | Value |
|---|---|
| Dependency graph | enabled |
| Dependabot alerts | enabled |
| Dependabot security updates | enabled |
| Code scanning (CodeQL) | will be enabled automatically by `.github/workflows/codeql.yml` |
| Secret scanning | enabled |
| Push protection | enabled |

### Verification

```bash
gh repo view fallrisk-ai/trustfall-lite --json hasIssuesEnabled,hasWikiEnabled,hasDiscussionsEnabled
```

Expected: `hasIssuesEnabled: true`, `hasWikiEnabled: false`,
`hasDiscussionsEnabled: true`.

---

## Step 2 — Branch protection on `main`

Open: `https://github.com/fallrisk-ai/trustfall-lite/settings/branches`

Click **Add branch protection rule**. Branch name pattern: `main`.

| Setting | Value |
|---|---|
| Require a pull request before merging | yes |
| Require approvals | **0** (see solo-maintainer note below) |
| Dismiss stale pull request approvals when new commits are pushed | yes |
| Require review from Code Owners | **no for now** (see solo-maintainer note below) |
| Require status checks to pass before merging | yes |
| Require branches to be up to date before merging | yes |
| **Required status checks (search and add):** | `pytest (Python 3.10 on ubuntu-latest)` |
|  | `pytest (Python 3.11 on ubuntu-latest)` |
|  | `pytest (Python 3.12 on ubuntu-latest)` |
|  | `pytest (Python 3.13 on ubuntu-latest)` |
|  | `pytest (Python 3.10 on macos-latest)` |
|  | `pytest (Python 3.11 on macos-latest)` |
|  | `pytest (Python 3.12 on macos-latest)` |
|  | `pytest (Python 3.13 on macos-latest)` |
|  | `pytest (Python 3.10 on windows-latest)` |
|  | `pytest (Python 3.11 on windows-latest)` |
|  | `pytest (Python 3.12 on windows-latest)` |
|  | `pytest (Python 3.13 on windows-latest)` |
|  | `CodeQL analysis` |
| Require conversation resolution before merging | yes |
| Require signed commits | optional (enable if you want; currently signed commits are not required by `CONTRIBUTING.md`) |
| Require linear history | yes |
| Require deployments to succeed before merging | no (deployments fire on tags, not PRs) |
| Lock branch | no |
| Do not allow bypassing the above settings | yes |
| Restrict who can push to matching branches | yes — add `fallrisk-ai` |
| Allow force pushes | no |
| Allow deletions | no |

**Important:** GitHub will not let you add status checks that haven't
fired at least once in this repo. If the dropdown is empty, push a
test commit on a branch and open a PR first to trigger the workflows,
then come back to this page. The workflows are:

- `.github/workflows/test.yml` (provides the 12 `pytest` matrix entries)
- `.github/workflows/codeql.yml` (provides `CodeQL analysis`)

### Solo-maintainer note (why approvals = 0)

GitHub's branch protection prevents pull request authors from
approving their own PRs. With a single maintainer, "Require approvals: 1"
combined with "Require review from Code Owners" creates a deadlock —
you would not be able to merge any of your own PRs.

The configuration above (Require PR yes, approvals 0, Code Owner review
no) keeps the audit-trail benefits of the PR workflow — required CI
checks, discussion thread, conversation resolution, signed-commit
option, no force-push — without the deadlock. Direct push to `main`
is still blocked; every change must go through a PR with all status
checks passing.

When Fall Risk has a second maintainer or a visible GitHub team with
write access, raise approvals to 1 and enable Code Owner review.

### Verification

```bash
gh api "repos/fallrisk-ai/trustfall-lite/branches/main/protection" \
  --jq '{
    requires_pr: .required_pull_request_reviews != null,
    required_checks: .required_status_checks.contexts,
    enforce_admins: .enforce_admins.enabled,
    linear_history: .required_linear_history.enabled
  }'
```

Expected: `requires_pr: true`, `enforce_admins: true`, `linear_history:
true`, and `required_checks` includes the 13 entries listed above.

---

## Step 3 — Create GitHub Environments

GitHub Environments are how the release workflow knows which
PyPI/TestPyPI Trusted Publisher to use. Each environment is a named
gate that the workflow's `environment:` block references.

Open: `https://github.com/fallrisk-ai/trustfall-lite/settings/environments`

### 3a. Create the `testpypi` environment

Click **New environment**. Name: `testpypi` (lowercase, exact match).

Configuration:

| Setting | Value |
|---|---|
| Required reviewers | **none** (TestPyPI is rehearsal space; friction here slows every iteration) |
| Wait timer | 0 minutes |
| Deployment branches and tags | **Selected branches and tags** → add tag pattern `v*.*.*` |
| Environment secrets | none |
| Environment variables | none |

Click **Save protection rules**.

### 3b. Create the `pypi` environment

Click **New environment**. Name: `pypi` (lowercase, exact match).

Configuration:

| Setting | Value |
|---|---|
| Required reviewers | **add yourself** (`fallrisk-ai`). This creates a manual approval gate before any production publish. |
| Prevent self-review | **off** (critical: if enabled with you as the only reviewer, you cannot approve your own deployment and the production publish deadlocks) |
| Wait timer | 0 minutes |
| Deployment branches and tags | **Selected branches and tags** → add tag pattern `v*.*.*` |
| Environment secrets | none |
| Environment variables | none |

Click **Save protection rules**.

### Verification

```bash
gh api "repos/fallrisk-ai/trustfall-lite/environments" \
  --jq '.environments[] | {name: .name, reviewers: [.protection_rules[]?.reviewers[]?.reviewer.login]}'
```

Expected output:

```json
{"name": "testpypi", "reviewers": []}
{"name": "pypi", "reviewers": ["fallrisk-ai"]}
```

If `pypi` shows `reviewers: []`, the manual-approval gate isn't
configured — go back and add yourself as a required reviewer.

---

## Step 4 — Configure TestPyPI Pending Trusted Publisher

TestPyPI is a separate site from PyPI. Log in at
`https://test.pypi.org/` (separate account from PyPI).

Open: `https://test.pypi.org/manage/account/publishing/`

Scroll to **Add a new pending publisher**. Select the **GitHub** tab.

Fill in **exactly** these values:

| Field | Value |
|---|---|
| PyPI Project Name | `fallrisk-trustfall` |
| Owner | `fallrisk-ai` |
| Repository name | `trustfall-lite` |
| Workflow name | `release.yml` |
| Environment name | `testpypi` |

Click **Add**.

### Important — name-race caveat

A pending publisher does **not** reserve the project name on TestPyPI
until the first publish actually succeeds. If someone else uploads a
package named `fallrisk-trustfall` to TestPyPI between now and your
first RC tag push, the pending publisher is invalidated. The mitigation
is simple: do the RC rehearsal in the `RELEASE.md` promptly
after this setup completes, ideally within the same work session.

For a name as obscure as `fallrisk-trustfall`, the practical risk is
near zero, but it's worth being aware of.

### Verification

The new pending publisher should appear at the top of the page, listed
as "Pending publisher: fallrisk-trustfall". If it does not appear,
re-check the form values for typos and re-submit.

---

## Step 5 — Configure PyPI Pending Trusted Publisher

PyPI is a separate site from TestPyPI. Log in at
`https://pypi.org/` (separate account from TestPyPI).

Open: `https://pypi.org/manage/account/publishing/`

Scroll to **Add a new pending publisher**. Select the **GitHub** tab.

Fill in **exactly** these values:

| Field | Value |
|---|---|
| PyPI Project Name | `fallrisk-trustfall` |
| Owner | `fallrisk-ai` |
| Repository name | `trustfall-lite` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

Click **Add**.

The same name-race caveat from Step 4 applies. The mitigation is the
same: complete the production release in the `RELEASE.md`
within a reasonable window after this setup.

### Verification

The new pending publisher appears at the top of
`https://pypi.org/manage/account/publishing/` listed as "Pending
publisher: fallrisk-trustfall".

---

## Step 6 — Cross-check: workflow ↔ publisher field alignment

This is the single most important verification step in this document.
A mismatch between the workflow file and the Trusted Publisher
configuration causes a silent `invalid-publisher` error at publish
time, with no useful diagnostic. Catch it now.

Run this one-liner from your local checkout:

```bash
grep -E "environment:|name: (pypi|testpypi)" .github/workflows/release.yml
```

Expected output:

```
    environment:
      name: testpypi
    environment:
      name: pypi
```

Cross-check each value against what you typed into the publisher forms:

| Field | release.yml | TestPyPI publisher | PyPI publisher |
|---|---|---|---|
| Owner | (n/a — implicit from repo) | `fallrisk-ai` | `fallrisk-ai` |
| Repository | (n/a — implicit from repo) | `trustfall-lite` | `trustfall-lite` |
| Workflow file | `release.yml` | `release.yml` | `release.yml` |
| Environment | `testpypi` (job 3) | `testpypi` | n/a |
| Environment | `pypi` (job 4) | n/a | `pypi` |
| Project name | (n/a — derived from `pyproject.toml`) | `fallrisk-trustfall` | `fallrisk-trustfall` |

If any row disagrees, fix the publisher form (not the workflow). The
workflow values are the source of truth — they were locked through
adversarial review and any change to them needs to go through the
same review process.

Also confirm `pyproject.toml` declares the right project name:

```bash
grep '^name' pyproject.toml
```

Expected: `name = "fallrisk-trustfall"`.

---

## Step 7 — Final sanity check

Confirm everything aligns by running this single block:

```bash
echo "=== Repo ===" && \
gh repo view fallrisk-ai/trustfall-lite --json name,visibility,defaultBranchRef && \
echo "" && \
echo "=== Branch protection ===" && \
gh api "repos/fallrisk-ai/trustfall-lite/branches/main/protection" --jq \
  '{requires_pr: .required_pull_request_reviews != null, required_checks: (.required_status_checks.contexts | length), enforce_admins: .enforce_admins.enabled}' && \
echo "" && \
echo "=== Environments ===" && \
gh api "repos/fallrisk-ai/trustfall-lite/environments" --jq \
  '.environments[] | {name: .name, reviewers: [.protection_rules[]?.reviewers[]?.reviewer.login]}' && \
echo "" && \
echo "=== Workflow file present ===" && \
ls -la .github/workflows/release.yml && \
echo "" && \
echo "=== pyproject project name ===" && \
grep '^name' pyproject.toml
```

Expected: all six sections produce non-error output, with the values
from the verification steps above. If anything is missing or wrong,
go back and fix it before proceeding to `RELEASE.md`.

---

## Setup complete

The repo is configured. The Pending Trusted Publishers are registered.
The Environments gate the publish jobs. Branch protection enforces
review and CI on every change.

The next thing you do is run `RELEASE.md` end-to-end. The
release ceremony will:

1. **First RC publish** (Phase 2 of `RELEASE.md`) converts the
   TestPyPI pending publisher into a normal publisher and reserves
   the `fallrisk-trustfall` name on TestPyPI.
2. **First production publish** (Phase 3 of `RELEASE.md`) converts
   the PyPI pending publisher into a normal publisher and reserves
   the `fallrisk-trustfall` name on PyPI.
3. After production publish, v0.3.0 is available via
   `pip install fallrisk-trustfall`.

After that, every subsequent release is just `RELEASE.md`
end-to-end — no setup work ever needs to be redone unless the
Trusted Publisher configuration is changed (e.g., environment rename,
workflow file rename, repo move).
