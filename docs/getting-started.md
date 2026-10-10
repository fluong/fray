# Getting started

Shortest path to a **first green Fray scan** in GitHub Actions.

## Checklist

1. [ ] Install the **Fray (getfray.dev)** GitHub App and **select this repository**
2. [ ] Add `fray.yaml` at the repo root (minimal example below)
3. [ ] Create secret `FRAY_REDACTION_KEY` (`openssl rand -hex 32 | gh secret set FRAY_REDACTION_KEY`). **Keep this key stable** — rotating or losing it resets the baseline (findings can't be compared with earlier scans). Store a copy in your password manager. See [README — redaction key rotation](../README.md#redaction-key-rotation).
4. [ ] Ensure the job can run `terraform plan` (provider + backend credentials — see below)
5. [ ] Add the workflow with the permissions below
6. [ ] [Verify your setup](#verify-your-setup) with `mode: check` (optional but recommended)
7. [ ] Push to the **default branch** once (establishes the merge baseline)
8. [ ] Open a PR from a branch **in this repository** (not a fork)

Free plan: **3 repositories** per App install; **30 scans/repo/hour** and **100 scans/org/day**.  
Troubleshooting: [README § Troubleshooting](../README.md#troubleshooting).

## 1. Install the App and select the repo

Install **[Fray (getfray.dev)](https://github.com/apps/fray-getfray-dev)** on your user or org account and select the repository under Repository access. Do not grant all-repos unless you intend to — the free plan covers **3 repositories**; selecting more skips scans with `installation_over_cap`.

The App has **metadata read** only. Fray never clones your code. Scans authenticate with **GitHub Actions OIDC** (`aud=fray`).

## 2. Workflow permissions

| Permission | Required? | Without it |
|------------|-----------|------------|
| `id-token: write` | **Required** | OIDC fails; scan never runs |
| `contents: read` | **Required** | Checkout / reading sources fails |
| `pull-requests: write` | Recommended | Scan runs, but **no PR comment** |
| `security-events: write` | Optional | Scan/gate still run; **SARIF upload** to Code Scanning fails (warning only). Set Action input `upload-sarif: false` if you do not want upload |

## 3. Minimal `fray.yaml`

At the repository root (or the path you pass as `config`):

```yaml
schema_version: fray-config/v1
```

Redaction is **on by default**. Keep `FRAY_REDACTION_KEY` set unless you deliberately use `redaction: off` (hosted API still rejects unredacted payloads for most orgs).

## 4. Copy-paste workflow

Pin third-party actions by **commit SHA**. Use the commit SHA of the release tag
(`git ls-remote https://github.com/fluong/fray refs/tags/v0.10.0^{}`); tags are
immutable but SHAs are what Actions guarantees. Replace the example commit SHA below
with that 40-character hex.

```yaml
name: fray

on:
  pull_request:
  push:
    branches: [main]

permissions:
  id-token: write        # required — OIDC audience "fray"
  contents: read         # required
  pull-requests: write   # PR comment
  security-events: write # SARIF → Code Scanning (optional; see table above)

jobs:
  fray:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false

      - uses: fluong/fray@c801e435b0301c8b0dff2d2d692ee94d7231a1c1 # v0.11.0
        with:
          api-url: https://api.getfray.dev
          working-directory: .   # Terraform root (directory with .tf files)
          redaction-key: ${{ secrets.FRAY_REDACTION_KEY }}
```

Set `working-directory` to your Terraform root if it is not the repo root (for example `infra`).

Optional: `fail-on-skip: true` fails the job on enrollment or rate-limit soft-skips (default is warn + exit 0). See [README](../README.md#github-action).

## Verify your setup

Before the first real scan, run **`mode: check`** to confirm OIDC, `api-url`,
`fray.yaml`, redaction key, waivers, either a valid `plan-file` or
`terraform init -backend=false` + `validate` in `working-directory`, and that
the **Fray GitHub App is installed with this repository enrolled**. This does
**not** submit a scan, post a PR comment, upload SARIF, or run the gate.

Use `workflow_dispatch` (or a non-fork branch). Fork PRs cannot mint OIDC and
fail the check on purpose.

```yaml
name: fray-setup-check

on:
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - uses: fluong/fray@c801e435b0301c8b0dff2d2d692ee94d7231a1c1 # v0.11.0
        with:
          mode: check
          api-url: https://api.getfray.dev
          working-directory: .   # Terraform root (directory with .tf files)
          redaction-key: ${{ secrets.FRAY_REDACTION_KEY }}
```

Inspect the job summary **Fray — setup check** for pass/warn/fail per row. Fix
any failures before switching to the full scan workflow (`mode` omitted or
`scan`).

## 5. What `terraform plan` needs (or bring your own plan)

**Default:** the Action runs **`terraform init`**, **`plan`**, and **`show -json`** inside `working-directory`. Give the job the **same provider and backend credentials** you use for a normal plan in CI.

**Bring your own plan:** if credentials or planning must live in another job, pass **`plan-file`** (path relative to `working-directory`) to a `terraform show -json` file. Fray skips terraform in the Fray job. See [README — Bring your own plan](../README.md#bring-your-own-plan).

> **Warning:** plan JSON contains **secrets in plaintext**. Use artifact `retention-days: 1`, never upload plans from fork PRs, and delete after use when possible. Fray strips sensitive-marked values before the API request; the artifact is still sensitive.

## 6. What to expect on the first PR

- **Default-branch push first:** Fray stores a baseline from the default branch. Until that exists, PR comments still appear, but findings are shown in **absolute** mode with:

  > No baseline yet — comparison against the default branch starts after its first Fray scan.

- After the default branch has been scanned once, PR comments show **new vs baseline** and the merge gate can block on new high-severity findings.
- Soft enrollment / rate-limit skips emit a **warning** on the checks page and a job-summary block (exit 0 unless `fail-on-skip` / `fail-on-unenrolled` / `fail-on-rate-limit`).
- Fork PRs cannot mint OIDC for audience `fray` — open the PR from a branch in this repository.

## Next

- [README — Install & Action inputs](../README.md#install)
- [README — Troubleshooting](../README.md#troubleshooting)
- [Waivers](../README.md#waivers)
- [Trust and data handling](trust.md)
