# Trust and data handling

How Fray handles data when you install the GitHub App, run scans from your CI,
or use the read-only dashboard. Plain facts — no marketing claims beyond what
the product does today.

**Last updated:** 2026-10-08

Hosted API: `https://api.getfray.dev`.  
Hosted dashboard: `https://app.getfray.dev` (limited preview — see
[Dashboard](#dashboard)).

## What is sent

Each scan POSTs a **data-flow diagram (DFD)** derived from your Terraform plan,
plus findings context needed for the merge gate.

**Redaction is on by default** (omit `redaction` in `fray.yaml`). When it is on,
you must set `FRAY_REDACTION_KEY` in CI — if the key is unset, the client fails
before posting (it does not fall back to plaintext). With redaction on:

- Resource names, Terraform addresses, signal names, and similar identifiers are
  replaced with HMAC digests under that key. The key never leaves your CI.
- Optional closed-enum `purpose` values (for example `customer_uploads`) may be
  sent in the clear — they are roles, not names.

You can set `redaction: off` in `fray.yaml` to send plaintext identifiers. That
is client-side only and prints a loud warning. The hosted API still **rejects
unredacted payloads** for orgs with `require_redaction` (the default for every
new org, including App installs) unless Fray disables it at your request.

Fray also learns **which GitHub repository and ref** ran the scan from the
GitHub Actions OIDC token used to authenticate. Redaction does not hide that
repository identity from Fray.

## What is not sent

- Source code or git history  
- Terraform state  
- Secret values or environment variable contents  
- Your redaction key  

Fray never clones your repositories. The GitHub App has **metadata read** only.

## What the GitHub App stores

From install and webhook events (not from your source tree):

- Account login, account id, and installation id  
- Repository ids and enrollment state (which repos are selected / active)  
- Install audit events, including the GitHub **user id of the actor**, retained
  for **12 months**

## Where data lives

Data is stored in the EU and UK.

| Component | Provider | Region |
|---|---|---|
| API | Google Cloud Run | europe-west1 (Belgium) |
| Database | Neon Postgres | AWS eu-west-2 (London, UK) |
| Scan archive | Cloudflare R2 | EU jurisdiction |
| Database backups | Cloudflare R2 | EU jurisdiction (encrypted; see [Backups](#backups)) |

## Retention

| Data | Retention |
|---|---|
| Scan records, findings, archived DFD/findings objects | Until you uninstall the App or remove a repository; then **hard-deleted after 30 days** (database rows and archive objects). Archive deletes are final — no object lock. |
| AI enrichment results (if opted in) | Deleted when the organization is purged (uninstall + 30 days or on request); not deleted on single-repository removal. |
| Webhook delivery IDs | 30 days |
| Install audit events | 12 months |
| Dashboard sessions | **8 hours** active; expired session records deleted by a daily cleanup (kept at most about one day after expiry) |
| Operator dashboard page views | 12 months |
| Platform logs | ~30 days (includes not-admitted dashboard sign-in events that record only a GitHub numeric user id) |
| Database point-in-time history | **6 hours** (after a live delete, rows may still be restoreable for that window) |
| Encrypted database backups | **30 days**, then deleted automatically. Data removed from the live service (including after uninstall/purge) may remain in these backups until that window ends. |

Access is soft-disabled immediately on uninstall or repo removal. Re-installing
within 30 days keeps existing scan history for that organization.

### Request deletion earlier

For privacy and data-protection requests — including an early purge of your
organization or repository — contact
[privacy@getfray.dev](mailto:privacy@getfray.dev). That is the only monitored
address on `getfray.dev`.

## Subprocessors

| Subprocessor | Purpose | Region / notes |
|---|---|---|
| Google Cloud | Hosts the API and platform logs | europe-west1 (Belgium) |
| Neon | Postgres for orgs, scans, findings, install linkage | AWS eu-west-2 (London, UK) |
| Cloudflare | Private R2 archive of redacted DFD/findings JSON; encrypted database backups | EU jurisdiction |
| Anthropic | Optional advisory LLM enrichment only | Processing in the **United States** for the current model; see below |

## Advisory LLM (optional, off by default)

Enrichment is **per-organization opt-in** and off by default. When enabled:

- Only neighborhoods for findings that are **new versus your default-branch
  baseline** may be sent — not every scan, and never source code.
- The payload is the **same redacted DFD structure** used for scans
  (identifiers as HMAC digests when redaction is on).
- Processing is in the **US** (Anthropic Messages API for the current Haiku
  model; no EU inference option for that model).
- Anthropic deletes API inputs/outputs within **30 days** and does **not** use
  them for training. Flagged content may be retained for Trust & Safety for up
  to **2 years**. Source:
  [Anthropic — How long do you store my organization’s data?](https://privacy.claude.com/en/articles/7996866-how-long-do-you-store-my-organization-s-data)
- Fray's logs record model id, token counts, latency, and HTTP status only —
  never prompts or completions.
- The advisory text returned for a scan is stored with that scan and deleted
  with it, including on uninstall/purge. Copies in encrypted backups expire
  within 30 days (see Backups).

Scans and the merge gate work with enrichment left off (rules-only).

## Backups

The service database is backed up **twice daily**. Backups are encrypted before
they leave the processing environment (key held offline by the operator), stored
in Cloudflare R2 (EU jurisdiction), and deleted automatically after **30 days**.
Backups are used only for disaster recovery; after any restore, deletions made
since the backup are re-applied.

## Security controls (summary)

- **CI auth:** GitHub Actions OIDC (`aud` = `fray`). No customer API keys for CI.
- **GitHub App:** metadata read-only; App signing key held in Cloud KMS
  (non-exportable). Fray does not clone repos.
- **Least privilege:** The API’s database role cannot delete customer data;
  deletion runs only as a separate purge role, nightly, with its own
  credentials.
- **Redaction:** customer-held key when redaction is on; hosted API rejects
  unredacted payloads unless Fray disables it at your request
  (`require_redaction` defaults on).

## Free plan

**3 repositories** per GitHub App installation. If an installation selects more
than 3 repositories, scans for **all** of its repositories are skipped
(`installation_over_cap`) until you narrow the selection.

## Dashboard

Read-only dashboard at `https://app.getfray.dev` (limited preview):

- **Read-only limited preview** — only Fray operators and allowlisted
  design-partner organisations can sign in.
- **Access scope** — visible repositories are those the user can access through
  the Fray GitHub App installation and that are actively enrolled in Fray,
  restricted to allowlisted organisations. The list is computed at sign-in;
  access removed on GitHub takes effect at the next sign-in or when the session
  expires (**at most 8 hours**).
- **Token not stored** — the GitHub user access token is used only during
  sign-in to list installations and repositories, then discarded.
- **Scoping in queries** — repository scoping is enforced in the database
  queries that serve each page, not only in the user interface.
- **Session cookies** — strictly necessary, host-only on `app.getfray.dev`,
  HttpOnly, Secure, SameSite=Lax: one session cookie (**8 hours**) and two
  short-lived sign-in cookies for OAuth state and PKCE (**10 minutes**). No
  analytics, advertising, or tracking cookies.
- **No third-party assets** — dashboard pages load no third-party scripts,
  fonts, images, or analytics; the Content-Security-Policy restricts everything
  to the dashboard’s own origin.
- **Operator access logged** — Fray operators can view all organisations’
  dashboard data for operations and support. Operator page views (operator
  GitHub id and login, page path, organisation) are kept **12 months**.
  Customer page views are not recorded.

Privacy wording: [privacy.md — Dashboard](privacy.md#dashboard).

## Related

- [Install](../README.md#install) — App install and workflow
- [Privacy policy](privacy.md) — draft (not legal advice; review before paid plans), including [Dashboard](privacy.md#dashboard)
- [Terms of service](terms.md) — draft (not legal advice; review before paid plans)
- [SECURITY.md](../SECURITY.md) — how to report a vulnerability
