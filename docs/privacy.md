# Privacy policy

**Draft — not legal advice; to be reviewed before paid plans.**  
**Last updated:** 2026-10-08

This policy describes how Fray processes personal data when you install the
GitHub App **Fray (getfray.dev)**, run scans, or use the read-only dashboard.
Technical detail on what is sent, where it is stored, and how long it is kept
lives in [Trust and data handling](trust.md) — that page is the source of
facts; this policy summarizes for privacy purposes.

Hosted API: `https://api.getfray.dev`.  
Hosted dashboard: `https://app.getfray.dev` (limited preview — see
[Dashboard](#dashboard)).

## Legal notice

| | |
|---|---|
| Operator | Francis Luong |
| Country | France |
| Address / registration | 15, rue Jules Lamant et ses Fils, 93330 Neuilly sur Marne |
| Privacy contact | [privacy@getfray.dev](mailto:privacy@getfray.dev) |

## Controller and contact

| | |
|---|---|
| Controller | Francis Luong, France |
| Privacy contact | [privacy@getfray.dev](mailto:privacy@getfray.dev) |

You may also use
[GitHub private vulnerability reporting](../SECURITY.md) on this repository for
security issues (security and privacy inboxes may differ).

## Personal data we process

| Category | Examples |
|---|---|
| GitHub account and install linkage | Account login, account id, installation id |
| Repository enrollment | Repository ids and whether a repo is selected / active |
| Install audit | Event metadata, including the GitHub **user id of the actor** (retained 12 months — see [trust.md](trust.md)) |
| Scan authentication | Repository identity and ref from GitHub Actions **OIDC** tokens |
| Dashboard session | GitHub numeric user id, GitHub login, visible repository ids, creation / expiry / last-seen times, and a keyed hash of the session identifier (see [Dashboard](#dashboard)) |
| Dashboard not-admitted log | GitHub numeric user id only (when sign-in succeeds but the user is not admitted) |
| Operator dashboard page views | Operator GitHub id and login, page path, and organisation (retained 12 months) |

**Scan content** is infrastructure metadata derived from your Terraform plan
(a data-flow diagram and findings). With redaction on (the default), identifying
fields are HMAC digests under a key you hold. That content is **not intended**
to contain personal data. See [trust.md](trust.md) for what is and is not sent.

We do **not** receive your source code, Terraform state, secret values, or your
redaction key. Fray never clones your repositories.

## Purposes and legal bases

| Purpose | Legal basis (GDPR-shaped) |
|---|---|
| Provide the scanning and merge-gate service you install | Performance of a contract (or steps prior to contract) |
| Provide the read-only dashboard (limited preview) to Fray operators and allowlisted design-partner organisations | Performance of a contract (or steps prior to contract) |
| Security, abuse prevention, and install audit | Legitimate interests |
| Operator dashboard page-view logging and not-admitted sign-in operational logs | Legitimate interests |
| Optional advisory LLM enrichment | Only if your organization **opts in**; otherwise not processed for this purpose |

## Processors

We use subprocessors to host and operate Fray. Names, purposes, and regions are
listed in [trust.md](trust.md) (Google Cloud, Neon, Cloudflare, and Anthropic
for opt-in enrichment only).

## International transfers

Some processing occurs outside the EEA:

- **United Kingdom** — database (Neon), as described in [trust.md](trust.md).
  Transfers rely on the European Commission’s **adequacy decision for the UK**
  (renewed 19 December 2025, valid until 27 December 2031).
- **United States** — optional Anthropic enrichment only, when an organization
  opts in ([trust.md](trust.md)). Transfers rely on the **EU Standard
  Contractual Clauses (Module 2)** incorporated in Anthropic’s Data Processing
  Addendum under its Commercial Terms. We do **not** claim EU–US Data Privacy
  Framework certification for this path.

## Retention

We keep data only as long as needed for the purposes above. Summary:

- Scan and archive data: until uninstall or repo removal, then hard-deleted
  after **30 days** (or earlier on request)
- Install audit events: **12 months**
- Dashboard sessions: **8 hours** active; expired session records are deleted by
  a daily cleanup (kept at most about one day after expiry)
- Operator dashboard page views: **12 months**
- Platform logs: about **30 days** (includes the not-admitted sign-in
  operational log described under [Dashboard](#dashboard))
- Database point-in-time history: **6 hours**
- Opt-in AI enrichment results: deleted when the **organization** is purged
  (not on single-repository removal)

### Database backups

The service database is backed up **twice daily**. Backups are **encrypted
before they leave** the processing environment, with a key held **offline** by
the operator. Encrypted backups are stored with **Cloudflare R2** in the **EU**
jurisdiction and are **deleted automatically after 30 days**.

**Consequence:** data deleted from the live service (including after uninstall
or purge) may still exist in those encrypted backups for **up to 30 days**
before it is permanently removed. Backups are used only to recover the service
after an incident and are not accessed for any other purpose. If a backup is
ever restored, deletions made since that backup was taken are applied again
before the service resumes normal operation.

Full table: [trust.md — Retention](trust.md#retention).

## Dashboard

The dashboard at `https://app.getfray.dev` is **read-only** and in **limited
preview**: only Fray operators and allowlisted design-partner organisations can
sign in.

**What is processed.** Sign-in uses the Fray GitHub App’s user authorization
(OAuth with PKCE). GitHub is the only third party contacted during sign-in:
GitHub’s OAuth authorize and token endpoints, and the API endpoints for the
signed-in user, their app installations, and the repositories of those
installations. The GitHub user access token is used only during sign-in to list
the installations and repositories the user can access, then discarded — it is
never stored.

Visible repositories are those the user can access through the Fray GitHub App
installation **and** that are actively enrolled in Fray, restricted to
allowlisted organisations. That list is computed at sign-in. Access removed on
GitHub takes effect at the next sign-in or when the session expires (at most
**8 hours**). Repository scoping is enforced in the database queries that serve
each page, not only in the user interface.

Per session Fray stores: the GitHub numeric user id, GitHub login, the list of
visible repository ids, creation, expiry and last-seen times, and a keyed hash
of the session identifier (the raw identifier exists only in the user’s
cookie).

If a user signs in but is not admitted, no session is created and no session
cookie is kept. Fray logs a single event containing only their GitHub numeric
user id. That is an operational log, retained as described under
[Retention](#retention) (platform logs).

**Purpose.** Limited-preview dashboard access for Fray operators and allowlisted
design-partner organisations, including Fray operator operations and support.

**Cookies.** Fray sets only strictly necessary, host-only cookies on
`app.getfray.dev`, each HttpOnly, Secure, and SameSite=Lax: one session cookie
(**8 hours**) and two short-lived sign-in cookies for OAuth state and PKCE
(**10 minutes**). There are no analytics, advertising, or tracking cookies.

**Third parties.** During dashboard sign-in, only GitHub is contacted (as
above). Dashboard pages load no third-party scripts, fonts, images, or
analytics; the Content-Security-Policy restricts everything to the dashboard’s
own origin.

**Operator access.** Fray operators can view all organisations’ dashboard data
for operations and support. Operator page views are recorded (operator GitHub
id and login, page path, organisation) and kept **12 months**. Customer page
views are not recorded.

Technical summary: [trust.md — Dashboard](trust.md#dashboard).

## Your rights

Depending on where you live, you may have the right to:

- Access your personal data  
- Rectification  
- Erasure  
- Restriction of processing  
- Objection to processing based on legitimate interests  
- Data portability  

You may also lodge a complaint with a supervisory authority: the French
**CNIL** (Commission nationale de l'informatique et des libertés),
[cnil.fr](https://www.cnil.fr).

To exercise rights, contact [privacy@getfray.dev](mailto:privacy@getfray.dev).

## What we do not do

- We do **not** sell personal data  
- We do **not** use Fray data for advertising  
- Fray does **not** train models on customer data  

Anthropic’s retention and training terms for opt-in enrichment are summarized
in [trust.md](trust.md) (with a link to Anthropic’s own documentation).

## Changes

We will date updates at the top of this file. Material changes will be
announced in this repository (for example a commit or release note). Continued
use of the App after a material change means you accept the updated policy,
except where law requires a different process.

## Related

- [Trust and data handling](trust.md) — including [Dashboard](trust.md#dashboard)  
- [Terms of service](terms.md)  
- [Security policy](../SECURITY.md)  
