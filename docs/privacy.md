# Privacy policy

**Draft — not legal advice; to be reviewed before paid plans.**  
**Last updated:** 2026-10-07

This policy describes how Fray processes personal data when you install the
GitHub App **Fray (getfray.dev)** and run scans. Technical detail on what is
sent, where it is stored, and how long it is kept lives in
[Trust and data handling](trust.md) — that page is the source of facts; this
policy summarizes for privacy purposes.

Hosted API: `https://api.getfray.dev`.

## Controller and contact

| | |
|---|---|
| Controller | `<OPERATOR_NAME>`, `<COUNTRY>` |
| Privacy contact | `<PRIVACY_CONTACT>` |

Until the placeholders are filled, use
[GitHub private vulnerability reporting](../SECURITY.md) on this repository for
privacy requests that cannot wait (there is no email inbox on `getfray.dev`).

## Personal data we process

| Category | Examples |
|---|---|
| GitHub account and install linkage | Account login, account id, installation id |
| Repository enrollment | Repository ids and whether a repo is selected / active |
| Install audit | Event metadata, including the GitHub **user id of the actor** (retained 12 months — see [trust.md](trust.md)) |
| Scan authentication | Repository identity and ref from GitHub Actions **OIDC** tokens |

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
| Security, abuse prevention, and install audit | Legitimate interests |
| Optional advisory LLM enrichment | Only if your organization **opts in**; otherwise not processed for this purpose |

## Processors

We use subprocessors to host and operate Fray. Names, purposes, and regions are
listed in [trust.md](trust.md) (Google Cloud, Neon, Cloudflare, and Anthropic
for opt-in enrichment only).

## International transfers

Some processing occurs outside the EEA:

- **United Kingdom** — database (Neon), as described in [trust.md](trust.md)
- **United States** — optional Anthropic enrichment only, when an organization
  opts in ([trust.md](trust.md))

Transfers rely on the providers’ data processing terms.
`<TRANSFER_MECHANISM_TO_VERIFY>` (for example Standard Contractual Clauses or
another lawful mechanism) — to be confirmed before paid plans.

## Retention

We keep data only as long as needed for the purposes above. Summary:

- Scan and archive data: until uninstall or repo removal, then hard-deleted
  after **30 days** (or earlier on request)
- Install audit events: **12 months**
- Platform logs: about **30 days**
- Database point-in-time history: **6 hours**
- Opt-in AI enrichment results: deleted when the **organization** is purged
  (not on single-repository removal)

Full table: [trust.md — Retention](trust.md#retention).

## Your rights

Depending on where you live, you may have the right to:

- Access your personal data  
- Rectification  
- Erasure  
- Restriction of processing  
- Objection to processing based on legitimate interests  
- Data portability  

You may also lodge a complaint with a supervisory authority:
`<SUPERVISORY_AUTHORITY>`.

To exercise rights, contact `<PRIVACY_CONTACT>` (or use
[private vulnerability reporting](../SECURITY.md) until that address is set).

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

- [Trust and data handling](trust.md)  
- [Terms of service](terms.md)  
- [Security policy](../SECURITY.md)  
