# Fray rules

Controls Fray evaluates on infrastructure plans. Each page explains the risk, how findings are classified, and how to fix or waive them.

Rules run on the Fray service; new rules apply without upgrading the Action.

A high-severity finding blocks a pull request only when it is new compared with the default branch; newly added rules never block until the default branch has been rescanned.

## Exposure

| ID | Title | Severity | STRIDE | Platforms | Added |
|---|---|---|---|---|---|
| [FR-001](FR-001.md) | Network entry is not anonymous | medium | Spoofing | AWS, Google Cloud |  |
| [FR-010](FR-010.md) | Object storage is not public | high | Information disclosure | AWS, Google Cloud, Cloudflare |  |
| [FR-025](FR-025.md) | Object storage blocks public access | high | Information disclosure | AWS, Google Cloud, Cloudflare |  |
| [FR-029](FR-029.md) | Relational database is not directly reachable from the internet | high | Information disclosure | AWS | 2026-10-11 |

## Encryption

| ID | Title | Severity | STRIDE | Platforms | Added |
|---|---|---|---|---|---|
| [FR-026](FR-026.md) | Traffic that crosses a trust boundary is encrypted | medium | Information disclosure | AWS, Google Cloud |  |
| [FR-030](FR-030.md) | Relational database is encrypted at rest | high | Information disclosure | AWS | 2026-10-11 |

## Identity

| ID | Title | Severity | STRIDE | Platforms | Added |
|---|---|---|---|---|---|
| [FR-003](FR-003.md) | Credentials are not injected through the environment | low | Information disclosure | AWS, Google Cloud |  |
| [FR-004](FR-004.md) | Model invocation is scoped to one resource | low | Elevation of privilege | Google Cloud |  |
| [FR-007](FR-007.md) | Secret use is scoped to one resource | medium | Elevation of privilege | AWS, Google Cloud |  |
| [FR-009](FR-009.md) | Secrets are rotated | low | Information disclosure | AWS, Google Cloud |  |
| [FR-024](FR-024.md) | Object storage does not use ACLs | medium | Elevation of privilege | AWS, Google Cloud, Cloudflare |  |
| [FR-032](FR-032.md) | Object storage access is scoped to one resource | medium | Elevation of privilege | AWS, Google Cloud, Cloudflare | 2026-10-11 |

## Logging

| ID | Title | Severity | STRIDE | Platforms | Added |
|---|---|---|---|---|---|
| [FR-006](FR-006.md) | Secret reads are audit logged | low | Repudiation | AWS, Google Cloud |  |
| [FR-023](FR-023.md) | Object reads are audit logged | medium | Repudiation | AWS, Google Cloud, Cloudflare |  |
| [FR-027](FR-027.md) | Audit archive is tamper-evident | medium | Tampering | AWS, Google Cloud, Cloudflare |  |

## Resilience

| ID | Title | Severity | STRIDE | Platforms | Added |
|---|---|---|---|---|---|
| [FR-002](FR-002.md) | Internet-reachable compute has a small instance cap | medium | Denial of service | AWS, Google Cloud |  |
| [FR-008](FR-008.md) | Secret store cannot be destroyed by the tool | low | Tampering, Denial of service | AWS, Google Cloud |  |
| [FR-012](FR-012.md) | Object storage cannot be destroyed by the tool | medium | Tampering, Denial of service | AWS, Google Cloud, Cloudflare |  |
| [FR-014](FR-014.md) | Object storage keeps prior versions | medium | Tampering, Denial of service | AWS, Google Cloud, Cloudflare |  |
| [FR-033](FR-033.md) | Relational database cannot be destroyed by the tool | medium | Tampering, Denial of service | AWS | 2026-10-11 |

## Supply chain

| ID | Title | Severity | STRIDE | Platforms | Added |
|---|---|---|---|---|---|
| [FR-005](FR-005.md) | Container image is pinned by digest | medium | Tampering | AWS, Google Cloud |  |

## Data flow

| ID | Title | Severity | STRIDE | Platforms | Added |
|---|---|---|---|---|---|
| [FR-017](FR-017.md) | LLM processing region is pinned | low | Information disclosure | Google Cloud |  |

