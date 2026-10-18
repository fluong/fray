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
| [FR-029](FR-029.md) | Relational database is not directly reachable from the internet | high | Information disclosure | AWS, Google Cloud | 2026-10-11 |
| [FR-034](FR-034.md) | Admin ports are not open to the internet | high | Elevation of privilege | AWS | 2026-10-13 |
| [FR-041](FR-041.md) | Cache accepts traffic only from restricted networks | low | Information disclosure | AWS | 2026-10-17 |
| [FR-048](FR-048.md) | NoSQL table is not shared through its resource policy | medium | Information disclosure, Elevation of privilege | AWS | 2026-10-18 |
| [FR-049](FR-049.md) | Storage bucket is not shared through its bucket policy | medium | Information disclosure, Elevation of privilege | AWS | 2026-10-18 |
| [FR-050](FR-050.md) | Secret is not shared through its resource policy | medium | Information disclosure, Elevation of privilege | AWS | 2026-10-18 |
| [FR-044](FR-044.md) | Queue or topic is not shared through its access policy | medium | Information disclosure, Elevation of privilege | AWS | 2026-10-18 |

## Encryption

| ID | Title | Severity | STRIDE | Platforms | Added |
|---|---|---|---|---|---|
| [FR-026](FR-026.md) | Traffic that crosses a trust boundary is encrypted | medium | Information disclosure | AWS, Google Cloud |  |
| [FR-030](FR-030.md) | Relational database is encrypted at rest | high | Information disclosure | AWS, Google Cloud | 2026-10-11 |
| [FR-031](FR-031.md) | Database requires TLS for client connections | medium | Information disclosure | AWS, Google Cloud | 2026-10-12 |
| [FR-035](FR-035.md) | Traffic from internet-reachable compute to a datastore is encrypted | high | Information disclosure | AWS, Google Cloud | 2026-10-15 |
| [FR-036](FR-036.md) | Object storage is encrypted with a customer-managed key | medium | Information disclosure | AWS, Google Cloud | 2026-10-15 |
| [FR-042](FR-042.md) | Cache encrypts data in transit | medium | Information disclosure | AWS | 2026-10-17 |
| [FR-043](FR-043.md) | Cache is encrypted at rest | medium | Information disclosure | AWS | 2026-10-17 |

## Identity

| ID | Title | Severity | STRIDE | Platforms | Added |
|---|---|---|---|---|---|
| [FR-003](FR-003.md) | Credentials are not injected through the environment | low | Information disclosure | AWS, Google Cloud |  |
| [FR-004](FR-004.md) | Model invocation is scoped to one resource | low | Elevation of privilege | Google Cloud, AWS |  |
| [FR-007](FR-007.md) | Secret use is scoped to one resource | medium | Elevation of privilege | AWS, Google Cloud |  |
| [FR-009](FR-009.md) | Secrets are rotated | low | Information disclosure | AWS, Google Cloud |  |
| [FR-024](FR-024.md) | Object storage does not use ACLs | medium | Elevation of privilege | AWS, Google Cloud, Cloudflare |  |
| [FR-028](FR-028.md) | Database access is scoped to one instance | medium | Elevation of privilege | AWS, Google Cloud | 2026-10-15 |
| [FR-032](FR-032.md) | Object storage access is scoped to one resource | medium | Elevation of privilege | AWS, Google Cloud, Cloudflare | 2026-10-11 |
| [FR-039](FR-039.md) | NoSQL table access is scoped to that table | medium | Elevation of privilege | AWS | 2026-10-16 |
| [FR-045](FR-045.md) | Message queue access is scoped to that queue or topic | medium | Elevation of privilege | AWS | 2026-10-18 |
| [FR-046](FR-046.md) | Workload cannot administer the database through the cloud API | medium | Tampering, Elevation of privilege, Denial of service | AWS, Google Cloud | 2026-10-17 |

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
| [FR-033](FR-033.md) | Relational database cannot be destroyed by the tool | medium | Tampering, Denial of service | AWS, Google Cloud | 2026-10-11 |
| [FR-038](FR-038.md) | Relational database is protected from console and API deletion | medium | Tampering, Denial of service | AWS, Google Cloud | 2026-10-15 |
| [FR-040](FR-040.md) | NoSQL table is protected from deletion | medium | Tampering, Denial of service | AWS | 2026-10-16 |

## Supply chain

| ID | Title | Severity | STRIDE | Platforms | Added |
|---|---|---|---|---|---|
| [FR-005](FR-005.md) | Container image is pinned by digest | medium | Tampering | AWS, Google Cloud |  |

## Data flow

| ID | Title | Severity | STRIDE | Platforms | Added |
|---|---|---|---|---|---|
| [FR-017](FR-017.md) | LLM processing region is pinned | low | Information disclosure | Google Cloud, AWS |  |

