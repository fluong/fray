No baseline yet — comparison against the default branch starts after its first Fray scan.

Blocked: 6 new issues

**Uploads bucket made public**
`module.uploads` · `block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets` · aws-web-app/main.tf:268 · high · information disclosure

uploads bucket is public, so anyone who knows an object name can read it.

Fix: Set `block_public_acls`, `block_public_policy`, `ignore_public_acls`,
`restrict_public_buckets` to true.

<details><summary>Accept this risk instead</summary>

Resource: `module.uploads.aws_s3_bucket_public_access_block.this[0]`

Add to `.fray/waivers.yml`:

```yaml
version: 1
waivers:
  - id: waiver-1
    rule: FR-010
    address: module.uploads.aws_s3_bucket.this[0]
    reason: "<why this risk is acceptable — min 10 chars>"
    owner: "@security-eng"
    expires: "YYYY-MM-DD"
```
</details>

**this resource is open to the internet**
`module.alb` · aws-web-app/main.tf:59 · medium · spoofing

{from} can reach this resource without a caller identity.

Fix: Require a caller identity on this flow. Do not grant it to the public.

<details><summary>Accept this risk instead</summary>

Resource: `module.alb.aws_lb.this[0]`

Add to `.fray/waivers.yml`:

```yaml
version: 1
waivers:
  - id: waiver-1
    rule: FR-001
    address: "signal:network_ingress:0.0.0.0/0 -> module.alb.aws_lb.this[0] unknown"
    reason: "<why this risk is acceptable — min 10 chars>"
    owner: "@security-eng"
    expires: "YYYY-MM-DD"
```
</details>

**ecs_service image can change without review**
`module.ecs_service` · aws-web-app/main.tf:112 · medium · tampering

ecs_service starts from a mutable image tag, so a later start can run different code.

Fix: Deploy the image by digest.

<details><summary>Accept this risk instead</summary>

Resource: `module.ecs_service.aws_ecs_service.this[0]`

Add to `.fray/waivers.yml`:

```yaml
version: 1
waivers:
  - id: waiver-1
    rule: FR-005
    address: module.ecs_service.aws_ecs_service.this[0]
    reason: "<why this risk is acceptable — min 10 chars>"
    owner: "@security-eng"
    expires: "YYYY-MM-DD"
```
</details>

**uploads bucket can be destroyed by the infrastructure tool**
`module.uploads` · `block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets` · aws-web-app/main.tf:268 · medium · tampering, denial of service

Destroying uploads bucket removes the stored objects.

Fix: Set `block_public_acls`, `block_public_policy`, `ignore_public_acls`,
`restrict_public_buckets` to true.

<details><summary>Accept this risk instead</summary>

Resource: `module.uploads.aws_s3_bucket.this[0]`

Add to `.fray/waivers.yml`:

```yaml
version: 1
waivers:
  - id: waiver-1
    rule: FR-012
    address: module.uploads.aws_s3_bucket.this[0]
    reason: "<why this risk is acceptable — min 10 chars>"
    owner: "@security-eng"
    expires: "YYYY-MM-DD"
  - id: waiver-2
    rule: FR-014
    address: module.uploads.aws_s3_bucket.this[0]
    reason: "<why this risk is acceptable — min 10 chars>"
    owner: "@security-eng"
    expires: "YYYY-MM-DD"
```
</details>

**db_password secret is never rotated**
`module.db_password` · aws-web-app/main.tf:282 · low · information disclosure

db_password secret stays valid indefinitely after it leaks.

Fix: Configure a rotation schedule on the secret.

<details><summary>Accept this risk instead</summary>

Resource: `module.db_password.aws_secretsmanager_secret.this[0]`

Add to `.fray/waivers.yml`:

```yaml
version: 1
waivers:
  - id: waiver-1
    rule: FR-009
    address: module.db_password.aws_secretsmanager_secret.this[0]
    reason: "<why this risk is acceptable — min 10 chars>"
    owner: "@security-eng"
    expires: "YYYY-MM-DD"
```
</details>

**Secret exposed in the process environment**
`module.ecs_service` · aws-web-app/main.tf:112 · low · information disclosure

A secret is injected into ecs_service as an environment variable.

Fix: Deliver the secret as a mounted file. Do not put it in the process environment.

<details><summary>Accept this risk instead</summary>

Resource: `module.ecs_service.aws_ecs_service.this[0]`

Add to `.fray/waivers.yml`:

```yaml
version: 1
waivers:
  - id: waiver-1
    rule: FR-003
    address: "module.db_password.aws_secretsmanager_secret.this[0] -> module.ecs_service.aws_ecs_service.this[0] credentials"
    reason: "<why this risk is acceptable — min 10 chars>"
    owner: "@security-eng"
    expires: "YYYY-MM-DD"
```
</details>

Nothing else changed (0 findings unchanged). Rules: FR-001, FR-003, FR-005, FR-009, FR-010, FR-012, FR-014
