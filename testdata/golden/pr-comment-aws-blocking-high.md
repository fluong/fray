Blocked: 1 new high-severity issue

**Uploads bucket made public**
`module.uploads` · `block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets` · aws-web-app/main.tf:268 · high · information disclosure

uploads bucket is public, so anyone who knows an object name can read it.

Fix: Set `block_public_acls`, `block_public_policy`, `ignore_public_acls`,
`restrict_public_buckets` to true.

<details><summary>Accept this risk instead</summary>

Resource: `module.uploads.aws_s3_bucket_public_access_block.this[0]`

```yaml
schema_version: mitigation/v1
entries:
  - rule_id: FR-010
    address: module.uploads.aws_s3_bucket.this[0]
    status: accepted
    reason: "<why this risk is acceptable>"
```
</details>

Nothing else changed (14 findings unchanged). Rules: FR-010
