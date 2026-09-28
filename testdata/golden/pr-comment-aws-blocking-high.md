Blocked: 1 new high-severity issue

**Uploads bucket made public**
`module.uploads.aws_s3_bucket_public_access_block.this[0]` · aws-web-app/main.tf:268 · high · information disclosure

uploads bucket is public, so anyone who knows an object name can read it.

Fix: Keep the bucket private. Do not grant public read.

<details><summary>Accept this risk instead</summary>

```yaml
schema_version: mitigation/v1
entries:
  - rule_id: FR-010
    address: module.uploads.aws_s3_bucket.this[0]
    status: accepted
    reason: reason
```
</details>

Nothing else changed (14 findings unchanged). Rules: FR-010
