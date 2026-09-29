Blocked: 1 new high-severity issue

**Uploads bucket no longer blocks public access**
`module.uploads` · `block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets` · aws-web-app/main.tf:253 · high · information disclosure

Nothing in the bucket is public yet, but nothing now prevents a bucket policy or ACL from
making it public.

Why this matters here: ACLs are already disabled on this bucket (object ownership is
BucketOwnerEnforced), so a bucket policy is now the only way it could become public —
and nothing blocks one anymore.

Fix: Set `block_public_acls`, `block_public_policy`, `ignore_public_acls`,
`restrict_public_buckets` to true.

<details><summary>Accept this risk instead</summary>

Resource: `module.uploads.aws_s3_bucket.this[0]`

```yaml
schema_version: mitigation/v1
entries:
  - rule_id: FR-025
    address: module.uploads.aws_s3_bucket.this[0]
    status: accepted
    reason: "<why this risk is acceptable>"
```
</details>

Nothing else changed (14 findings unchanged). Rules: FR-025
