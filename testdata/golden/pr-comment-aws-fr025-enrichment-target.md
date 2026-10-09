Blocked: 1 new high-severity issue

**Uploads bucket no longer blocks public access**
`module.uploads` · `block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets` · aws-web-app/main.tf:268 · high · information disclosure

Nothing in the bucket is public yet, but nothing now prevents a bucket policy from making
it public.

Why this matters here: ACLs are already disabled on this bucket, so a bucket policy is now
the only way it could become public — and nothing blocks one anymore.

Fix: Set `block_public_acls`, `block_public_policy`, `ignore_public_acls`,
`restrict_public_buckets` to true.

<details><summary>Accept this risk instead</summary>

Resource: `module.uploads.aws_s3_bucket.this[0]`

Add to `.fray/waivers.yml`:

```yaml
version: 1
waivers:
  - id: waiver-1
    rule: FR-025
    address: module.uploads.aws_s3_bucket.this[0]
    reason: "<why this risk is acceptable — min 10 chars>"
    owner: "@security-eng"
    expires: "YYYY-MM-DD"
```
</details>

Nothing else changed (14 findings unchanged). Rules: FR-025
