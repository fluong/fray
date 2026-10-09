Not blocking: 1 new issue

**Secret access widened to the whole project**
`google_project_iam_member.database_url_accessor` · infra/main.tf:2 · medium · elevation of privilege

fray-api can now read every secret in the project, including secrets created later. Before
this change it could read only the 1 secret it uses.

Fix: grant `roles/secretmanager.secretAccessor` on each secret with
`google_secret_manager_secret_iam_member`, not on the project.

<details><summary>Accept this risk instead</summary>

Add to `.fray/waivers.yml`:

```yaml
version: 1
waivers:
  - id: waiver-1
    rule: FR-007
    address: "google_secret_manager_secret.database_url -> fray-api credentials"
    reason: "<why this risk is acceptable — min 10 chars>"
    owner: "@security-eng"
    expires: "YYYY-MM-DD"
```
</details>

Nothing else changed (0 findings unchanged). Rules: FR-007
