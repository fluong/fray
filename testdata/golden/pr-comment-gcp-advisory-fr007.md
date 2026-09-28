Not blocking: 1 new issue

**Secret access widened to the whole project**
`google_project_iam_member.database_url_accessor` · infra/main.tf:2 · medium · elevation of privilege

fray-api can now read every secret in the project, including secrets created later. Before
this change it could read only the 1 secret it uses.

Fix: grant `roles/secretmanager.secretAccessor` on each secret with
`google_secret_manager_secret_iam_member`, not on the project.

<details><summary>Accept this risk instead</summary>

```yaml
schema_version: mitigation/v1
entries:
  - rule_id: FR-007
    address: "google_secret_manager_secret.database_url -> fray-api credentials"
    status: accepted
    reason: "<why this risk is acceptable>"
```
</details>

Nothing else changed (0 findings unchanged). Rules: FR-007
