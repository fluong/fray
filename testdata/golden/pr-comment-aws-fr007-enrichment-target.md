Not blocking: 1 new issue

**Secret access widened to the whole account**
`module.ecs_service` · `task_exec_iam_statements` · aws-web-app/main.tf:112 · medium · elevation of privilege

ecs_service can now read every secret in the account, including secrets created later.
Before this change it could read only the 1 secret it uses.

Why this matters here: A secret-scoped grant from ecs_service to db_password secret
already exists, so the account-wide grant is redundant.

Fix: Scope GetSecretValue in `task_exec_iam_statements` to the secret ARN in Resource, not
"*".

<details><summary>Accept this risk instead</summary>

Resource: `module.ecs_service.data.aws_iam_policy_document.execution[0]`

```yaml
schema_version: mitigation/v1
entries:
  - rule_id: FR-007
    address: "module.db_password.aws_secretsmanager_secret.this[0] -> module.ecs_service.aws_ecs_service.this[0] credentials"
    status: accepted
    reason: "<why this risk is acceptable>"
```
</details>

Nothing else changed (14 findings unchanged). Rules: FR-007
