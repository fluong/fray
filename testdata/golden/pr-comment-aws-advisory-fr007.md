Not blocking: 1 new issue

**Secret access widened to the whole project**
`module.ecs_service.data.aws_iam_policy_document.execution[0]` · module.ecs_service.data.aws_iam_policy_document.execution[0] · medium · elevation of privilege

fray-aws-web-app can now read every secret the role can reach, including secrets created
later. Before this change it could read only the 1 secrets it uses.

Fix: scope `GetSecretValue` to the secret ARN in `Resource`, not `"*"`.

<details><summary>Accept this risk instead</summary>

```yaml
schema_version: mitigation/v1
entries:
  - rule_id: FR-007
    address: "module.db_password.aws_secretsmanager_secret.this[0] -> module.ecs_service.aws_ecs_service.this[0] credentials"
    status: accepted
    reason: reason
```
</details>

Nothing else changed (14 findings unchanged). Rules: FR-007
