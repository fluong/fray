package client

import (
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func TestB08LambdaRDSMatchesECSAuthz(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["rds-db:connect"],"Resource":["arn:aws:rds-db:us-east-1:111122223333:dbuser:db-ABCDEF/app"]}]}`
	ecsDoc := parseB08Plan(t, dbAuthzECSPlan(t, policy, false))
	lambdaDoc := parseB08Plan(t, lambdaIAMRDSPlan(t, policy))
	ecsFlow := firstFlowToKind(ecsDoc, "relational_db")
	lambdaFlow := firstFlowToKind(lambdaDoc, "relational_db")
	if ecsFlow == nil || lambdaFlow == nil {
		t.Fatal("missing relational_db flow")
	}
	if ecsFlow.AuthzScope != lambdaFlow.AuthzScope ||
		strings.Join(ecsFlow.AuthzGrants, ",") != strings.Join(lambdaFlow.AuthzGrants, ",") ||
		ecsFlow.Transport != lambdaFlow.Transport ||
		ecsFlow.DataClass != lambdaFlow.DataClass {
		t.Fatalf("ecs=%+v lambda=%+v", ecsFlow, lambdaFlow)
	}
	if ecsFlow.Causes["authz_scope"] == "" || lambdaFlow.Causes["authz_scope"] == "" {
		t.Fatalf("expected authz_scope cause on both flows")
	}
}

func TestB08LambdaEnvSecretTable(t *testing.T) {
	secretARN := "arn:aws:secretsmanager:us-east-1:111122223333:secret:app/db-AbCdEf"
	foreignARN := "arn:aws:secretsmanager:us-east-1:444455556666:secret:other/db-XyZ123"
	cases := []struct {
		name       string
		env        map[string]string
		wantFlows  int
		wantDelEnv bool
		wantRef    bool
	}{
		{
			name:      "secret_arn",
			env:       map[string]string{"DB": secretARN},
			wantFlows: 1, wantRef: true,
		},
		{
			name:      "interpolated_secret",
			env:       map[string]string{"DB": "aws_secretsmanager_secret.db.arn"},
			wantFlows: 1, wantRef: true,
		},
		{
			name:      "material_version_ref",
			env:       map[string]string{"DB": "aws_secretsmanager_secret_version.v.secret_string"},
			wantFlows: 1, wantDelEnv: true,
		},
		{
			name:      "literal_secret_looking",
			env:       map[string]string{"DB": "SEN_RANDOM_PASSWORD_RESULT_1c2b3a"},
			wantFlows: 0,
		},
		{
			name:      "non_secret_literal",
			env:       map[string]string{"DB": "postgres://example.com"},
			wantFlows: 0,
		},
		{
			name:      "foreign_account_arn",
			env:       map[string]string{"DB": foreignARN},
			wantFlows: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := parseB08Plan(t, lambdaEnvSecretPlan(t, tc.env, false))
			var secretFlows []Flow
			for _, f := range doc.Flows {
				if flowTouchesSecretStore(doc, f) {
					secretFlows = append(secretFlows, f)
				}
			}
			if len(secretFlows) != tc.wantFlows {
				t.Fatalf("flows=%d want %d", len(secretFlows), tc.wantFlows)
			}
			if tc.wantFlows == 0 {
				return
			}
			f := secretFlows[0]
			if tc.wantRef && f.SecretDelivery != "" {
				t.Fatalf("reference flow must omit secret_delivery, got %q", f.SecretDelivery)
			}
			if tc.wantDelEnv && f.SecretDelivery != "env" {
				t.Fatalf("material flow delivery=%q want env", f.SecretDelivery)
			}
		})
	}
}

func TestB08LambdaEnvUnknownOmits(t *testing.T) {
	doc := parseB08Plan(t, lambdaEnvSecretPlan(t, map[string]string{"DB": "x"}, true))
	if n := countSecretStoreFlows(doc); n != 0 {
		t.Fatalf("unknown environment: flows=%d want 0", n)
	}
}

func TestB08DedupeTwoEnvVarsSameSecret(t *testing.T) {
	secretARN := "arn:aws:secretsmanager:us-east-1:111122223333:secret:app/db-AbCdEf"
	doc := parseB08Plan(t, lambdaEnvSecretPlan(t, map[string]string{
		"A": secretARN,
		"B": secretARN,
	}, false))
	if n := countSecretStoreFlows(doc); n != 1 {
		t.Fatalf("dedupe flows=%d want 1", n)
	}
}

func TestB08RedactedFlowWireKeys(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["rds-db:connect"],"Resource":["*"]}]}`
	doc := parseB08Plan(t, lambdaIAMRDSPlan(t, policy))
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	red, _, err := Redact(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(red)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "111122223333") {
		t.Fatal("redacted doc leaked account id")
	}
	if err := AssertNoPlaintext(raw, nil); err != nil {
		t.Fatal(err)
	}
}

func parseB08Plan(t *testing.T, plan string) DFD {
	t.Helper()
	doc, _, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "fray.yaml",
		Source{Repo: "example/demo", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func firstFlowToKind(doc DFD, kind string) *Flow {
	for i := range doc.Flows {
		f := &doc.Flows[i]
		for _, el := range doc.Elements {
			if el.ID == f.To && el.Kind == kind {
				return f
			}
		}
	}
	return nil
}

func flowTouchesSecretStore(doc DFD, f Flow) bool {
	for _, el := range doc.Elements {
		if el.Kind == "secret_store" && (el.ID == f.From || el.ID == f.To) {
			return true
		}
	}
	return false
}

func countSecretStoreFlows(doc DFD) int {
	n := 0
	for _, f := range doc.Flows {
		if flowTouchesSecretStore(doc, f) {
			n++
		}
	}
	return n
}

func lambdaIAMRDSPlan(t *testing.T, policyJSON string) string {
	t.Helper()
	resources := []map[string]any{
		{
			"address": "aws_lambda_function.app", "mode": "managed", "type": "aws_lambda_function", "name": "app",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"function_name": "app",
				"role":          "arn:aws:iam::111122223333:role/app",
			}},
		},
		{
			"address": "aws_iam_role.app", "mode": "managed", "type": "aws_iam_role", "name": "app",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
		},
		{
			"address": "aws_iam_role_policy.db", "mode": "managed", "type": "aws_iam_role_policy", "name": "db",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"name": "db-access", "policy": policyJSON,
			}},
		},
		{
			"address": "aws_db_instance.main", "mode": "managed", "type": "aws_db_instance", "name": "main",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"identifier": "main", "resource_id": "db-ABCDEF", "engine": "postgres",
			}},
		},
	}
	cfg := []map[string]any{
		{
			"address": "aws_lambda_function.app", "type": "aws_lambda_function", "name": "app",
			"expressions": map[string]any{
				"role": map[string]any{"references": []any{"aws_iam_role.app.arn", "aws_iam_role.app"}},
			},
		},
		{"address": "aws_iam_role.app", "type": "aws_iam_role", "name": "app", "expressions": map[string]any{}},
		{
			"address": "aws_iam_role_policy.db", "type": "aws_iam_role_policy", "name": "db",
			"expressions": map[string]any{
				"role":   map[string]any{"references": []any{"aws_iam_role.app.id", "aws_iam_role.app"}},
				"policy": map[string]any{"constant_value": policyJSON},
			},
		},
		{"address": "aws_db_instance.main", "type": "aws_db_instance", "name": "main", "expressions": map[string]any{}},
	}
	return marshalB08Plan(t, resources, cfg)
}

func lambdaEnvSecretPlan(t *testing.T, env map[string]string, envUnknown bool) string {
	t.Helper()
	secretARN := "arn:aws:secretsmanager:us-east-1:111122223333:secret:app/db-AbCdEf"
	execPol := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["secretsmanager:GetSecretValue"],"Resource":["` + secretARN + `"]}]}`
	envBlock := []any{map[string]any{"variables": env}}
	change := map[string]any{
		"actions": []any{"create"},
		"after": map[string]any{
			"function_name": "app",
			"role":          "arn:aws:iam::111122223333:role/app",
			"environment":   envBlock,
		},
	}
	if envUnknown {
		change["after_unknown"] = map[string]any{"environment": true}
		delete(change["after"].(map[string]any), "environment")
	}
	resources := []map[string]any{
		{
			"address": "aws_lambda_function.app", "mode": "managed", "type": "aws_lambda_function", "name": "app",
			"change": change,
		},
		{
			"address": "aws_iam_role.app", "mode": "managed", "type": "aws_iam_role", "name": "app",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
		},
		{
			"address": "aws_iam_role_policy.secrets", "mode": "managed", "type": "aws_iam_role_policy", "name": "secrets",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "secrets", "policy": execPol}},
		},
		{
			"address": "aws_secretsmanager_secret.db", "mode": "managed", "type": "aws_secretsmanager_secret", "name": "db",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app/db", "arn": secretARN}},
		},
		{
			"address": "aws_secretsmanager_secret_version.v", "mode": "managed", "type": "aws_secretsmanager_secret_version", "name": "v",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"secret_id": "aws_secretsmanager_secret.db", "secret_string": "placeholder",
			}},
		},
	}
	cfg := []map[string]any{
		{
			"address": "aws_lambda_function.app", "type": "aws_lambda_function", "name": "app",
			"expressions": map[string]any{
				"role": map[string]any{"references": []any{"aws_iam_role.app.arn", "aws_iam_role.app"}},
			},
		},
		{"address": "aws_iam_role.app", "type": "aws_iam_role", "name": "app", "expressions": map[string]any{}},
		{
			"address": "aws_iam_role_policy.secrets", "type": "aws_iam_role_policy", "name": "secrets",
			"expressions": map[string]any{
				"role":   map[string]any{"references": []any{"aws_iam_role.app.id", "aws_iam_role.app"}},
				"policy": map[string]any{"constant_value": execPol},
			},
		},
		{"address": "aws_secretsmanager_secret.db", "type": "aws_secretsmanager_secret", "name": "db", "expressions": map[string]any{}},
		{
			"address": "aws_secretsmanager_secret_version.v", "type": "aws_secretsmanager_secret_version", "name": "v",
			"expressions": map[string]any{
				"secret_id": map[string]any{"references": []any{"aws_secretsmanager_secret.db.id", "aws_secretsmanager_secret.db"}},
			},
		},
	}
	return marshalB08Plan(t, resources, cfg)
}

func marshalB08Plan(t *testing.T, resources, cfg []map[string]any) string {
	t.Helper()
	root := map[string]any{
		"format_version":   "1.2",
		"resource_changes": resources,
		"configuration":    map[string]any{"root_module": map[string]any{"resources": cfg}},
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
