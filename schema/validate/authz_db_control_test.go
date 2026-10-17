package validate_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/fluong/fray/schema/validate"
)

func minimalDBControlFlow(flow map[string]any) []byte {
	from := map[string]any{
		"id": "e250e091b0d65d04f", "name": "app", "type": "process",
		"kind": "container_service", "provenance": "iac", "provider": "aws",
		"evidence": map[string]any{"addresses": []string{"aws_ecs_service.app"}},
	}
	to := map[string]any{
		"id": "e9468970500753318", "name": "db", "type": "datastore",
		"kind": "relational_db", "provenance": "iac", "provider": "aws",
		"evidence": map[string]any{"addresses": []string{"aws_db_instance.main"}},
	}
	doc := map[string]any{
		"schema_version": "dfd/v1",
		"source": map[string]any{
			"repo": "example/db-control", "commit": "0000000000000000000000000000000000000001",
			"iac_tool": "terraform", "fidelity": "static",
		},
		"elements":         []any{from, to},
		"trust_boundaries": []any{},
		"flows":            []any{flow},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestAuthzDBControlFlowSchema(t *testing.T) {
	schema, err := validate.Compile(filepath.Join("..", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}

	base := map[string]any{
		"id": "f3333333333333333", "from": "e250e091b0d65d04f", "to": "e9468970500753318",
		"data_class": "unknown", "transport": "tls", "boundaries": []any{},
	}

	t.Run("valid_resource_scope", func(t *testing.T) {
		flow := map[string]any{}
		for k, v := range base {
			flow[k] = v
		}
		flow["authz_db_control_classes"] = []any{"delete"}
		flow["authz_db_control_scope"] = "resource"
		if err := validate.DFD(schema, minimalDBControlFlow(flow)); err != nil {
			t.Fatalf("want valid: %v", err)
		}
	})

	t.Run("valid_all_classes", func(t *testing.T) {
		flow := map[string]any{}
		for k, v := range base {
			flow[k] = v
		}
		flow["authz_db_control_classes"] = []any{
			"reset_credentials", "snapshot_exfiltrate", "restore_clone", "delete",
		}
		flow["authz_db_control_scope"] = "account"
		if err := validate.DFD(schema, minimalDBControlFlow(flow)); err != nil {
			t.Fatalf("want valid: %v", err)
		}
	})

	t.Run("empty_classes_rejected", func(t *testing.T) {
		flow := map[string]any{}
		for k, v := range base {
			flow[k] = v
		}
		flow["authz_db_control_classes"] = []any{}
		flow["authz_db_control_scope"] = "account"
		if err := validate.DFD(schema, minimalDBControlFlow(flow)); err == nil {
			t.Fatal("want rejection for empty authz_db_control_classes")
		}
	})

	t.Run("unknown_class_rejected", func(t *testing.T) {
		flow := map[string]any{}
		for k, v := range base {
			flow[k] = v
		}
		flow["authz_db_control_classes"] = []any{"admin_wildcard"}
		flow["authz_db_control_scope"] = "account"
		if err := validate.DFD(schema, minimalDBControlFlow(flow)); err == nil {
			t.Fatal("want rejection for unknown class")
		}
	})

	t.Run("bad_scope_rejected", func(t *testing.T) {
		flow := map[string]any{}
		for k, v := range base {
			flow[k] = v
		}
		flow["authz_db_control_classes"] = []any{"delete"}
		flow["authz_db_control_scope"] = "project"
		if err := validate.DFD(schema, minimalDBControlFlow(flow)); err == nil {
			t.Fatal("want rejection for bad authz_db_control_scope")
		}
	})
}
