package client

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestStripRemovesSensitiveValues(t *testing.T) {
	plan := []byte(`{
	  "resource_changes": [{
	    "change": {
	      "after": {"name": "kept", "secret_data": "super-secret-value", "note": "prefix super-secret-value suffix"},
	      "after_sensitive": {"name": false, "secret_data": true, "note": false}
	    }
	  }],
	  "planned_values": {"root_module": {"resources": [{"values": {"secret_data": "super-secret-value"}, "sensitive_values": {"secret_data": false}}]}}
	}`)
	out, secrets, err := StripSensitive(plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 || secrets[0] != "super-secret-value" {
		t.Fatalf("collected %#v", secrets)
	}
	if bytes.Contains(out, []byte("super-secret-value")) {
		t.Fatal("sensitive value remains")
	}
	if !bytes.Contains(out, []byte("kept")) {
		t.Fatal("unrelated value was removed")
	}
}

func TestFixtureHasNoSensitiveLeaf(t *testing.T) {
	orig := os.Getenv("FRAY_PLAN")
	if orig != "" && os.Getenv("FRAY_WRITE_FIXTURE") == "1" {
		raw, err := os.ReadFile(orig)
		if err != nil {
			t.Fatal(err)
		}
		stripped, secrets, err := StripSensitive(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("testdata/aws-plan.json", stripped, 0o644); err != nil {
			t.Fatal(err)
		}
		assertSecretsGone(t, stripped, secrets)
	}
	fixture, err := os.ReadFile("testdata/aws-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(fixture, []byte("postgres://")) {
		t.Fatal("fixture contains a database url")
	}
	if leftover := nonemptySensitive(fixture); leftover != "" {
		t.Fatal(leftover)
	}
	if orig == "" {
		return
	}
	raw, err := os.ReadFile(orig)
	if err != nil {
		t.Fatal(err)
	}
	stripped, secrets, err := StripSensitive(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stripped, fixture) {
		t.Fatal("committed fixture is not the stripped plan")
	}
	assertSecretsGone(t, fixture, secrets)
}

func nonemptySensitive(fixture []byte) string {
	var root any
	if err := json.Unmarshal(fixture, &root); err != nil {
		return err.Error()
	}
	var problem string
	var scan func(any)
	scan = func(node any) {
		m, ok := node.(map[string]any)
		if !ok {
			if list, ok := node.([]any); ok {
				for _, v := range list {
					scan(v)
				}
			}
			return
		}
		for _, pair := range [][2]string{{"after", "after_sensitive"}, {"before", "before_sensitive"}, {"values", "sensitive_values"}} {
			if mark, ok := m[pair[1]]; ok {
				if val, ok := m[pair[0]]; ok && markedNonempty(val, mark) {
					problem = "sensitive-marked " + pair[0] + " is not empty"
				}
			}
		}
		if m["sensitive"] == true {
			if s, ok := m["value"].(string); ok && s != "" {
				problem = "sensitive variable value is not empty"
			}
		}
		for _, v := range m {
			scan(v)
		}
	}
	scan(root)
	return problem
}

func markedNonempty(val, mark any) bool {
	if mark == true {
		s, ok := val.(string)
		return ok && s != ""
	}
	switch m := mark.(type) {
	case map[string]any:
		vm, ok := val.(map[string]any)
		if !ok {
			return false
		}
		for k, mv := range m {
			if markedNonempty(vm[k], mv) {
				return true
			}
		}
	case []any:
		vs, ok := val.([]any)
		if !ok {
			return false
		}
		for i, mv := range m {
			if i < len(vs) && markedNonempty(vs[i], mv) {
				return true
			}
		}
	}
	return false
}

func assertSecretsGone(t *testing.T, fixture []byte, secrets []string) {
	t.Helper()
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if bytes.Contains(fixture, []byte(secret)) {
			t.Fatalf("fixture contains a sensitive value of length %d", len(secret))
		}
		if strings.Contains(secret, "://") || len(secret) > 16 {
			t.Fatalf("plan marked a sensitive value of length %d", len(secret))
		}
	}
}
