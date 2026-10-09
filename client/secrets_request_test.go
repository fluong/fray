package client_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
)

// Sentinels planted in sensitive-marked plan attributes.
const (
	senDBPassword   = "SEN_DB_PASSWORD_9f3a2c1b"
	senSecretString = "SEN_SECRET_STRING_7e4d8a0f"
	senRandomResult = "SEN_RANDOM_PASSWORD_RESULT_1c2b3a"
	senIAMSecret    = "SEN_IAM_ACCESS_KEY_SECRET_5d6e7f"
	senNonSensitive = "KEEP_PUBLIC_FALSE_MARKER"
)

// TestNoSecretsInScanRequest is the permanent regression for sensitive plan
// values: synthetic fixture + demo-shape plan, redaction on and off, all four
// sentinels must be absent from the serialized ScanRequest.
func TestNoSecretsInScanRequest(t *testing.T) {
	t.Run("synthetic", func(t *testing.T) {
		plan := []byte(sensitiveProbePlanJSON())
		cfg := []byte("schema_version: fray-config/v1\naudit_config: owned_by_this_root\n")
		src := client.Source{Repo: "probe/sensitive", Commit: "abcdef1234567", Tool: "terraform", Fidelity: "plan"}

		doc, _, err := client.Parse(plan, cfg, "fray.yaml", src, t.TempDir())
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		assertDBControlAttrs(t, doc)
		assertSentinelsAbsentInRequests(t, doc, "synthetic")
	})

	t.Run("demo_shape", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join("testdata", "aws-plan.json"))
		if err != nil {
			t.Fatal(err)
		}
		plan, err := injectDemoAWSSentinels(raw)
		if err != nil {
			t.Fatal(err)
		}
		cfg := []byte("schema_version: fray-config/v1\naudit_config: owned_by_this_root\n")
		doc, _, err := client.Parse(plan, cfg, "fray.yaml", client.Source{
			Repo: "fluong/fray", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan",
		}, filepath.Join("..", "testdata", "aws-web-app"))
		if err != nil {
			t.Fatalf("Parse demo plan: %v", err)
		}
		assertSentinelsAbsentInRequests(t, doc, "demo")
	})
}

// TestSensitiveMarkedValueNeverInParsedDFD asserts StripSensitive-before-Parse:
// a sensitive-marked after value must not appear anywhere in the marshaled DFD.
func TestSensitiveMarkedValueNeverInParsedDFD(t *testing.T) {
	const secret = "SUPER_SENSITIVE_PLAN_VALUE_never_in_dfd"
	plan := []byte(`{
	  "resource_changes": [
	    {
	      "address": "aws_db_instance.this",
	      "mode": "managed",
	      "type": "aws_db_instance",
	      "change": {
	        "after": {
	          "identifier": "app-db",
	          "password": "` + secret + `",
	          "publicly_accessible": false,
	          "storage_encrypted": true
	        },
	        "after_sensitive": {"password": true}
	      }
	    },
	    {
	      "address": "aws_secretsmanager_secret_version.this",
	      "mode": "managed",
	      "type": "aws_secretsmanager_secret_version",
	      "change": {
	        "after": {"secret_string": "` + secret + `"},
	        "after_sensitive": {"secret_string": true}
	      }
	    }
	  ]
	}`)
	doc, _, err := client.Parse(plan, []byte("schema_version: fray-config/v1\n"), "fray.yaml",
		client.Source{Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := client.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("sensitive-marked plan value appeared in parsed DFD")
	}
}

func assertDBControlAttrs(t *testing.T, doc client.DFD) {
	t.Helper()
	var db *client.Element
	for i := range doc.Elements {
		if doc.Elements[i].Kind == "relational_db" {
			db = &doc.Elements[i]
			break
		}
	}
	if db == nil {
		t.Fatal("expected relational_db element")
	}
	if db.Attributes["public"] != false {
		t.Fatalf("control attr public: got %#v want false", db.Attributes["public"])
	}
	if db.Attributes["encrypted_at_rest"] != true {
		t.Fatalf("control attr encrypted_at_rest: got %#v want true", db.Attributes["encrypted_at_rest"])
	}
}

func assertSentinelsAbsentInRequests(t *testing.T, doc client.DFD, label string) {
	t.Helper()
	sentinels := []struct{ name, val string }{
		{"aws_db_instance.password", senDBPassword},
		{"aws_secretsmanager_secret_version.secret_string", senSecretString},
		{"random_password.result", senRandomResult},
		{"aws_iam_access_key.secret", senIAMSecret},
	}
	key := mustSecretsKey(t)
	for _, mode := range []struct {
		name   string
		redact bool
	}{
		{label + "_redaction_on", true},
		{label + "_redaction_off", false},
	} {
		t.Run(mode.name, func(t *testing.T) {
			body := buildScanRequestBody(t, doc, key, mode.redact)
			for _, s := range sentinels {
				if bytes.Contains(body, []byte(s.val)) {
					t.Errorf("FAIL: sentinel %s (%q) PRESENT in ScanRequest", s.name, s.val)
				}
			}
		})
	}
}

func buildScanRequestBody(t *testing.T, doc client.DFD, key []byte, redact bool) []byte {
	t.Helper()
	wire := doc
	var idMap client.IDMap
	repo := doc.Source.Repo
	if redact {
		var err error
		wire, idMap, err = client.Redact(doc, key)
		if err != nil {
			t.Fatal(err)
		}
		repo = wire.Source.Repo
	}
	rawDFD, err := client.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(apiv1.ScanRequest{
		DFD:             rawDFD,
		Repo:            repo,
		Commit:          "abcdef1234567",
		IsDefaultBranch: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if redact {
		if err := client.AssertNoPlaintext(body, idMap.Plaintext); err != nil {
			t.Fatalf("AssertNoPlaintext: %v", err)
		}
	}
	return body
}

func mustSecretsKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func injectDemoAWSSentinels(raw []byte) ([]byte, error) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	changes, _ := root["resource_changes"].([]any)
	for _, rawRC := range changes {
		rc, ok := rawRC.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := rc["type"].(string)
		addr, _ := rc["address"].(string)
		ch, _ := rc["change"].(map[string]any)
		if ch == nil {
			continue
		}
		after, _ := ch["after"].(map[string]any)
		if after == nil {
			after = map[string]any{}
			ch["after"] = after
		}
		switch {
		case typ == "aws_db_instance":
			after["password"] = senDBPassword
		case typ == "aws_secretsmanager_secret_version":
			after["secret_string"] = senSecretString
		case typ == "random_password" && addr == "random_password.db":
			after["result"] = senRandomResult
			after["bcrypt_hash"] = senRandomResult
		}
	}
	changes = append(changes, map[string]any{
		"address": "aws_iam_access_key.probe",
		"mode":    "managed",
		"type":    "aws_iam_access_key",
		"change": map[string]any{
			"after": map[string]any{
				"id": "AKIAEXAMPLE", "user": "probe", "status": "Active", "secret": senIAMSecret,
			},
			"after_sensitive": map[string]any{"secret": true, "ses_smtp_password_v4": true},
		},
	})
	root["resource_changes"] = changes
	return json.Marshal(root)
}

func sensitiveProbePlanJSON() string {
	containerDefsBytes, _ := json.Marshal([]map[string]any{{
		"name":  "web",
		"image": "example.com/app:1.0",
		"secrets": []map[string]any{{
			"name": "DB_PASSWORD", "valueFrom": "arn:aws:secretsmanager:us-east-1:123:secret:db-password",
		}},
		"environment": []map[string]any{{
			"name": "LEAK_PROBE", "value": senRandomResult,
		}},
	}})
	containerDefsJSON, _ := json.Marshal(string(containerDefsBytes))
	return `{
  "resource_changes": [
    {
      "address": "random_password.db",
      "mode": "managed",
      "type": "random_password",
      "change": {
        "after": {"result": "` + senRandomResult + `", "length": 32},
        "after_sensitive": {"result": true, "bcrypt_hash": true}
      }
    },
    {
      "address": "module.db_password.aws_secretsmanager_secret.this[0]",
      "mode": "managed",
      "type": "aws_secretsmanager_secret",
      "change": {
        "after": {"name": "app/db-password", "recovery_window_in_days": 7},
        "after_sensitive": {}
      }
    },
    {
      "address": "module.db_password.aws_secretsmanager_secret_version.this[0]",
      "mode": "managed",
      "type": "aws_secretsmanager_secret_version",
      "change": {
        "after": {
          "secret_id": "module.db_password.aws_secretsmanager_secret.this[0]",
          "secret_string": "` + senSecretString + `"
        },
        "after_sensitive": {"secret_string": true, "secret_binary": true}
      }
    },
    {
      "address": "module.db.aws_db_instance.this[0]",
      "mode": "managed",
      "type": "aws_db_instance",
      "change": {
        "after": {
          "identifier": "probe-db",
          "db_name": "app",
          "password": "` + senDBPassword + `",
          "publicly_accessible": false,
          "storage_encrypted": true,
          "deletion_protection": true
        },
        "after_sensitive": {"password": true, "password_wo": true}
      }
    },
    {
      "address": "aws_iam_access_key.ci",
      "mode": "managed",
      "type": "aws_iam_access_key",
      "change": {
        "after": {"id": "AKIAEXAMPLE", "user": "ci", "status": "Active", "secret": "` + senIAMSecret + `"},
        "after_sensitive": {"secret": true, "ses_smtp_password_v4": true}
      }
    },
    {
      "address": "module.uploads.aws_s3_bucket.this[0]",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "change": {
        "after": {"bucket": "` + senNonSensitive + `"},
        "after_sensitive": {}
      }
    },
    {
      "address": "module.ecs_service.aws_ecs_service.this[0]",
      "mode": "managed",
      "type": "aws_ecs_service",
      "change": {"after": {"name": "probe-svc"}, "after_sensitive": {}}
    },
    {
      "address": "module.ecs_service.aws_ecs_task_definition.this[0]",
      "mode": "managed",
      "type": "aws_ecs_task_definition",
      "change": {
        "after": {"family": "probe", "container_definitions": ` + string(containerDefsJSON) + `},
        "after_sensitive": {}
      }
    },
    {
      "address": "module.alb.aws_lb.this[0]",
      "mode": "managed",
      "type": "aws_lb",
      "change": {"after": {"name": "probe-alb", "internal": true}, "after_sensitive": {}}
    }
  ],
  "configuration": {
    "root_module": {
      "module_calls": {
        "db_password": {
          "expressions": {
            "secret_string": {"references": ["random_password.db.result", "random_password.db"]}
          },
          "module": {
            "resources": [
              {"address":"aws_secretsmanager_secret.this[0]","type":"aws_secretsmanager_secret","name":"this","mode":"managed","expressions":{"name":{"constant_value":"app/db-password"}}},
              {"address":"aws_secretsmanager_secret_version.this[0]","type":"aws_secretsmanager_secret_version","name":"this","mode":"managed","expressions":{"secret_string":{"references":["var.secret_string"]}}}
            ]
          }
        },
        "db": {
          "module": {
            "resources": [
              {"address":"aws_db_instance.this[0]","type":"aws_db_instance","name":"this","mode":"managed","expressions":{"password":{"references":["var.password"]},"publicly_accessible":{"constant_value":false},"storage_encrypted":{"constant_value":true}}}
            ]
          }
        },
        "ecs_service": {
          "module": {
            "resources": [
              {"address":"aws_ecs_service.this[0]","type":"aws_ecs_service","name":"this","mode":"managed","expressions":{}},
              {"address":"aws_ecs_task_definition.this[0]","type":"aws_ecs_task_definition","name":"this","mode":"managed","expressions":{}}
            ]
          }
        },
        "uploads": {
          "module": {
            "resources": [
              {"address":"aws_s3_bucket.this[0]","type":"aws_s3_bucket","name":"this","mode":"managed","expressions":{"bucket":{"constant_value":"` + senNonSensitive + `"}}}
            ]
          }
        },
        "alb": {
          "module": {
            "resources": [
              {"address":"aws_lb.this[0]","type":"aws_lb","name":"this","mode":"managed","expressions":{"internal":{"constant_value":true}}}
            ]
          }
        }
      },
      "resources": [
        {"address":"random_password.db","type":"random_password","name":"db","mode":"managed","expressions":{}},
        {"address":"aws_iam_access_key.ci","type":"aws_iam_access_key","name":"ci","mode":"managed","expressions":{}}
      ]
    }
  },
  "planned_values": {
    "root_module": {
      "resources": [
        {"address":"random_password.db","type":"random_password","values":{"result":"` + senRandomResult + `"},"sensitive_values":{"result":true}}
      ]
    }
  }
}`
}
