package client

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fluong/fray/schema/validate"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// TestEveryFixtureDFDValidatesAgainstSchema marshals DFDs produced from the
// major plan/fixture shapes and validates them against the embedded DFD
// schema. Failures report the JSON pointer (same shape as the hosted 400).
func TestEveryFixtureDFDValidatesAgainstSchema(t *testing.T) {
	rootSchema, err := os.ReadFile(filepath.Join("..", "schema", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	embedSchema, err := os.ReadFile(filepath.Join("..", "schema", "validate", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rootSchema, embedSchema) {
		t.Fatal("schema/dfd.schema.json and schema/validate/dfd.schema.json must be byte-identical")
	}

	schema, err := validate.CompileDFD()
	if err != nil {
		t.Fatal(err)
	}

	cfg := []byte("schema_version: fray-config/v1\n")
	src := func(repo string) Source {
		return Source{Repo: repo, Commit: "abcdef1234567", Tool: "terraform", Fidelity: "plan"}
	}

	cases := []struct {
		name string
		doc  func(t *testing.T) DFD
	}{
		{
			name: "aws-plan.json",
			doc: func(t *testing.T) DFD {
				t.Helper()
				plan, err := os.ReadFile(filepath.Join("testdata", "aws-plan.json"))
				if err != nil {
					t.Fatal(err)
				}
				doc, _, err := Parse(plan, cfg, "fray.yaml", src("example/aws-web-app"), filepath.Join("..", "testdata", "aws-web-app"))
				if err != nil {
					t.Fatal(err)
				}
				return doc
			},
		},
		{
			name: "bedrock_lambda_iam_service",
			doc: func(t *testing.T) DFD {
				t.Helper()
				plan := bedrockLambdaPlan(t, bedrockIAMOpts{
					resources: []string{"arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"},
				})
				doc, _, err := Parse([]byte(plan), cfg, "fray.yaml", src("probe/bedrock"), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				return doc
			},
		},
		{
			name: "ec2_instance_fr034",
			doc: func(t *testing.T) DFD {
				t.Helper()
				doc, _, err := Parse(instancePlanJSON(t, true, true), cfg, "fray.yaml", src("probe/ec2"), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				return doc
			},
		},
		{
			name: "asg_launch_template",
			doc: func(t *testing.T) DFD {
				t.Helper()
				doc, _, err := Parse(asgNoLeakPlanJSON(t), cfg, "fray.yaml", src("probe/asg"), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				return doc
			},
		},
		{
			name: "eks_node_group",
			doc: func(t *testing.T) DFD {
				t.Helper()
				doc, _, err := Parse(ngNoLeakPlanJSON(t), cfg, "fray.yaml", src("probe/eks"), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				return doc
			},
		},
		{
			name: "inline_iam_jsonencode",
			doc: func(t *testing.T) DFD {
				t.Helper()
				doc, _, err := Parse([]byte(inlineIAMNoLeakPlan(t)), cfg, "fray.yaml", src("probe/inline-iam"), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				return doc
			},
		},
		{
			name: "api_gateway_http_none",
			doc: func(t *testing.T) DFD {
				t.Helper()
				plan := httpPlan(t, httpOpts{routes: []string{"NONE"}})
				doc, _, err := Parse([]byte(plan), cfg, "fray.yaml", src("probe/apigw"), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				return doc
			},
		},
		{
			name: "api_gateway_rest_lambda",
			doc: func(t *testing.T) DFD {
				t.Helper()
				plan := restPlan(t, restOpts{
					types: []string{"REGIONAL"}, stage: true,
					methods: []string{"NONE"}, lambdaInteg: true,
				})
				doc, _, err := Parse([]byte(plan), cfg, "fray.yaml", src("probe/apigw-rest"), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				return doc
			},
		},
		{
			name: "coverage_cache_plan",
			doc: func(t *testing.T) DFD {
				t.Helper()
				plan, err := os.ReadFile(filepath.Join("testdata", "coverage-cache-plan.json"))
				if err != nil {
					t.Fatal(err)
				}
				doc, _, err := Parse(plan, cfg, "fray.yaml", src("probe/coverage-cache"), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				return doc
			},
		},
		{
			name: "coverage_db_control_plan",
			doc: func(t *testing.T) DFD {
				t.Helper()
				plan, err := os.ReadFile(filepath.Join("testdata", "coverage-db-control-plan.json"))
				if err != nil {
					t.Fatal(err)
				}
				doc, _, err := Parse(plan, cfg, "fray.yaml", src("probe/coverage-db-control"), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				return doc
			},
		},
		{
			name: "coverage_lambda_s3_plan",
			doc: func(t *testing.T) DFD {
				t.Helper()
				plan, err := os.ReadFile(filepath.Join("testdata", "coverage-lambda-s3-plan.json"))
				if err != nil {
					t.Fatal(err)
				}
				doc, _, err := Parse(plan, cfg, "fray.yaml", src("probe/coverage-lambda-s3"), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				return doc
			},
		},
		{
			name: "coverage_b72_plan",
			doc: func(t *testing.T) DFD {
				t.Helper()
				plan, err := os.ReadFile(filepath.Join("testdata", "coverage-b72-plan.json"))
				if err != nil {
					t.Fatal(err)
				}
				doc, _, err := Parse(plan, cfg, "fray.yaml", src("probe/coverage-b72"), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				return doc
			},
		},
		{
			name: "coverage_b73_plan",
			doc: func(t *testing.T) DFD {
				t.Helper()
				plan, err := os.ReadFile(filepath.Join("testdata", "coverage-b73-plan.json"))
				if err != nil {
					t.Fatal(err)
				}
				doc, _, err := Parse(plan, cfg, "fray.yaml", src("probe/coverage-b73"), filepath.Join("testdata", "b73_hcl"))
				if err != nil {
					t.Fatal(err)
				}
				return doc
			},
		},
		{
			name: "coverage_db_worker_plan",
			doc: func(t *testing.T) DFD {
				t.Helper()
				plan, err := os.ReadFile(filepath.Join("testdata", "coverage-db-worker-plan.json"))
				if err != nil {
					t.Fatal(err)
				}
				doc, _, err := Parse(plan, cfg, "fray.yaml", src("probe/coverage-db-worker"), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				return doc
			},
		},
		{
			name: "coverage_cache_serverless_plan",
			doc: func(t *testing.T) DFD {
				t.Helper()
				plan, err := os.ReadFile(filepath.Join("testdata", "coverage-cache-serverless-plan.json"))
				if err != nil {
					t.Fatal(err)
				}
				doc, _, err := Parse(plan, cfg, "fray.yaml", src("probe/coverage-cache-serverless"), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				return doc
			},
		},
		{
			name: "gcp_cloud_run_secret_r2",
			doc: func(t *testing.T) DFD {
				t.Helper()
				plan := []byte(`{
				  "resource_changes": [
				    {"address":"google_cloud_run_v2_service.api","mode":"managed","type":"google_cloud_run_v2_service","change":{"after":{
				      "name":"api","location":"europe-west1",
				      "template":[{"service_account":"api@example.iam.gserviceaccount.com","containers":[{"image":"example","env":[
				        {"name":"R2_ACCESS_KEY_ID","value_source":[{"secret_key_ref":[{"secret":"r2-key"}]}]}
				      ]}]}]
				    }}},
				    {"address":"google_secret_manager_secret.r2","mode":"managed","type":"google_secret_manager_secret","change":{"after":{"secret_id":"r2-key","rotation":[]}}},
				    {"address":"cloudflare_r2_bucket.archive","mode":"managed","type":"cloudflare_r2_bucket","change":{"after":{"name":"archive"}}}
				  ]
				}`)
				doc, _, err := Parse(plan, cfg, "fray.yaml", src("probe/gcp"), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				return doc
			},
		},
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := tc.doc(t)
			if len(doc.Elements) == 0 {
				t.Skip("parser produced no elements")
			}
			assertDFDValidates(t, schema, doc, "plain")
			redacted, _, err := Redact(doc, key)
			if err != nil {
				t.Fatal(err)
			}
			assertDFDValidates(t, schema, redacted, "redacted")
		})
	}

	// Client-emitted golden DFDs (skip empty diagrams: those cases produce no DFD).
	_ = filepath.WalkDir(filepath.Join("testdata", "golden"), func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		if !strings.HasSuffix(path, ".dfd.json") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			return nil
		}
		if !bytes.Contains(raw, []byte(`"dfd/v1"`)) {
			return nil
		}
		// Empty elements = parser deliberately produced no diagram.
		if bytes.Contains(raw, []byte(`"elements": []`)) || bytes.Contains(raw, []byte("\"elements\":[]")) {
			return nil
		}
		rel := path
		if r, err := filepath.Rel("testdata", path); err == nil {
			rel = r
		}
		t.Run("golden/"+rel, func(t *testing.T) {
			if err := validate.DFD(schema, raw); err != nil {
				_, pointer := validate.LogSafe(err)
				t.Fatalf("golden DFD invalid: pointer=%s err=%v", pointer, err)
			}
		})
		return nil
	})
}

func assertDFDValidates(t *testing.T, schema *jsonschema.Schema, doc DFD, label string) {
	t.Helper()
	raw, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate.DFD(schema, raw); err != nil {
		_, pointer := validate.LogSafe(err)
		t.Fatalf("%s DFD schema validation failed: pointer=%s err=%v", label, pointer, err)
	}
}
