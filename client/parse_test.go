package client

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAWSWebAppPlan(t *testing.T) {
	plan, err := os.ReadFile("testdata/aws-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, warnings, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "", Source{
		Repo:     "example/aws-web-app",
		Commit:   "4530a865f29ba14931379f361b177a992edeab51",
		Tool:     "terraform",
		Fidelity: "plan",
	}, filepath.Join("..", "testdata", "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) > 0 {
		t.Fatalf("warnings: %s", strings.Join(warnings, "\n"))
	}
	got, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join("..", "testdata", "golden", "aws-web-app-fixture.dfd.json")
	want, err := os.ReadFile(wantPath)
	if err != nil {
		_ = os.WriteFile("/tmp/aws-fixture.dfd.json", got, 0o644)
		t.Fatalf("dfd golden missing, wrote /tmp/aws-fixture.dfd.json")
	}
	if !bytes.Equal(got, want) {
		_ = os.WriteFile("/tmp/aws-fixture.dfd.json", got, 0o644)
		t.Fatalf("dfd mismatch, wrote /tmp/aws-fixture.dfd.json (%d bytes)", len(got))
	}
}

func TestFlowAnnotationKeepsIdentity(t *testing.T) {
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
	src := Source{Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}
	base, _, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "fray.yaml", src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var before Flow
	n := 0
	for _, f := range base.Flows {
		for _, el := range base.Elements {
			if el.ID == f.To && el.Kind == "object_storage" {
				before = f
				n++
			}
		}
	}
	if n != 1 {
		t.Fatalf("object-storage flows: %d", n)
	}
	if before.DataClass != "unknown" {
		t.Fatalf("parser class %q", before.DataClass)
	}

	annotated, _, err := Parse(plan, []byte(`schema_version: fray-config/v1
annotations:
  flows:
    - from: google_cloud_run_v2_service.api
      to: cloudflare_r2_bucket.archive
      data_class: customer_data
`), "fray.yaml", src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(annotated.Flows) != len(base.Flows) {
		t.Fatalf("flow count %d -> %d", len(base.Flows), len(annotated.Flows))
	}
	var after Flow
	for _, f := range annotated.Flows {
		for _, el := range annotated.Elements {
			if el.ID == f.To && el.Kind == "object_storage" {
				after = f
			}
		}
	}
	if after.ID != before.ID {
		t.Fatalf("id moved %s -> %s", before.ID, after.ID)
	}
	if after.DataClass != "customer_data" {
		t.Fatalf("annotated class %q", after.DataClass)
	}

	_, _, err = Parse(plan, []byte(`schema_version: fray-config/v1
annotations:
  flows:
    - from: cloudflare_r2_bucket.archive
      to: google_cloud_run_v2_service.api
      data_class: customer_data
`), "fray.yaml", src, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "matched no parser flow") {
		t.Fatalf("missing pair: %v", err)
	}
}

func TestProjectScopeCoversEverySecret(t *testing.T) {
	plan := []byte(`{
	  "resource_changes": [
	    {"address":"google_cloud_run_v2_service.api","mode":"managed","type":"google_cloud_run_v2_service","change":{"after":{
	      "name":"api","location":"europe-west1",
	      "template":[{"service_account":"api@example.iam.gserviceaccount.com","containers":[{"image":"example","env":[
	        {"name":"DATABASE_URL","value_source":[{"secret_key_ref":[{"secret":"fray-database-url"}]}]},
	        {"name":"OTHER_SECRET","value_source":[{"secret_key_ref":[{"secret":"other-secret"}]}]}
	      ]}]}]
	    }}},
	    {"address":"google_secret_manager_secret.database_url","mode":"managed","type":"google_secret_manager_secret","change":{"after":{"secret_id":"fray-database-url","rotation":[]}}},
	    {"address":"google_secret_manager_secret.other","mode":"managed","type":"google_secret_manager_secret","change":{"after":{"secret_id":"other-secret","rotation":[]}}},
	    {"address":"google_secret_manager_secret_iam_member.database_url","mode":"managed","type":"google_secret_manager_secret_iam_member","change":{"after":{"secret_id":"fray-database-url","role":"roles/secretmanager.secretAccessor","member":"serviceAccount:api@example.iam.gserviceaccount.com"}}},
	    {"address":"google_secret_manager_secret_iam_member.other","mode":"managed","type":"google_secret_manager_secret_iam_member","change":{"after":{"secret_id":"other-secret","role":"roles/secretmanager.secretAccessor","member":"serviceAccount:api@example.iam.gserviceaccount.com"}}},
	    {"address":"google_project_iam_member.database_url_accessor","mode":"managed","type":"google_project_iam_member","change":{"after":{"role":"roles/secretmanager.secretAccessor","member":"serviceAccount:api@example.iam.gserviceaccount.com"}}}
	  ]
	}`)
	doc, warnings, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "fray.yaml", Source{Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "ambiguous") {
			t.Fatal(w)
		}
	}
	n := 0
	for _, f := range doc.Flows {
		if f.DataClass != "credentials" || f.SecretDelivery != "env" {
			continue
		}
		n++
		if f.AuthzScope != "project" {
			t.Fatalf("scope %q, want project", f.AuthzScope)
		}
		if !slices.Equal(f.AuthzGrants, []string{"resource", "project"}) {
			t.Fatalf("grants %#v, want [resource project]", f.AuthzGrants)
		}
		if f.Causes["authz_scope"] != "google_project_iam_member.database_url_accessor" {
			t.Fatalf("cause %q", f.Causes["authz_scope"])
		}
	}
	if n != 2 {
		t.Fatalf("credential flows: %d", n)
	}
}

func TestCloudRunSecretDelivery(t *testing.T) {
	secretResources := `
	    {"address":"google_secret_manager_secret.app","mode":"managed","type":"google_secret_manager_secret","change":{"after":{"secret_id":"app-secret","rotation":[]}}},
	    {"address":"google_secret_manager_secret_iam_member.app","mode":"managed","type":"google_secret_manager_secret_iam_member","change":{"after":{"secret_id":"app-secret","role":"roles/secretmanager.secretAccessor","member":"serviceAccount:api@example.iam.gserviceaccount.com"}}}`
	cases := []struct {
		name       string
		template   string
		wantDeliv  string // "" = no credentials flow for app-secret
		wantFR003  string // mitigated | open | (none)
	}{
		{
			name: "volume-only → volume (FR-003 mitigated)",
			template: `[{
	        "volumes":[{"name":"secvol","secret":[{"secret":"app-secret","items":[{"path":"token","version":"latest"}]}]}],
	        "containers":[{"image":"gcr.io/x/y@sha256:abc","volume_mounts":[{"name":"secvol","mount_path":"/secrets"}]}]
	      }]`,
			wantDeliv: "volume", wantFR003: "mitigated",
		},
		{
			name: "env-only → env (FR-003 open)",
			template: `[{
	        "containers":[{"image":"gcr.io/x/y@sha256:abc",
	          "env":[{"name":"TOK","value_source":[{"secret_key_ref":[{"secret":"app-secret","version":"latest"}]}]}]}]
	      }]`,
			wantDeliv: "env", wantFR003: "open",
		},
		{
			name: "both mount and env → env (FR-003 open)",
			template: `[{
	        "volumes":[{"name":"secvol","secret":[{"secret":"app-secret","items":[{"path":"token","version":"latest"}]}]}],
	        "containers":[{"image":"gcr.io/x/y@sha256:abc","volume_mounts":[{"name":"secvol","mount_path":"/secrets"}],
	          "env":[{"name":"TOK","value_source":[{"secret_key_ref":[{"secret":"app-secret","version":"latest"}]}]}]}]
	      }]`,
			wantDeliv: "env", wantFR003: "open",
		},
		{
			name: "declared volume not mounted → no flow",
			template: `[{
	        "volumes":[{"name":"secvol","secret":[{"secret":"app-secret","items":[{"path":"token","version":"latest"}]}]}],
	        "containers":[{"image":"gcr.io/x/y@sha256:abc"}]
	      }]`,
			wantDeliv: "", wantFR003: "(none)",
		},
		{
			name: "two containers: one mounts, one env → env (FR-003 open)",
			template: `[{
	        "volumes":[{"name":"secvol","secret":[{"secret":"app-secret","items":[{"path":"token","version":"latest"}]}]}],
	        "containers":[
	          {"image":"gcr.io/x/y@sha256:abc","volume_mounts":[{"name":"secvol","mount_path":"/secrets"}]},
	          {"image":"gcr.io/x/y@sha256:def","env":[{"name":"TOK","value_source":[{"secret_key_ref":[{"secret":"app-secret","version":"latest"}]}]}]}
	        ]
	      }]`,
			wantDeliv: "env", wantFR003: "open",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := []byte(`{
	  "resource_changes": [
	    {"address":"google_cloud_run_v2_service.api","mode":"managed","type":"google_cloud_run_v2_service","change":{"after":{
	      "name":"api","location":"us-central1",
	      "template":` + tc.template + `
	    }}},` + secretResources + `
	  ]
	}`)
			doc, _, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "fray.yaml", Source{Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			var got string
			n := 0
			for _, f := range doc.Flows {
				if f.DataClass != "credentials" {
					continue
				}
				n++
				got = f.SecretDelivery
			}
			if tc.wantDeliv == "" {
				if n != 0 {
					t.Fatalf("want no credentials flow, got %d delivery=%q", n, got)
				}
				return
			}
			if n != 1 || got != tc.wantDeliv {
				t.Fatalf("got n=%d delivery=%q want 1 %q (FR-003 %s)", n, got, tc.wantDeliv, tc.wantFR003)
			}
		})
	}
}

func TestR2BucketLockSetsObjectLock(t *testing.T) {
	plan := []byte(`{
	  "resource_changes": [
	    {"address":"cloudflare_r2_bucket.archive","mode":"managed","type":"cloudflare_r2_bucket","change":{"after":{"name":"demo-archive"}}},
	    {"address":"cloudflare_r2_bucket_lock.archive","mode":"managed","type":"cloudflare_r2_bucket_lock","change":{"after":{
	      "bucket_name":"demo-archive",
	      "rules":[{"id":"all","enabled":true,"prefix":"","condition":{"type":"Indefinite"}}]
	    }}}
	  ]
	}`)
	doc, warnings, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "fray.yaml", Source{Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "cloudflare_r2_bucket_lock") {
			t.Fatalf("unexpected warning: %s", w)
		}
	}
	var bucket *Element
	for i := range doc.Elements {
		if doc.Elements[i].Kind == "object_storage" {
			bucket = &doc.Elements[i]
			break
		}
	}
	if bucket == nil {
		t.Fatal("no object_storage")
	}
	if bucket.Attributes["object_lock"] != true {
		t.Fatalf("object_lock=%#v want true", bucket.Attributes["object_lock"])
	}
	if bucket.Causes["object_lock"] != "cloudflare_r2_bucket_lock.archive" {
		t.Fatalf("cause=%q", bucket.Causes["object_lock"])
	}
}

func TestR2NoLockObjectLockFalse(t *testing.T) {
	plan := []byte(`{
	  "resource_changes": [
	    {"address":"cloudflare_r2_bucket.archive","mode":"managed","type":"cloudflare_r2_bucket","change":{"after":{"name":"demo-archive"}}}
	  ]
	}`)
	doc, _, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "fray.yaml", Source{Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var bucket *Element
	for i := range doc.Elements {
		if doc.Elements[i].Kind == "object_storage" {
			bucket = &doc.Elements[i]
			break
		}
	}
	if bucket == nil {
		t.Fatal("no object_storage")
	}
	if bucket.Attributes["object_lock"] != false {
		t.Fatalf("object_lock=%#v want false", bucket.Attributes["object_lock"])
	}
}

func TestR2DevDomainMakesBucketPublic(t *testing.T) {
	plan := []byte(`{
	  "resource_changes": [
	    {"address":"cloudflare_r2_bucket.archive","mode":"managed","type":"cloudflare_r2_bucket","change":{"after":{"name":"demo-archive"}}},
	    {"address":"cloudflare_r2_managed_domain.archive","mode":"managed","type":"cloudflare_r2_managed_domain","change":{"after":{"bucket_name":"demo-archive","enabled":true}}},
	    {"address":"cloudflare_r2_bucket_cors.archive","mode":"managed","type":"cloudflare_r2_bucket_cors","change":{"after":{"bucket_name":"demo-archive"}}}
	  ]
	}`)
	doc, warnings, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "fray.yaml", Source{Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "cloudflare_r2_managed_domain") {
			t.Fatal(w)
		}
	}
	var bucket *Element
	for i := range doc.Elements {
		if doc.Elements[i].Name == "demo-archive" {
			bucket = &doc.Elements[i]
		}
	}
	if bucket == nil {
		t.Fatal("missing bucket")
	}
	if bucket.Attributes["public"] != true || bucket.Attributes["public_access_blocked"] != false {
		t.Fatalf("attrs %#v", bucket.Attributes)
	}
	if bucket.Causes["public"] != "cloudflare_r2_managed_domain.archive" {
		t.Fatalf("cause %q", bucket.Causes["public"])
	}
}

func TestAmbiguousR2Buckets(t *testing.T) {
	plan := []byte(`{
	  "resource_changes": [
	    {"address":"google_cloud_run_v2_service.api","mode":"managed","type":"google_cloud_run_v2_service","change":{"after":{
	      "name":"api","location":"europe-west1",
	      "template":[{"service_account":"api@example.iam.gserviceaccount.com","containers":[{"image":"example","env":[
	        {"name":"R2_ACCESS_KEY_ID","value_source":[{"secret_key_ref":[{"secret":"r2-key"}]}]}
	      ]}]}]
	    }}},
	    {"address":"google_secret_manager_secret.r2","mode":"managed","type":"google_secret_manager_secret","change":{"after":{"secret_id":"r2-key","rotation":[]}}},
	    {"address":"cloudflare_r2_bucket.one","mode":"managed","type":"cloudflare_r2_bucket","change":{"after":{"name":"one"}}},
	    {"address":"cloudflare_r2_bucket.two","mode":"managed","type":"cloudflare_r2_bucket","change":{"after":{"name":"two"}}}
	  ]
	}`)
	cfg := []byte("schema_version: fray-config/v1\n")
	doc, warnings, err := Parse(plan, cfg, "fray.yaml", Source{Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "cloudflare_r2_bucket.one") || !strings.Contains(joined, "cloudflare_r2_bucket.two") {
		t.Fatalf("warnings: %s", joined)
	}
	for _, f := range doc.Flows {
		for _, el := range doc.Elements {
			if el.ID == f.To && el.Kind == "object_storage" {
				t.Fatalf("emitted a flow to object storage despite two buckets")
			}
		}
	}
}

func TestR2AuthzFromAPIToken(t *testing.T) {
	baseSvc := `{"address":"google_cloud_run_v2_service.api","mode":"managed","type":"google_cloud_run_v2_service","change":{"after":{
	      "name":"api","location":"europe-west1",
	      "template":[{"service_account":"api@example.iam.gserviceaccount.com","containers":[{"image":"example","env":[
	        {"name":"R2_ACCESS_KEY_ID","value_source":[{"secret_key_ref":[{"secret":"r2-key"}]}]},
	        {"name":"R2_SECRET_ACCESS_KEY","value_source":[{"secret_key_ref":[{"secret":"r2-secret"}]}]}
	      ]}]}]
	    }}}`
	baseSecret := `{"address":"google_secret_manager_secret.r2","mode":"managed","type":"google_secret_manager_secret","change":{"after":{"secret_id":"r2-key","rotation":[]}}},
	    {"address":"google_secret_manager_secret.r2sec","mode":"managed","type":"google_secret_manager_secret","change":{"after":{"secret_id":"r2-secret","rotation":[]}}},
	    {"address":"cloudflare_r2_bucket.archive","mode":"managed","type":"cloudflare_r2_bucket","change":{"after":{"name":"archive"}}}`
	src := Source{Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}
	cfg := []byte("schema_version: fray-config/v1\n")

	r2Flow := func(t *testing.T, plan []byte) (Flow, []string) {
		t.Helper()
		doc, warnings, err := Parse(plan, cfg, "fray.yaml", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range doc.Flows {
			for _, el := range doc.Elements {
				if el.ID == f.To && el.Kind == "object_storage" {
					return f, warnings
				}
			}
		}
		t.Fatal("missing service→R2 flow")
		return Flow{}, nil
	}

	t.Run("bucket-scoped", func(t *testing.T) {
		plan := []byte(`{"resource_changes":[` + baseSvc + `,` + baseSecret + `,
	    {"address":"cloudflare_api_token.r2","mode":"managed","type":"cloudflare_api_token","change":{"after":{
	      "name":"r2-write",
	      "policies":[{"effect":"allow","resources":{"com.cloudflare.edge.r2.bucket.abc_default_archive":"*"}}]
	    }}}
	  ]}`)
		f, warnings := r2Flow(t, plan)
		if f.AuthzScope != "resource" {
			t.Fatalf("scope %q", f.AuthzScope)
		}
		if !slices.Equal(f.AuthzGrants, []string{"resource"}) {
			t.Fatalf("grants %#v", f.AuthzGrants)
		}
		if f.Causes["authz_scope"] != "cloudflare_api_token.r2" {
			t.Fatalf("cause %q", f.Causes["authz_scope"])
		}
		for _, w := range warnings {
			if strings.Contains(w, "authz_scope omitted") {
				t.Fatalf("unexpected warning: %s", w)
			}
		}
	})

	t.Run("account-wide", func(t *testing.T) {
		plan := []byte(`{"resource_changes":[` + baseSvc + `,` + baseSecret + `,
	    {"address":"cloudflare_api_token.r2","mode":"managed","type":"cloudflare_api_token","change":{"after":{
	      "name":"r2-account",
	      "policies":[{"effect":"allow","resources":"{\"com.cloudflare.api.account.abc\":\"*\"}"}]
	    }}}
	  ]}`)
		f, _ := r2Flow(t, plan)
		if f.AuthzScope != "account" {
			t.Fatalf("scope %q", f.AuthzScope)
		}
		if !slices.Equal(f.AuthzGrants, []string{"account"}) {
			t.Fatalf("grants %#v", f.AuthzGrants)
		}
	})

	t.Run("token-absent", func(t *testing.T) {
		plan := []byte(`{"resource_changes":[` + baseSvc + `,` + baseSecret + `]}`)
		f, warnings := r2Flow(t, plan)
		if f.AuthzScope != "" {
			t.Fatalf("scope %q want empty", f.AuthzScope)
		}
		if f.AuthzGrants != nil {
			t.Fatalf("grants %#v want nil", f.AuthzGrants)
		}
		joined := strings.Join(warnings, "\n")
		if !strings.Contains(joined, "no cloudflare_api_token in plan; authz_scope omitted") {
			t.Fatalf("warnings: %s", joined)
		}
	})
}

