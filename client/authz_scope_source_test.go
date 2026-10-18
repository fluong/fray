package client

import (
	"slices"
	"strings"
	"testing"
)

func TestAuthzScopeSourceFillAuthzScopeWithAndWithoutAnnotation(t *testing.T) {
	src := Source{Repo: "t/b66", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}
	reason := "rds-db:connect scoped via managed policy arn:aws:iam::123:policy/app-db"
	plan := bucketUnknownDocsPlan(t)

	withAnn := `  flows:
    - from: aws_ecs_service.app
      to: aws_s3_bucket.uploads
      authz_scope: resource
      reason: "` + reason + `"
`
	f := fillScope(t, plan, "fray.yaml", src, withAnn, "unknown")
	if f.AuthzScopeSource != authzScopeSourceDeclared {
		t.Fatalf("authz_scope_source=%q want declared", f.AuthzScopeSource)
	}

	noAnn := "schema_version: fray-config/v1\n"
	doc, _, err := Parse([]byte(plan), []byte(noAnn), "fray.yaml", src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, flow := range doc.Flows {
		if flow.AuthzScope == "" {
			continue
		}
		if flow.AuthzScopeSource != "" {
			t.Fatalf("parser flow authz_scope_source=%q want absent", flow.AuthzScopeSource)
		}
	}
}

func TestAuthzScopeSourceDeclaredFlow(t *testing.T) {
	plan := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address":"aws_ecs_service.app","mode":"managed","type":"aws_ecs_service","change":{"after":{"name":"app"}}},
	    {"address":"aws_db_instance.main","mode":"managed","type":"aws_db_instance","change":{"after":{"identifier":"main"}}}
	  ]
	}`)
	src := Source{Repo: "t/b66", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}

	withScope := `schema_version: fray-config/v1
flows:
  - from: aws_ecs_service.app
    to: aws_db_instance.main
    data_class: unknown
    transport: tls
    authz_scope: account
`
	doc, _, err := Parse(plan, []byte(withScope), "fray.yaml", src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var declared Flow
	for _, f := range doc.Flows {
		if f.AuthzScope == "account" {
			declared = f
		}
	}
	if declared.AuthzScopeSource != authzScopeSourceDeclared {
		t.Fatalf("declared flow authz_scope_source=%q", declared.AuthzScopeSource)
	}

	noScope := `schema_version: fray-config/v1
flows:
  - from: aws_ecs_service.app
    to: aws_db_instance.main
    data_class: unknown
    transport: tls
`
	doc2, _, err := Parse(plan, []byte(noScope), "fray.yaml", src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range doc2.Flows {
		if f.AuthzScopeSource != "" {
			t.Fatalf("flow without yaml authz_scope has authz_scope_source=%q", f.AuthzScopeSource)
		}
	}
}

func TestAuthzScopeSourceAnnotationIgnoredWhenParserDerived(t *testing.T) {
	src := Source{Repo: "t/b66", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}
	plan := dbAuthzECSPlan(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["rds-db:connect"],"Resource":["arn:aws:rds-db:us-east-1:111122223333:dbuser:db-ABCDEF/app"]}]}`, false)
	doc, warnings, err := Parse([]byte(plan), []byte(`schema_version: fray-config/v1
annotations:
  flows:
    - from: module.ecs.aws_ecs_service.this
      to: module.db.aws_db_instance.this
      authz_scope: resource
      reason: "parser already derived resource from the task role"
`), "fray.yaml", src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	wantWarn := "fray.yaml annotation ignored: module.ecs.aws_ecs_service.this -> module.db.aws_db_instance.this already has derived authz_scope resource"
	if !slices.ContainsFunc(warnings, func(w string) bool { return strings.Contains(w, wantWarn) }) {
		t.Fatalf("warnings: %s", strings.Join(warnings, "\n"))
	}
	for _, f := range doc.Flows {
		if f.AuthzScope != "" && f.AuthzScopeSource != "" {
			t.Fatalf("derived scope must not carry authz_scope_source=%q", f.AuthzScopeSource)
		}
	}
}

func TestRedactKeepsDeclaredAuthzScopeSource(t *testing.T) {
	src := Source{Repo: "t/b66", Commit: "abcdef1234567890abcdef1234567890abcd", Tool: "terraform", Fidelity: "plan"}
	reason := "rds-db:connect scoped via managed policy arn:aws:iam::123:policy/app-db"
	cfg := `schema_version: fray-config/v1
annotations:
  flows:
    - from: aws_ecs_service.app
      to: aws_s3_bucket.uploads
      authz_scope: resource
      reason: "` + reason + `"
`
	doc, _, err := Parse([]byte(bucketUnknownDocsPlan(t)), []byte(cfg), "fray.yaml", src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	redacted, _, err := Redact(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	var kept bool
	for _, f := range redacted.Flows {
		if f.AuthzScopeSource == authzScopeSourceDeclared {
			kept = true
		}
		if f.AuthzScopeSource == "derived" {
			t.Fatalf("derived on redacted wire")
		}
	}
	if !kept {
		t.Fatal("want declared authz_scope_source on redacted fill flow")
	}
}

func TestRedactClearsNonDeclaredAuthzScopeSource(t *testing.T) {
	doc := DFD{
		SchemaVersion: "dfd/v1",
		Source: Source{
			Repo: "acme/app", Commit: "abcdef1234567890abcdef1234567890abcd", Tool: "terraform", Fidelity: "plan",
		},
		Elements: []Element{
			{ID: "e1", Type: "process", Kind: "container_service", Provider: "aws", Provenance: "iac", Evidence: Evidence{Addresses: []string{"aws_ecs_service.app"}}},
			{ID: "e2", Type: "datastore", Kind: "object_storage", Provider: "aws", Provenance: "iac", Evidence: Evidence{Addresses: []string{"aws_s3_bucket.uploads"}}},
		},
		TrustBoundaries: []Boundary{},
		Flows: []Flow{{
			ID: "f1", From: "e1", To: "e2", DataClass: "unknown", Transport: "tls", Boundaries: []string{},
			AuthzScope: "resource", AuthzScopeSource: "derived",
		}},
	}
	finalize(&doc)
	key := make([]byte, 32)
	redacted, _, err := Redact(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	if redacted.Flows[0].AuthzScopeSource != "" {
		t.Fatalf("derived leaked on wire: %q", redacted.Flows[0].AuthzScopeSource)
	}
}

func TestRedactAbsentAuthzScopeSourceStaysAbsent(t *testing.T) {
	doc := DFD{
		SchemaVersion: "dfd/v1",
		Source: Source{
			Repo: "acme/app", Commit: "abcdef1234567890abcdef1234567890abcd", Tool: "terraform", Fidelity: "plan",
		},
		Elements: []Element{
			{ID: "e1", Type: "process", Kind: "container_service", Provider: "aws", Provenance: "iac", Evidence: Evidence{Addresses: []string{"aws_ecs_service.app"}}},
			{ID: "e2", Type: "datastore", Kind: "object_storage", Provider: "aws", Provenance: "iac", Evidence: Evidence{Addresses: []string{"aws_s3_bucket.uploads"}}},
		},
		TrustBoundaries: []Boundary{},
		Flows: []Flow{{
			ID: "f1", From: "e1", To: "e2", DataClass: "unknown", Transport: "tls", Boundaries: []string{},
			AuthzScope: "resource",
		}},
	}
	finalize(&doc)
	key := make([]byte, 32)
	redacted, _, err := Redact(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	if redacted.Flows[0].AuthzScopeSource != "" {
		t.Fatalf("want absent, got %q", redacted.Flows[0].AuthzScopeSource)
	}
}
