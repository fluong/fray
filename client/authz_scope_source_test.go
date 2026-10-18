package client

import "testing"

func TestAuthzScopeSourceDeclaredFromAnnotation(t *testing.T) {
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
		if flow.From == "" || flow.AuthzScope == "" {
			continue
		}
		if flow.AuthzScopeSource != "" {
			t.Fatalf("parser flow %s->%s authz_scope_source=%q want absent", flow.From, flow.To, flow.AuthzScopeSource)
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
