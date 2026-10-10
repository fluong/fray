package client

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePlanJSONBranches(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr error
	}{
		{
			name:    "a_missing_format_version",
			body:    `{"resource_changes":[{"address":"aws_s3_bucket.a","mode":"managed","change":{"after":{"bucket":"x"}}}]}`,
			wantErr: ErrPlanNotTerraformJSON,
		},
		{
			name:    "a_format_version_not_string",
			body:    `{"format_version":1.2,"resource_changes":[{"address":"aws_s3_bucket.a","mode":"managed","change":{"after":{"bucket":"x"}}}]}`,
			wantErr: ErrPlanNotTerraformJSON,
		},
		{
			name:    "b_state_shaped",
			body:    `{"format_version":"1.0","values":{"root_module":{"resources":[]}}}`,
			wantErr: ErrPlanLooksLikeState,
		},
		{
			name:    "c_data_only_format_ok",
			body:    `{"format_version":"1.2","resource_changes":[{"address":"data.aws_caller_identity.current","mode":"data","change":{"after":{}}}],"planned_values":{"root_module":{}}}`,
			wantErr: nil, // RefuseUnanalysablePlan rejects; format/state checks only here
		},
		{
			name:    "d_planned_values_only_format_ok",
			body:    `{"format_version":"1.2","resource_changes":[],"planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket.a","values":{"bucket":"x"}}]}}}`,
			wantErr: nil,
		},
		{
			name:    "d_empty_resource_changes_format_ok",
			body:    `{"format_version":"1.2","resource_changes":[],"planned_values":{"root_module":{}}}`,
			wantErr: nil,
		},
		{
			name: "noop_accepted",
			body: `{
			  "format_version": "1.2",
			  "resource_changes": [{
			    "address": "aws_s3_bucket.a",
			    "mode": "managed",
			    "type": "aws_s3_bucket",
			    "change": {"actions": ["no-op"], "after": {"bucket": "keep-me"}}
			  }],
			  "planned_values": {"root_module": {"resources": []}}
			}`,
			wantErr: nil,
		},
		{
			name: "all_delete_passes_c",
			body: `{
			  "format_version": "1.2",
			  "resource_changes": [{
			    "address": "aws_s3_bucket.gone",
			    "mode": "managed",
			    "type": "aws_s3_bucket",
			    "change": {"actions": ["delete"], "before": {"bucket": "x"}, "after": null}
			  }]
			}`,
			wantErr: nil,
		},
		{
			name:    "binary_rejected",
			body:    "\x00\x01tfplan binary",
			wantErr: ErrPlanNotJSON,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePlanJSON([]byte(tc.body))
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("want accept, got %v", err)
				}
				return
			}
			if err == nil || err.Error() != tc.wantErr.Error() {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestLoadPlanFileSizeCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse file: large logical size without writing 32 MiB of data.
	if err := f.Truncate(MaxPlanFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte(`{"format_version":"1.2"}`), 0); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = LoadPlanFile(path)
	if err != ErrPlanTooLarge {
		t.Fatalf("got %v, want ErrPlanTooLarge", err)
	}
}

func TestLoadPlanFileOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	body := `{
	  "format_version": "1.2",
	  "resource_changes": [{
	    "address": "aws_s3_bucket.a",
	    "mode": "managed",
	    "type": "aws_s3_bucket",
	    "change": {"actions": ["no-op"], "after": {"bucket": "x"}}
	  }]
	}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPlanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "format_version") {
		t.Fatal("missing body")
	}
}

func TestCountUnmatchedPlanAddresses(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
resource "aws_s3_bucket" "keep" {
  bucket = "x"
}
module "uploads" {
  source = "./mod"
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "mod"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mod", "main.tf"), []byte(`
resource "aws_s3_bucket" "inner" { bucket = "y" }
`), 0o644); err != nil {
		t.Fatal(err)
	}

	plan := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address":"aws_s3_bucket.keep","mode":"managed","change":{"after":{"bucket":"x"}}},
	    {"address":"module.uploads.aws_s3_bucket.inner[0]","mode":"managed","change":{"after":{"bucket":"y"}}},
	    {"address":"aws_s3_bucket.missing","mode":"managed","change":{"after":{"bucket":"z"}}}
	  ]
	}`)
	n, err := CountUnmatchedPlanAddresses(plan, dir)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("unmatched=%d, want 1 (aws_s3_bucket.missing)", n)
	}
}

func TestRefuseUnanalysablePlan(t *testing.T) {
	cfg := []byte("schema_version: fray-config/v1\n")
	src := Source{Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}
	dir := t.TempDir()

	parse := func(plan []byte) DFD {
		t.Helper()
		doc, _, err := Parse(plan, cfg, "fray.yaml", src, dir)
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}

	t.Run("no_managed", func(t *testing.T) {
		plan := []byte(`{"format_version":"1.2","resource_changes":[],"planned_values":{"root_module":{}}}`)
		err := RefuseUnanalysablePlan(plan, parse(plan), "infra")
		if !errors.Is(err, ErrPlanNoResources) {
			t.Fatalf("got %v", err)
		}
		if !strings.Contains(err.Error(), "check working-directory (currently: infra)") {
			t.Fatalf("missing workdir hint: %v", err)
		}
	})
	t.Run("all_delete", func(t *testing.T) {
		plan := []byte(`{
		  "format_version": "1.2",
		  "resource_changes": [{
		    "address": "aws_s3_bucket.gone",
		    "mode": "managed",
		    "type": "aws_s3_bucket",
		    "change": {"actions": ["delete"], "before": {"bucket": "x"}, "after": null}
		  }]
		}`)
		err := RefuseUnanalysablePlan(plan, parse(plan), "infra")
		if !errors.Is(err, ErrPlanEmptyDFD) {
			t.Fatalf("got %v", err)
		}
		if !strings.Contains(err.Error(), "all changes are deletes") {
			t.Fatalf("missing delete hint: %v", err)
		}
	})
	t.Run("unsupported_only", func(t *testing.T) {
		plan := []byte(`{
		  "format_version": "1.2",
		  "resource_changes": [{
		    "address": "null_resource.x",
		    "mode": "managed",
		    "type": "null_resource",
		    "change": {"actions": ["no-op"], "after": {}}
		  }],
		  "configuration": {"root_module": {"resources": [
		    {"address":"null_resource.x","type":"null_resource","name":"x","mode":"managed","expressions":{}}
		  ]}}
		}`)
		err := RefuseUnanalysablePlan(plan, parse(plan), "infra")
		if !errors.Is(err, ErrPlanEmptyDFD) {
			t.Fatalf("got %v", err)
		}
		if strings.Contains(err.Error(), "deletes") {
			t.Fatalf("unsupported must not claim deletes: %v", err)
		}
	})
	t.Run("normal", func(t *testing.T) {
		plan := []byte(`{
		  "format_version": "1.2",
		  "resource_changes": [{
		    "address": "aws_s3_bucket.a",
		    "mode": "managed",
		    "type": "aws_s3_bucket",
		    "name": "a",
		    "change": {"actions": ["no-op"], "after": {"bucket": "keep-me"}}
		  }],
		  "configuration": {"root_module": {"resources": [
		    {"address":"aws_s3_bucket.a","type":"aws_s3_bucket","name":"a","mode":"managed","expressions":{}}
		  ]}}
		}`)
		if err := RefuseUnanalysablePlan(plan, parse(plan), "infra"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestNoopPlanProducesNonEmptyDFD(t *testing.T) {
	plan := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [{
	    "address": "aws_s3_bucket.a",
	    "mode": "managed",
	    "type": "aws_s3_bucket",
	    "name": "a",
	    "change": {"actions": ["no-op"], "after": {"bucket": "keep-me"}}
	  }],
	  "configuration": {"root_module": {"resources": [
	    {"address":"aws_s3_bucket.a","type":"aws_s3_bucket","name":"a","mode":"managed","expressions":{}}
	  ]}}
	}`)
	if err := ValidatePlanJSON(plan); err != nil {
		t.Fatal(err)
	}
	doc, _, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "fray.yaml",
		Source{Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Elements) == 0 {
		t.Fatal("expected non-empty DFD from no-op managed resource")
	}
}

func TestAllDeletePlanEmptyDFD(t *testing.T) {
	plan := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [{
	    "address": "aws_s3_bucket.gone",
	    "mode": "managed",
	    "type": "aws_s3_bucket",
	    "change": {"actions": ["delete"], "before": {"bucket": "x"}, "after": null}
	  }]
	}`)
	if err := ValidatePlanJSON(plan); err != nil {
		t.Fatal(err)
	}
	doc, _, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "fray.yaml",
		Source{Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Elements) != 0 {
		t.Fatalf("all-delete should yield empty DFD, got %d elements", len(doc.Elements))
	}
}
