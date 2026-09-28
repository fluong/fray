package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreventDestroyFromHCL(t *testing.T) {
	dir := t.TempDir()
	src := `
resource "google_storage_bucket" "shared" {
  count = 2
  name  = "from-hcl-not-used"
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_secret_manager_secret" "each" {
  for_each  = toset(["a"])
  secret_id = each.key
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket" "open" {
  name = "open"
  lifecycle {
    prevent_destroy = false
  }
}

resource "google_storage_bucket" "dynamic" {
  name = "dynamic"
  lifecycle {
    prevent_destroy = var.protect
  }
}

resource "google_secret_manager_secret_version" "placeholder" {
  secret_data = "not-read"
  lifecycle {
    ignore_changes = [secret_data, enabled]
  }
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	idx, err := readPreventDestroy(dir)
	if err != nil {
		t.Fatal(err)
	}
	protected := []string{
		"google_storage_bucket.shared[0]",
		"google_storage_bucket.shared[1]",
		`google_secret_manager_secret.each["a"]`,
	}
	for _, addr := range protected {
		if !idx.protected(addr) {
			t.Errorf("%s: want prevent_destroy", addr)
		}
	}
	open := []string{
		"google_storage_bucket.open",
		"google_storage_bucket.dynamic",
		"google_secret_manager_secret_version.placeholder",
	}
	for _, addr := range open {
		if idx.protected(addr) {
			t.Errorf("%s: prevent_destroy must stay unread", addr)
		}
	}
}

func TestResourceLocation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "infra")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "\nresource \"google_project_iam_member\" \"database_url_accessor\" {\n  role = \"roles/secretmanager.secretAccessor\"\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	locs, err := ResourceLocations(dir)
	if err != nil {
		t.Fatal(err)
	}
	loc, ok := LookupLocation(locs, "google_project_iam_member.database_url_accessor")
	if !ok {
		t.Fatal("missing location")
	}
	if loc.String() != "infra/main.tf:2" {
		t.Fatalf("location %s", loc)
	}
}

func TestDataSourceLocation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "infra")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := `
data "aws_iam_policy_document" "task_exec" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["*"]
  }
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	locs, err := ResourceLocations(dir)
	if err != nil {
		t.Fatal(err)
	}
	loc, ok := LookupLocation(locs, "data.aws_iam_policy_document.task_exec[0]")
	if !ok {
		t.Fatal("missing data location")
	}
	if loc.Path == "" || loc.Line <= 0 {
		t.Fatalf("location %+v", loc)
	}
}

func TestModuleCallLocation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "infra")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := `
module "uploads" {
  source = "./uploads"

  block_public_acls = false
}

resource "aws_s3_bucket" "local" {
  bucket = "local"
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	locs, err := ResourceLocations(dir)
	if err != nil {
		t.Fatal(err)
	}
	call, ok := LookupCauseLocation(locs, "module.uploads.aws_s3_bucket_public_access_block.this[0]", "public_access_blocked")
	if !ok {
		t.Fatal("missing module call location")
	}
	if call.Line != 2 { // module "uploads" call site
		t.Fatalf("want module call line, got %s", call)
	}
	if strings.Contains(call.Path, ".terraform/modules") {
		t.Fatalf("vendored path %s", call.Path)
	}
	mc, ok := LookupModuleCause(locs, "module.uploads.aws_s3_bucket_public_access_block.this[0]", "public_access_blocked")
	if !ok {
		t.Fatal("missing module cause")
	}
	if mc.Call != "module.uploads" {
		t.Fatalf("call %s", mc.Call)
	}
	if len(mc.Inputs) != 1 || mc.Inputs[0] != "block_public_acls" {
		t.Fatalf("inputs %+v", mc.Inputs)
	}
	rootCall, ok := LookupLocation(locs, "module.uploads.aws_s3_bucket.this[0]")
	if !ok {
		t.Fatal("missing module.uploads call")
	}
	if rootCall.Line != 2 {
		t.Fatalf("module call line %s", rootCall)
	}
}

func TestPreventDestroyChildModule(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, ".terraform", "modules", "child")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{
	  "Modules": [
	    {"Key": "", "Source": "", "Dir": "."},
	    {"Key": "child", "Source": "./child", "Dir": ".terraform/modules/child"}
	  ]
	}`
	if err := os.WriteFile(filepath.Join(root, ".terraform", "modules", "modules.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	src := `
resource "cloudflare_r2_bucket" "archive" {
  name = "from-hcl-not-used"
  lifecycle {
    prevent_destroy = true
  }
}
`
	if err := os.WriteFile(filepath.Join(child, "main.tf"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	idx, err := readPreventDestroy(root)
	if err != nil {
		t.Fatal(err)
	}
	addr := `module.child.cloudflare_r2_bucket.archive["eu"]`
	if !idx.protected(addr) {
		t.Fatalf("%s: want prevent_destroy from the downloaded module", addr)
	}
	if idx.protected("cloudflare_r2_bucket.archive") {
		t.Fatal("root address must not inherit the child module block")
	}
}
