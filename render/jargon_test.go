package render

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Customer-facing rule prose must not leak DFD schema field names or the word
// "flow" (engine jargon). Placeholders like {process}/{secret} are fine in YAML
// before fill; this checks rendered goldens and authored fix_here/why_here after
// the demo enrichments are applied.
var dfdJargon = regexp.MustCompile(`(?i)\b(authz_scope|authz_grants|authz_actions|purpose_source|acls_disabled|public_access_blocked|secret_delivery|object_lock|data_class|internet_reachable)\b|\bflows?\b`)

func TestCustomerFacingProseHasNoDFDJargon(t *testing.T) {
	root := filepath.Join("..", "testdata", "golden")
	files := []string{
		"pr-comment-aws-fr007-enrichment-target.md",
		"pr-comment-aws-fr025-enrichment-target.md",
	}
	for _, name := range files {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if loc := dfdJargon.FindIndex(raw); loc != nil {
			snippet := string(raw[loc[0]:loc[1]])
			t.Fatalf("%s contains DFD jargon %q", name, snippet)
		}
	}

	// Authored context lines used by the enrichment goldens (post-placeholder).
	authored := []string{
		"Drop the account-wide grant; the scoped grant already gives ecs_service access to db_password secret.",
		"ACLs are already disabled on this bucket, so a bucket policy is now the only way it could become public — and nothing blocks one anymore.",
		"Nothing in the bucket is public yet, but nothing now prevents a bucket policy from making it public.",
	}
	for _, s := range authored {
		if dfdJargon.MatchString(s) {
			t.Fatalf("authored prose has jargon: %q", s)
		}
		if strings.Contains(strings.ToLower(s), "authorizes this flow") {
			t.Fatalf("stale fix_here jargon: %q", s)
		}
	}
}
