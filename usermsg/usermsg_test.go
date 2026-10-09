package usermsg

import (
	"strings"
	"testing"
)

func TestSeeTroubleshootingAnchor(t *testing.T) {
	got := SeeTroubleshooting("fix me.")
	if !strings.Contains(got, "fix me.") {
		t.Fatalf("lost message: %q", got)
	}
	if !strings.Contains(got, TroubleshootingURL) {
		t.Fatalf("missing anchor: %q", got)
	}
}

func TestRemediesIncludeFixAndAnchor(t *testing.T) {
	cases := []string{
		SeeTroubleshooting(EmptyOIDC),
		SeeTroubleshooting(MissingOIDCEndpoints),
		SeeTroubleshooting(GateBlocked),
		SeeTroubleshooting(WorkdirMissing("infra")),
		SeeTroubleshooting(NoTerraformFiles("infra")),
		SeeTroubleshooting(FrayYAMLMissing("fray.yaml")),
		SeeTroubleshooting(TerraformFailed("infra", "plan")),
		SeeTroubleshooting(APIRequestFailed("500: boom")),
		SeeTroubleshooting("Scan rate limit reached (retry after 7 s)" + RateLimitFreePlan),
	}
	for _, msg := range cases {
		if !strings.Contains(msg, TroubleshootingURL) {
			t.Fatalf("missing troubleshooting URL in %q", msg)
		}
		// Each should name a concrete fix (permission, path, api-url, wait, etc.).
		hasFix := strings.Contains(msg, "id-token") ||
			strings.Contains(msg, "working-directory") ||
			strings.Contains(msg, "schema_version") ||
			strings.Contains(msg, "credentials") ||
			strings.Contains(msg, "api-url") ||
			strings.Contains(msg, "waivers.yml") ||
			strings.Contains(msg, "retry-after") ||
			strings.Contains(msg, "30 scans")
		if !hasFix {
			t.Fatalf("expected a fix hint in %q", msg)
		}
	}
}
