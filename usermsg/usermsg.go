// Package usermsg holds user-facing Action/CLI strings that point at public docs.
package usermsg

// TroubleshootingURL is the README troubleshooting anchor (public docs).
const TroubleshootingURL = "https://github.com/fluong/fray#troubleshooting"

// SeeTroubleshooting appends a one-line pointer to the troubleshooting table.
func SeeTroubleshooting(msg string) string {
	return msg + " See " + TroubleshootingURL + "."
}

// NoBaselineNote is shown on PR comments when the server has no baseline findings yet.
const NoBaselineNote = "No baseline yet — comparison against the default branch starts after its first Fray scan."

// EmptyOIDC is the Action annotation when the OIDC token value is empty.
const EmptyOIDC = `Empty OIDC token for audience "fray". Confirm permissions include id-token: write and that this is not a fork PR.`

// MissingOIDCEndpoints is the Action annotation when ID-token endpoints are absent.
const MissingOIDCEndpoints = `Missing Actions ID token endpoints. Grant permissions: id-token: write.`

// GateBlocked is the Gate step error when the merge gate fails.
const GateBlocked = `Fray gate blocked this change (new high-severity findings vs baseline). Review the Fray PR comment (or findings.sarif). To accept risk, add an entry under .fray/waivers.yml (see README Waivers). A default-branch scan sets the merge baseline.`

// RateLimitFreePlan is appended to rate-limit notices.
const RateLimitFreePlan = ` Free plan: 30 scans/repo/hour and 100/org/day — see README Limits. Wait for retry-after, then re-run.`

// WorkdirMissing formats the working-directory not found error.
func WorkdirMissing(path string) string {
	return "working-directory not found: " + path + ". Set the Action input working-directory to your Terraform root (directory with .tf files), relative to the repository root."
}

// NoTerraformFiles formats the empty Terraform root error.
func NoTerraformFiles(path string) string {
	return "No Terraform (.tf) files in working-directory: " + path + ". Set working-directory to your Terraform root (directory with .tf files), relative to the repository root."
}

// FrayYAMLMissing formats the missing config error.
func FrayYAMLMissing(path string) string {
	return "fray.yaml not found: " + path + ". Add a file with: schema_version: fray-config/v1 (see README Config)."
}

// TerraformFailed formats init/plan failure after Terraform exits non-zero.
func TerraformFailed(workdir, step string) string {
	return "terraform " + step + " failed in " + workdir + ". Fray runs terraform init/plan in CI — ensure provider and backend credentials are available to the job (same as your normal plan workflow)."
}

// APIRequestFailed formats transport or non-OK API responses (non-enrollment).
func APIRequestFailed(detail string) string {
	return "Fray API request failed (" + detail + "). Check api-url is https://api.getfray.dev, then retry. If this persists, open an issue on fluong/fray."
}
