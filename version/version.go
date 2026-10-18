// Package version holds the Fray Action/CLI release identity used in SARIF
// driver metadata and (eventually) release tooling.
package version

import "regexp"

// Version is the release version string (SemVer without a leading "v").
const Version = "0.40.0"

// InformationURI is the public repository URL for SARIF driver.informationUri.
const InformationURI = "https://github.com/fluong/fray"

// RuleIDRe matches public catalog rule ids (FR-010 or FR-AWS-0001).
var RuleIDRe = regexp.MustCompile(`^FR-([0-9]{3}|[A-Z][A-Z0-9]{1,9}-[0-9]{4})$`)

// RuleDocURL returns the GitHub blob URL for a rule's public catalog page, or
// "" when id is not a catalog rule id.
func RuleDocURL(id string) string {
	if !RuleIDRe.MatchString(id) {
		return ""
	}
	return InformationURI + "/blob/main/docs/rules/" + id + ".md"
}
