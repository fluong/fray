package v1

import (
	"fmt"
	"regexp"
	"strings"
)

// StackIDRe is the allowed scan stack format (empty string is also valid).
var StackIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ValidateStack reports whether stack is empty or matches StackIDRe.
func ValidateStack(stack string) error {
	if stack == "" || StackIDRe.MatchString(stack) {
		return nil
	}
	return fmt.Errorf("invalid stack %q: must be empty or match ^[a-z0-9][a-z0-9-]{0,31}$ (lowercase letter or digit, then up to 31 lowercase letters, digits, or hyphens)", stack)
}

// CommentMarker is the HTML marker the Action uses to find/update the PR comment.
// Empty stack keeps today's marker; a named stack never shares a comment.
func CommentMarker(stack string) string {
	if stack == "" {
		return "<!-- fray -->"
	}
	return "<!-- fray:" + stack + " -->"
}

// OutDirName is the FRAY_OUT directory basename under runner.temp.
func OutDirName(stack string) string {
	if stack == "" {
		return "fray-out"
	}
	return "fray-out-" + stack
}

// ArtifactName is the upload-artifact name for show-payload.
func ArtifactName(stack string) string {
	if stack == "" {
		return "fray-payload"
	}
	return "fray-payload-" + stack
}

// SARIFCategory is the Code Scanning upload category.
func SARIFCategory(stack string) string {
	if stack == "" {
		return "fray"
	}
	return "fray/" + stack
}

// CommentMatchesMarker reports whether a PR comment body belongs to marker.
// Match is exact: body == marker, or body starts with marker + newline.
// A named stack must never match the default marker (or another stack's).
func CommentMatchesMarker(body, marker string) bool {
	return body == marker || strings.HasPrefix(body, marker+"\n")
}
