package client

import (
	"os"
	"path/filepath"
	"strings"
)

// ReportConfigPath is the config path recorded on a declared authz_scope cause
// and shown in the PR comment. When GITHUB_WORKSPACE is set and path is inside
// it, the result is relative to that root. A relative path is kept (cleaned).
// Any other absolute path is its base name. Separators are forward slashes.
func ReportConfigPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	cleaned := filepath.Clean(path)
	if ws := strings.TrimSpace(os.Getenv("GITHUB_WORKSPACE")); ws != "" && filepath.IsAbs(cleaned) {
		rel, err := filepath.Rel(filepath.Clean(ws), cleaned)
		if err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(rel)
		}
	}
	if !filepath.IsAbs(cleaned) {
		return filepath.ToSlash(cleaned)
	}
	return filepath.Base(cleaned)
}
