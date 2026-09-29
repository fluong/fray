package client

import "strings"

// Purpose values are the closed dfd/v1 enum. Only these may appear on the wire.
var Purposes = []string{
	"audit_archive",
	"customer_uploads",
	"backups",
	"static_assets",
	"logs",
	"secrets",
	"app_data",
	"internal_api",
	"public_api",
	"other",
}

// ValidPurpose reports whether p is a dfd/v1 purpose enum value.
func ValidPurpose(p string) bool {
	for _, v := range Purposes {
		if p == v {
			return true
		}
	}
	return false
}

// InferPurpose guesses a purpose enum from a local display name.
// Only the enum is kept; the name itself is never written onto the element
// beyond what the parser already stored in Name (stripped on redact).
func InferPurpose(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return ""
	}
	switch {
	case strings.Contains(n, "backup"):
		return "backups"
	case strings.Contains(n, "upload"):
		return "customer_uploads"
	case strings.Contains(n, "audit") || strings.Contains(n, "archive"):
		return "audit_archive"
	case strings.Contains(n, "static") || strings.Contains(n, "asset") || strings.Contains(n, "cdn"):
		return "static_assets"
	case strings.Contains(n, "secret"):
		return "secrets"
	case strings.Contains(n, "log"):
		return "logs"
	case strings.Contains(n, "public") && strings.Contains(n, "api"):
		return "public_api"
	case strings.Contains(n, "internal") && strings.Contains(n, "api"):
		return "internal_api"
	case strings.Contains(n, "api"):
		return "internal_api"
	default:
		return ""
	}
}

// ApplyPurposeInference sets Purpose from Name when unset. Declared annotations win.
func ApplyPurposeInference(elements []Element) {
	for i := range elements {
		if elements[i].Purpose != "" {
			continue
		}
		if p := InferPurpose(elements[i].Name); p != "" {
			elements[i].Purpose = p
		}
	}
}

func applyPurposeInferencePtrs(elements []*Element) {
	for _, el := range elements {
		if el.Purpose != "" {
			continue
		}
		if p := InferPurpose(el.Name); p != "" {
			el.Purpose = p
		}
	}
}
