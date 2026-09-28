package client

import "strings"

// DisplayName picks a human name for comments and reports.
// Module resources use "<module> <kind-noun>" when a noun is known
// (for example "uploads bucket"), otherwise the module name alone.
// Non-module resources use the Terraform resource name, else the address.
func DisplayName(address, resourceName, kind string) string {
	if mod := rootModuleName(address); mod != "" {
		if noun := kindNoun(kind); noun != "" {
			return mod + " " + noun
		}
		return mod
	}
	if resourceName != "" {
		return resourceName
	}
	if address != "" {
		return address
	}
	return resourceName
}

func rootModuleName(address string) string {
	if !strings.HasPrefix(address, "module.") {
		return ""
	}
	rest := strings.TrimPrefix(address, "module.")
	i := 0
	for i < len(rest) && rest[i] != '.' && rest[i] != '[' {
		i++
	}
	if i == 0 {
		return ""
	}
	return rest[:i]
}

func kindNoun(kind string) string {
	switch kind {
	case "object_storage":
		return "bucket"
	case "secret_store":
		return "secret"
	case "relational_db":
		return "database"
	case "load_balancer":
		return "load balancer"
	default:
		return ""
	}
}
