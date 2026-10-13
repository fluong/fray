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
	case "api_gateway":
		return "API"
	case "serverless_function":
		return "function"
	case "virtual_machine":
		// Standalone aws_instance only. Auto Scaling groups and EKS node
		// groups share Kind virtual_machine for FR-034 but must use
		// ASGDisplayName / EKSNodeGroupDisplayName so comments never say
		// "instance".
		return "instance"
	default:
		return ""
	}
}

// ASGDisplayName is the comment/SARIF-facing name for an aws_autoscaling_group.
// Always ends with "Auto Scaling group" so display never falls through to
// kindNoun("virtual_machine") → "instance".
func ASGDisplayName(address, resourceName string) string {
	base := ""
	if mod := rootModuleName(address); mod != "" {
		base = mod
	} else if resourceName != "" {
		base = resourceName
	} else if address != "" {
		base = address
	}
	if base == "" {
		return "Auto Scaling group"
	}
	return base + " Auto Scaling group"
}

// EKSNodeGroupDisplayName is the comment/SARIF-facing name for an
// aws_eks_node_group. Always ends with "EKS node group" so display never
// falls through to kindNoun("virtual_machine") → "instance".
func EKSNodeGroupDisplayName(address, resourceName string) string {
	base := ""
	if mod := rootModuleName(address); mod != "" {
		base = mod
	} else if resourceName != "" {
		base = resourceName
	} else if address != "" {
		base = address
	}
	if base == "" {
		return "EKS node group"
	}
	return base + " EKS node group"
}
