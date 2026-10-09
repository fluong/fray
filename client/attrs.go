package client

import (
	"fmt"
	"os"
	"regexp"
)

// attrKind is the closed value kind for an Element.Attributes key.
type attrKind int

const (
	attrBool attrKind = iota
	attrInt
	attrRegion
)

// allowedAttributes is the closed set of Element.Attributes keys and the
// value kinds accepted at DFD build time. Keep in sync with
// schema/dfd.schema.json #$defs/attributes.
var allowedAttributes = map[string]attrKind{
	"public":                 attrBool,
	"acls_disabled":          attrBool,
	"public_access_blocked":  attrBool,
	"encrypted_at_rest":      attrBool,
	"deletion_protection":    attrBool,
	"image_pinned_by_digest": attrBool,
	"audit_logging":          attrBool,
	"rotation_configured":    attrBool,
	"versioning":             attrBool,
	"object_lock":            attrBool,
	"network_restricted":     attrBool,
	"max_instances":          attrInt,
	"region":                 attrRegion,
}

// regionAttrPattern matches dfd/v1 region strings (same as regionPattern / schema).
var regionAttrPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// AllowedAttributeKeys returns the closed attribute key set (for tests).
func AllowedAttributeKeys() []string {
	out := make([]string, 0, len(allowedAttributes))
	for k := range allowedAttributes {
		out = append(out, k)
	}
	return out
}

// sanitizeAttributes drops any attribute that is not in the allow-list or
// whose value does not match the declared kind. Only the key is debug-logged
// (never the value). Called at DFD build time before finalize.
func sanitizeAttributes(elements []*Element) {
	for _, el := range elements {
		if el == nil || len(el.Attributes) == 0 {
			continue
		}
		for k, v := range el.Attributes {
			if !attrAllowed(k, v) {
				debugDropAttr(k)
				delete(el.Attributes, k)
			}
		}
		if len(el.Attributes) == 0 {
			el.Attributes = nil
		}
	}
}

func attrAllowed(key string, v any) bool {
	kind, ok := allowedAttributes[key]
	if !ok {
		return false
	}
	switch kind {
	case attrBool:
		_, ok := v.(bool)
		return ok
	case attrInt:
		switch n := v.(type) {
		case int:
			return n >= 0
		case int64:
			return n >= 0
		case float64:
			return n >= 0 && n == float64(int(n))
		default:
			return false
		}
	case attrRegion:
		s, ok := v.(string)
		return ok && regionAttrPattern.MatchString(s)
	default:
		return false
	}
}

func debugDropAttr(key string) {
	if os.Getenv("FRAY_DEBUG") == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "fray: dropped attribute %q\n", key)
}
