package render

import "strings"

const (
	lookupFieldElement = iota + 1
	lookupFieldFlow
)

// lookupFieldTable is the set of non-prefixed field names lookup() resolves on
// elements or flows. Dynamic paths attributes.<name>, from.<field>, and
// to.<field> are derived from this table (see ReadableField).
var lookupFieldTable = map[string]byte{
	"type":       lookupFieldElement,
	"kind":       lookupFieldElement,
	"provenance": lookupFieldElement,
	"provider":   lookupFieldElement,

	"data_class":               lookupFieldFlow,
	"transport":                lookupFieldFlow,
	"authz_scope":              lookupFieldFlow,
	"secret_delivery":          lookupFieldFlow,
	"authz_db_control_classes": lookupFieldFlow,
	"authz_db_control_scope":   lookupFieldFlow,
}

// ReadableField reports whether render.lookup understands field (including
// attributes.* and from./to. prefixes). It does not require a value to be present.
func ReadableField(field string) bool {
	field = strings.TrimSpace(field)
	if field == "" {
		return false
	}
	if side, rest, ok := strings.Cut(field, "."); ok && (side == "from" || side == "to") {
		return ReadableField(rest)
	}
	if name, ok := strings.CutPrefix(field, "attributes."); ok {
		return name != "" && !strings.Contains(name, ".")
	}
	_, ok := lookupFieldTable[field]
	return ok
}
