package schema

import _ "embed"

// WaiversSchemaJSON is the JSON Schema for .fray/waivers.yml (version 1).
//
//go:embed waivers.schema.json
var WaiversSchemaJSON []byte
