package validate

import (
	"embed"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed dfd.schema.json
var embeddedSchemas embed.FS

// CompileDFD compiles the embedded DFD JSON Schema.
func CompileDFD() (*jsonschema.Schema, error) {
	raw, err := embeddedSchemas.ReadFile("dfd.schema.json")
	if err != nil {
		return nil, err
	}
	return CompileBytes("dfd.schema.json", raw)
}
