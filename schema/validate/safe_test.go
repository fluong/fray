package validate_test

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fluong/fray/schema/validate"
)

func TestLogSafeOmitsPayloadFragments(t *testing.T) {
	schema, err := validate.Compile(filepath.Join("..", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "examples", "negative-secret.dfd.json"))
	if err != nil {
		t.Fatal(err)
	}
	const secret = "postgres://fray_app:secret@host/fray_db"
	if !bytes.Contains(raw, []byte(secret)) {
		t.Fatal("fixture must contain the secret-shaped value")
	}
	err = validate.DFD(schema, raw)
	if err == nil {
		t.Fatal("expected schema rejection")
	}
	class, pointer := validate.LogSafe(err)
	if class == "" || !strings.HasPrefix(class, "schema") {
		t.Fatalf("class: %q", class)
	}
	if pointer != "/elements/0" {
		t.Fatalf("pointer: %q", pointer)
	}

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("invalid_dfd", "err_class", class, "json_pointer", pointer)
	logged := buf.String()
	if strings.Contains(logged, secret) || strings.Contains(logged, "fray_app:secret") {
		t.Fatalf("log leaked payload:\n%s", logged)
	}
	if !strings.Contains(logged, `"err_class"`) || !strings.Contains(logged, pointer) {
		t.Fatalf("log missing class/pointer:\n%s", logged)
	}
	// Caller-facing detail may describe the schema failure (not for logs).
	if !strings.Contains(err.Error(), "additional properties") {
		t.Fatalf("detail for caller: %v", err)
	}
}

func TestLogSafeSemanticPointer(t *testing.T) {
	schema, err := validate.Compile(filepath.Join("..", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "examples", "negative-dangling.dfd.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = validate.DFD(schema, raw)
	if err == nil {
		t.Fatal("expected semantic rejection")
	}
	class, pointer := validate.LogSafe(err)
	if class != "semantic" {
		t.Fatalf("class: %q", class)
	}
	if !strings.HasPrefix(pointer, "/flows/") {
		t.Fatalf("pointer: %q", pointer)
	}
}
