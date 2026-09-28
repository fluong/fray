// Package validate checks a DFD against JSON Schema and semantic rules.
package validate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

type evidence struct {
	Addresses []string `json:"addresses"`
	Signals   []signal `json:"signals"`
	Source    string   `json:"source"`
	Key       string   `json:"key"`
}

type signal struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type element struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Provider   string   `json:"provider"`
	Provenance string   `json:"provenance"`
	Evidence   evidence `json:"evidence"`
}

type boundary struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind"`
	Inside  []string `json:"inside"`
	Outside []string `json:"outside"`
}

type flow struct {
	ID         string   `json:"id"`
	From       string   `json:"from"`
	To         string   `json:"to"`
	DataClass  string   `json:"data_class"`
	Boundaries []string `json:"boundaries"`
}

type document struct {
	Elements        []element  `json:"elements"`
	TrustBoundaries []boundary `json:"trust_boundaries"`
	Flows           []flow     `json:"flows"`
}

// Error is a validation failure. Detail may name values for the caller;
// Class and Pointer are safe to log (T22).
type Error struct {
	Class   string // "schema" or "semantic"
	Pointer string // JSON pointer into the instance, e.g. "/elements/0"
	Detail  string // full message for the HTTP response
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Detail
}

// LogSafe returns the error class and JSON pointer for logging.
// It never returns payload fragments from schema diagnostics.
func LogSafe(err error) (class, pointer string) {
	var ve *Error
	if errors.As(err, &ve) && ve != nil {
		return ve.Class, ve.Pointer
	}
	return "unknown", ""
}

// DFD validates raw against schema, then runs semantic checks.
func DFD(schema *jsonschema.Schema, raw []byte) error {
	if err := Schema(schema, raw); err != nil {
		return err
	}
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return &Error{Class: "schema", Pointer: "", Detail: "invalid json"}
	}
	return Semantic(doc)
}

// Schema validates raw against JSON Schema only.
func Schema(schema *jsonschema.Schema, raw []byte) error {
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		return &Error{Class: "schema", Pointer: "", Detail: "invalid json"}
	}
	if err := schema.Validate(inst); err != nil {
		return schemaError(raw, err)
	}
	return nil
}

// Compile loads a JSON Schema from path.
func Compile(schemaPath string) (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	return compiler.Compile(schemaPath)
}

// CompileBytes loads a JSON Schema from in-memory JSON.
func CompileBytes(schemaPath string, raw []byte) (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}
	if err := compiler.AddResource(schemaPath, inst); err != nil {
		return nil, err
	}
	return compiler.Compile(schemaPath)
}

// Semantic checks id uniqueness, references, boundary sides, and derived
// element/boundary ids. Flow ids are not re-derived from data_class: an
// annotation may change data_class without moving the identity key
// (docs/schema/dfd.md).
func Semantic(doc document) error {
	var problems []string
	var firstPtr string
	set := func(ptr, msg string) {
		if firstPtr == "" {
			firstPtr = ptr
		}
		problems = append(problems, msg)
	}

	elements := map[string]element{}
	for i, el := range doc.Elements {
		ptr := fmt.Sprintf("/elements/%d", i)
		if _, ok := elements[el.ID]; ok {
			set(ptr, "duplicate element id "+el.ID)
			continue
		}
		elements[el.ID] = el
		want, err := elementID(el)
		if err != nil {
			set(ptr, err.Error())
			continue
		}
		if el.ID != want {
			set(ptr+"/id", "element "+el.ID+" derived id is "+want)
		}
	}

	boundaries := map[string]boundary{}
	for i, b := range doc.TrustBoundaries {
		ptr := fmt.Sprintf("/trust_boundaries/%d", i)
		if _, ok := boundaries[b.ID]; ok {
			set(ptr, "duplicate boundary id "+b.ID)
		}
		boundaries[b.ID] = b
		for _, id := range append(append([]string{}, b.Inside...), b.Outside...) {
			if _, ok := elements[id]; !ok {
				set(ptr, "boundary "+b.ID+" references unknown element "+id)
			}
		}
		if overlap(b.Inside, b.Outside) {
			set(ptr, "boundary "+b.ID+" lists an element on both sides")
		}
		if want := boundaryID(b); b.ID != want {
			set(ptr+"/id", "boundary "+b.ID+" derived id is "+want)
		}
	}

	seenFlow := map[string]bool{}
	for i, f := range doc.Flows {
		ptr := fmt.Sprintf("/flows/%d", i)
		if seenFlow[f.ID] {
			set(ptr, "duplicate flow id "+f.ID)
		}
		seenFlow[f.ID] = true
		if _, ok := elements[f.From]; !ok {
			set(ptr+"/from", "flow "+f.ID+" from unknown element "+f.From)
		}
		if _, ok := elements[f.To]; !ok {
			set(ptr+"/to", "flow "+f.ID+" to unknown element "+f.To)
		}
		if !strings.HasPrefix(f.ID, "f") || len(f.ID) != 17 {
			set(ptr+"/id", "flow "+f.ID+" has a malformed id")
		}
		for _, bid := range f.Boundaries {
			b, ok := boundaries[bid]
			if !ok {
				set(ptr+"/boundaries", "flow "+f.ID+" references unknown boundary "+bid)
				continue
			}
			fromIn, fromOut := side(b, f.From)
			toIn, toOut := side(b, f.To)
			if !((fromIn && toOut) || (fromOut && toIn)) {
				set(ptr+"/boundaries", "flow "+f.ID+" does not cross "+bid+" with one endpoint on each side")
			}
		}
	}
	if len(problems) > 0 {
		return &Error{
			Class:   "semantic",
			Pointer: firstPtr,
			Detail:  strings.Join(problems, "\n"),
		}
	}
	return nil
}

func schemaError(raw []byte, err error) *Error {
	ptr, keyword := schemaLocation(err)
	detail := explainSchema(raw, err)
	class := "schema"
	if keyword != "" {
		class = "schema:" + keyword
	}
	return &Error{Class: class, Pointer: ptr, Detail: detail}
}

func schemaLocation(err error) (pointer, keyword string) {
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) || ve == nil {
		return "", ""
	}
	leaf := deepest(ve)
	pointer = "/" + strings.Join(leaf.InstanceLocation, "/")
	if pointer == "/" {
		pointer = ""
	}
	if leaf.ErrorKind != nil {
		path := leaf.ErrorKind.KeywordPath()
		if len(path) > 0 {
			keyword = path[len(path)-1]
		}
	}
	return pointer, keyword
}

func deepest(ve *jsonschema.ValidationError) *jsonschema.ValidationError {
	for len(ve.Causes) > 0 {
		ve = ve.Causes[0]
	}
	return ve
}

func elementID(el element) (string, error) {
	var key string
	switch el.Provenance {
	case "iac":
		addrs := slices.Clone(el.Evidence.Addresses)
		slices.Sort(addrs)
		key = strings.Join(addrs, "\n")
	case "declared":
		key = "declared:" + el.Evidence.Key
	case "inferred":
		sigs := make([]string, len(el.Evidence.Signals))
		for i, s := range el.Evidence.Signals {
			sigs[i] = s.Type + ":" + s.Name
		}
		slices.Sort(sigs)
		key = "inferred:" + strings.Join(sigs, "\n")
	default:
		return "", fmt.Errorf("element %s has unknown provenance %q", el.ID, el.Provenance)
	}
	return digest("e", key), nil
}

func boundaryID(b boundary) string {
	inside := slices.Clone(b.Inside)
	outside := slices.Clone(b.Outside)
	slices.Sort(inside)
	slices.Sort(outside)
	return digest("b", b.Kind+"\n"+strings.Join(inside, ",")+"\n"+strings.Join(outside, ","))
}

func digest(prefix, key string) string {
	sum := sha256.Sum256([]byte(key))
	return prefix + hex.EncodeToString(sum[:])[:16]
}

func side(b boundary, id string) (inside, outside bool) {
	return slices.Contains(b.Inside, id), slices.Contains(b.Outside, id)
}

func overlap(a, b []string) bool {
	for _, id := range a {
		if slices.Contains(b, id) {
			return true
		}
	}
	return false
}

func explainSchema(raw []byte, err error) string {
	if !strings.Contains(err.Error(), "'not' failed") {
		return err.Error()
	}
	url, eq := false, false
	var walk func(any)
	walk = func(n any) {
		switch t := n.(type) {
		case string:
			if strings.Contains(t, "://") {
				url = true
			}
			if strings.Contains(t, "=") {
				eq = true
			}
		case map[string]any:
			for _, child := range t {
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		}
	}
	var doc any
	if json.Unmarshal(raw, &doc) == nil {
		walk(doc)
	}
	var notes []string
	if url {
		notes = append(notes, `a string contains "://"`)
	}
	if eq {
		notes = append(notes, `a string contains "="`)
	}
	if len(notes) == 0 {
		return err.Error()
	}
	return strings.Join(notes, "\n") + "\n" + err.Error()
}
