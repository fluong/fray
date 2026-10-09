package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
	"github.com/fluong/fray/render"
	frayschema "github.com/fluong/fray/schema"
	"github.com/fluong/fray/schema/validate"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

const (
	maxWaiversFileBytes = 64 * 1024
	maxWaiverHorizonDays = 365
	waiverMigrationMsg  = "mitigations.yaml is no longer supported; migrate to .fray/waivers.yml — copy each entry, add id/owner/expires, drop status: accepted (see README#waivers)"
)

type waiverFile struct {
	Version int           `yaml:"version" json:"version"`
	Waivers []waiverEntry `yaml:"waivers" json:"waivers"`
}

type waiverEntry struct {
	ID      string `yaml:"id" json:"id"`
	Rule    string `yaml:"rule" json:"rule"`
	Address string `yaml:"address" json:"address"`
	Reason  string `yaml:"reason" json:"reason"`
	Owner   string `yaml:"owner" json:"owner"`
	Expires string `yaml:"expires" json:"expires"`
}

var waiversSchema *jsonschema.Schema

func init() {
	s, err := validate.CompileBytes("waivers.schema.json", frayschema.WaiversSchemaJSON)
	if err != nil {
		panic("compile waivers schema: " + err.Error())
	}
	waiversSchema = s
}

// loadWaivers reads path. Missing file → empty list. Validates size, JSON Schema,
// unique ids, real calendar dates, and expires ≤ today+365 (UTC).
func loadWaivers(path string, now time.Time) ([]waiverEntry, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if len(raw) > maxWaiversFileBytes {
		return nil, fmt.Errorf("%s: file exceeds 64 KiB (%d bytes)", path, len(raw))
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("%s: empty file", path)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	doc := &root
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		doc = root.Content[0]
	}

	jsonBytes, err := yamlNodeToJSON(doc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := validate.Schema(waiversSchema, jsonBytes); err != nil {
		return nil, fmt.Errorf("%s: %s", path, formatSchemaErr(err, doc))
	}

	var file waiverFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	today := dateUTC(now)
	maxExp := today.AddDate(0, 0, maxWaiverHorizonDays)
	seen := map[string]int{} // id → 1-based index
	for i, w := range file.Waivers {
		line := waiverLine(doc, i)
		if prev, ok := seen[w.ID]; ok {
			return nil, fmt.Errorf("%s:%d: waiver %q: duplicate id (first at entry %d)", path, line, w.ID, prev)
		}
		seen[w.ID] = i + 1
		exp, err := time.ParseInLocation("2006-01-02", w.Expires, time.UTC)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: waiver %q: expires must be a valid YYYY-MM-DD date", path, line, w.ID)
		}
		exp = dateUTC(exp)
		// Reject impossible calendar leftovers from pattern-only match (e.g. 2026-02-30).
		if exp.Format("2006-01-02") != w.Expires {
			return nil, fmt.Errorf("%s:%d: waiver %q: expires must be a valid YYYY-MM-DD date", path, line, w.ID)
		}
		if exp.After(maxExp) {
			return nil, fmt.Errorf("%s:%d: waiver %q: expires beyond 365 days from today (UTC)", path, line, w.ID)
		}
	}
	return file.Waivers, nil
}

// checkLegacyMitigations enforces the hard cutover from mitigations.yaml.
// Non-empty legacy + any waivers → error. Non-empty legacy alone → migration message.
// Empty or missing legacy file → nil.
func checkLegacyMitigations(mitigationsPath string, waiverCount int) error {
	if mitigationsPath == "" {
		return nil
	}
	entries, err := loadMitigations(mitigationsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	if waiverCount > 0 {
		return fmt.Errorf("both mitigations.yaml and .fray/waivers.yml have entries; keep only .fray/waivers.yml")
	}
	return errors.New(waiverMigrationMsg)
}

func resolveWaivers(doc client.DFD, entries []waiverEntry) ([]apiv1.Accepted, error) {
	out := make([]apiv1.Accepted, 0, len(entries))
	for _, e := range entries {
		id := render.ResolveAddress(doc, e.Address)
		if id == "" {
			return nil, fmt.Errorf("waiver %q: address %q not found", e.ID, e.Address)
		}
		out = append(out, apiv1.Accepted{
			RuleID:   e.Rule,
			TargetID: id,
			ID:       e.ID,
			Expires:  e.Expires,
		})
	}
	return out, nil
}

func toRenderWaiverEntries(entries []waiverEntry) []render.MitigationEntry {
	out := make([]render.MitigationEntry, len(entries))
	for i, e := range entries {
		out[i] = render.MitigationEntry{
			RuleID: e.Rule, Address: e.Address, Status: "waived",
			Reason: e.Reason, Revisit: e.Expires,
		}
	}
	return out
}

func dateUTC(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}

func yamlNodeToJSON(n *yaml.Node) ([]byte, error) {
	var v any
	if err := n.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func formatSchemaErr(err error, doc *yaml.Node) string {
	var ve *validate.Error
	if errors.As(err, &ve) && ve != nil {
		line := pointerLine(doc, ve.Pointer)
		if line > 0 {
			return fmt.Sprintf("line %d: %s", line, ve.Detail)
		}
		if ve.Pointer != "" {
			return fmt.Sprintf("%s: %s", ve.Pointer, ve.Detail)
		}
		return ve.Detail
	}
	return err.Error()
}

func waiverLine(doc *yaml.Node, index int) int {
	waivers := mapValue(doc, "waivers")
	if waivers == nil || waivers.Kind != yaml.SequenceNode {
		return 1
	}
	if index < 0 || index >= len(waivers.Content) {
		return 1
	}
	return waivers.Content[index].Line
}

func pointerLine(doc *yaml.Node, pointer string) int {
	if doc == nil || pointer == "" {
		return 0
	}
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	n := doc
	for _, p := range parts {
		if p == "" {
			continue
		}
		switch n.Kind {
		case yaml.MappingNode:
			n = mapValue(n, p)
			if n == nil {
				return 0
			}
		case yaml.SequenceNode:
			var idx int
			if _, err := fmt.Sscanf(p, "%d", &idx); err != nil || idx < 0 || idx >= len(n.Content) {
				return 0
			}
			n = n.Content[idx]
		default:
			return 0
		}
	}
	return n.Line
}

func mapValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
