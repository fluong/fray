package client

import (
	"bytes"
	"encoding/json"
	"strings"
)

// StripSensitive blanks every value the plan marks sensitive, then blanks any
// other string equal to one of those values. Terraform keeps the mark in a
// sibling field and leaves the value in plaintext.
func StripSensitive(plan []byte) ([]byte, []string, error) {
	var root any
	dec := json.NewDecoder(bytes.NewReader(plan))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, nil, err
	}
	var secrets []string
	walkPairs(root, &secrets)
	if len(secrets) > 0 {
		blankEquals(root, secrets)
	}
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return append(out, '\n'), secrets, nil
}

func walkPairs(node any, secrets *[]string) {
	switch n := node.(type) {
	case map[string]any:
		for _, pair := range [][2]string{
			{"after", "after_sensitive"},
			{"before", "before_sensitive"},
			{"values", "sensitive_values"},
		} {
			if mark, ok := n[pair[1]]; ok {
				if val, ok := n[pair[0]]; ok {
					n[pair[0]] = blankMarked(val, mark, secrets)
				}
			}
		}
		if sens, ok := n["sensitive"].(bool); ok && sens {
			if s, ok := n["value"].(string); ok && s != "" {
				*secrets = append(*secrets, s)
				n["value"] = ""
			}
		}
		for _, v := range n {
			walkPairs(v, secrets)
		}
	case []any:
		for _, v := range n {
			walkPairs(v, secrets)
		}
	}
}

func blankMarked(val, mark any, secrets *[]string) any {
	if mark == true {
		if s, ok := val.(string); ok && s != "" {
			*secrets = append(*secrets, s)
		}
		return ""
	}
	switch m := mark.(type) {
	case map[string]any:
		vm, ok := val.(map[string]any)
		if !ok {
			return val
		}
		for k, mv := range m {
			if cur, exists := vm[k]; exists {
				vm[k] = blankMarked(cur, mv, secrets)
			}
		}
		return vm
	case []any:
		vs, ok := val.([]any)
		if !ok {
			return val
		}
		for i, mv := range m {
			if i < len(vs) {
				vs[i] = blankMarked(vs[i], mv, secrets)
			}
		}
		return vs
	default:
		return val
	}
}

func blankEquals(node any, secrets []string) {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if s, ok := v.(string); ok && containsSecret(s, secrets) {
				n[k] = ""
				continue
			}
			blankEquals(v, secrets)
		}
	case []any:
		for i, v := range n {
			if s, ok := v.(string); ok && containsSecret(s, secrets) {
				n[i] = ""
				continue
			}
			blankEquals(v, secrets)
		}
	}
}

func containsSecret(s string, secrets []string) bool {
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if s == secret || (len(secret) >= 8 && strings.Contains(s, secret)) {
			return true
		}
	}
	return false
}
