package client

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// containerSpec is the image and secret references of one container.
// Environment values are never read.
type containerSpec struct {
	image   string
	imageOK bool
	secrets []string
}

// readRootContainers reads image and secrets from root module calls.
// The plan's container_definitions value is often unknown, and its reference
// list mixes secret ARNs with environment values. Child modules are not read.
func readRootContainers(moduleDir string) (map[string][]containerSpec, error) {
	if moduleDir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(moduleDir)
	if err != nil {
		return nil, err
	}
	out := map[string][]containerSpec{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tf") {
			continue
		}
		path := filepath.Join(moduleDir, entry.Name())
		src, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		file, diags := hclsyntax.ParseConfig(src, path, hcl.InitialPos)
		if diags.HasErrors() {
			return nil, fmt.Errorf("%s: %s", path, diags.Error())
		}
		body, ok := file.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for _, block := range body.Blocks {
			if block.Type != "module" || len(block.Labels) != 1 {
				continue
			}
			attr, ok := block.Body.Attributes["container_definitions"]
			if !ok {
				continue
			}
			// Module-call path: object/map form only (pre-B-49).
			specs, ok := parseContainersObject(attr.Expr)
			if !ok {
				continue
			}
			out["module."+block.Labels[0]] = specs
		}
	}
	return out, nil
}

// readRootTaskDefinitionContainers reads container_definitions from root-module
// aws_ecs_task_definition resource blocks. Used when the plan value is unknown
// (secret/resource created in the same plan). Blocks with count/for_each, or
// duplicate names across .tf files, are omitted. Child-module source files are
// not read.
func readRootTaskDefinitionContainers(moduleDir string) (map[string][]containerSpec, error) {
	if moduleDir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(moduleDir)
	if err != nil {
		return nil, err
	}
	out := map[string][]containerSpec{}
	seen := map[string]bool{}
	dup := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tf") {
			continue
		}
		path := filepath.Join(moduleDir, entry.Name())
		src, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		file, diags := hclsyntax.ParseConfig(src, path, hcl.InitialPos)
		if diags.HasErrors() {
			return nil, fmt.Errorf("%s: %s", path, diags.Error())
		}
		body, ok := file.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for _, block := range body.Blocks {
			if block.Type != "resource" || len(block.Labels) != 2 {
				continue
			}
			if block.Labels[0] != "aws_ecs_task_definition" {
				continue
			}
			name := block.Labels[1]
			if seen[name] {
				dup[name] = true
				delete(out, name)
				continue
			}
			seen[name] = true
			if dup[name] {
				continue
			}
			if _, hasCount := block.Body.Attributes["count"]; hasCount {
				continue
			}
			if _, hasForEach := block.Body.Attributes["for_each"]; hasForEach {
				continue
			}
			attr, ok := block.Body.Attributes["container_definitions"]
			if !ok {
				continue
			}
			// Root resource path: object/map, jsonencode([{...}]), or bare [{...}].
			specs, ok := containersFromRootExpr(attr.Expr)
			if !ok {
				continue
			}
			out[name] = specs
		}
	}
	return out, nil
}

// containersFromRootExpr turns a root-module aws_ecs_task_definition
// container_definitions expression into specs. Accepts object/map form,
// jsonencode([{...}]), and bare [{...}]. local/var/file()/templatefile() omit.
func containersFromRootExpr(expr hclsyntax.Expression) ([]containerSpec, bool) {
	if call, ok := expr.(*hclsyntax.FunctionCallExpr); ok {
		if call.Name != "jsonencode" || len(call.Args) != 1 {
			return nil, false
		}
		expr = call.Args[0]
	}
	if tup, ok := expr.(*hclsyntax.TupleConsExpr); ok {
		var out []containerSpec
		for _, item := range tup.Exprs {
			obj, ok := item.(*hclsyntax.ObjectConsExpr)
			if !ok {
				return nil, false
			}
			spec, ok := oneContainer(obj)
			if !ok {
				return nil, false
			}
			out = append(out, spec)
		}
		return out, len(out) > 0
	}
	return parseContainersObject(expr)
}

// parseContainersObject handles the module-call object/map form only:
// { image = ... } or { app = { image = ... }, ... }.
func parseContainersObject(expr hclsyntax.Expression) ([]containerSpec, bool) {
	obj, ok := expr.(*hclsyntax.ObjectConsExpr)
	if !ok {
		return nil, false
	}
	if containerObject(obj) {
		spec, ok := oneContainer(obj)
		if !ok {
			return nil, false
		}
		return []containerSpec{spec}, true
	}
	var out []containerSpec
	for _, item := range obj.Items {
		inner, ok := item.ValueExpr.(*hclsyntax.ObjectConsExpr)
		if !ok {
			return nil, false
		}
		spec, ok := oneContainer(inner)
		if !ok {
			return nil, false
		}
		out = append(out, spec)
	}
	return out, len(out) > 0
}

func containerObject(obj *hclsyntax.ObjectConsExpr) bool {
	for _, item := range obj.Items {
		name, ok := attrName(item.KeyExpr)
		if ok && (name == "image" || name == "secrets" || name == "essential") {
			return true
		}
	}
	return false
}

func oneContainer(obj *hclsyntax.ObjectConsExpr) (containerSpec, bool) {
	var spec containerSpec
	for _, item := range obj.Items {
		name, ok := attrName(item.KeyExpr)
		if !ok {
			continue
		}
		switch name {
		case "image":
			if s, ok := literalString(item.ValueExpr); ok {
				spec.image = s
				spec.imageOK = true
			}
		case "secrets":
			spec.secrets = secretRefs(item.ValueExpr)
		}
	}
	return spec, true
}

func secretRefs(expr hclsyntax.Expression) []string {
	tup, ok := expr.(*hclsyntax.TupleConsExpr)
	if !ok {
		return nil
	}
	var refs []string
	for _, item := range tup.Exprs {
		obj, ok := item.(*hclsyntax.ObjectConsExpr)
		if !ok {
			continue
		}
		for _, field := range obj.Items {
			name, ok := attrName(field.KeyExpr)
			if !ok || name != "valueFrom" {
				continue
			}
			if ref, ok := exprRef(field.ValueExpr); ok {
				refs = append(refs, ref)
			}
		}
	}
	return refs
}

func attrName(expr hclsyntax.Expression) (string, bool) {
	if key, ok := expr.(*hclsyntax.ObjectConsKeyExpr); ok {
		if s := hcl.ExprAsKeyword(key.Wrapped); s != "" {
			return s, true
		}
	}
	if s := hcl.ExprAsKeyword(expr); s != "" {
		return s, true
	}
	return literalString(expr)
}

func literalString(expr hclsyntax.Expression) (string, bool) {
	val, diags := expr.Value(nil)
	if diags.HasErrors() || !val.IsKnown() || val.Type() != cty.String {
		return "", false
	}
	return val.AsString(), true
}

func exprRef(expr hclsyntax.Expression) (string, bool) {
	vars := expr.Variables()
	if len(vars) != 1 {
		return "", false
	}
	var b strings.Builder
	for i, step := range vars[0] {
		switch s := step.(type) {
		case hcl.TraverseRoot:
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteString(s.Name)
		case hcl.TraverseAttr:
			b.WriteByte('.')
			b.WriteString(s.Name)
		default:
			return "", false
		}
	}
	if b.Len() == 0 {
		return "", false
	}
	return b.String(), true
}
