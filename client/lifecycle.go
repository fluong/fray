package client

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// preventIndex maps a resource block (module address, type, name) to whether
// its lifecycle.prevent_destroy is the literal true. count and for_each
// instances share the block, so the key has no instance index.
type preventIndex map[string]bool

func (idx preventIndex) protected(address string) bool {
	if idx == nil {
		return false
	}
	moduleAddr, typ, name, ok := splitResourceAddress(address)
	if !ok {
		return false
	}
	return idx[blockKey(moduleAddr, typ, name)]
}

func blockKey(moduleAddr, typ, name string) string {
	return moduleAddr + "\n" + typ + "\n" + name
}

// readPreventDestroy reads only lifecycle.prevent_destroy from HCL. Other
// expressions stay unread: the plan is the source of truth for values.
// moduleDir is the root module. An empty dir skips the read. Child modules
// downloaded by terraform init are included through .terraform/modules/modules.json.
func readPreventDestroy(moduleDir string) (preventIndex, error) {
	if moduleDir == "" {
		return nil, nil
	}
	dirs, err := moduleDirs(moduleDir)
	if err != nil {
		return nil, err
	}
	idx := preventIndex{}
	for _, mod := range dirs {
		if err := indexModule(idx, mod.addr, mod.dir); err != nil {
			return nil, err
		}
	}
	return idx, nil
}

type moduleDir struct {
	addr string
	dir  string
}

type modulesManifest struct {
	Modules []struct {
		Key string `json:"Key"`
		Dir string `json:"Dir"`
	} `json:"Modules"`
}

func moduleDirs(root string) ([]moduleDir, error) {
	path := filepath.Join(root, ".terraform", "modules", "modules.json")
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return []moduleDir{{addr: "", dir: root}}, nil
	}
	if err != nil {
		return nil, err
	}
	var manifest modulesManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("modules.json: %w", err)
	}
	if len(manifest.Modules) == 0 {
		return []moduleDir{{addr: "", dir: root}}, nil
	}
	out := make([]moduleDir, 0, len(manifest.Modules))
	for _, rec := range manifest.Modules {
		dir := filepath.FromSlash(rec.Dir)
		if dir == "" {
			dir = "."
		}
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(root, dir)
		}
		out = append(out, moduleDir{addr: moduleAddress(rec.Key), dir: dir})
	}
	return out, nil
}

// moduleAddress turns a modules.json key into a Terraform module address.
// "foo.bar" is module.foo.module.bar. The root key is empty.
func moduleAddress(key string) string {
	if key == "" {
		return ""
	}
	parts := strings.Split(key, ".")
	for i, p := range parts {
		parts[i] = "module." + p
	}
	return strings.Join(parts, ".")
}

func indexModule(idx preventIndex, moduleAddr, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("module %q: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tf") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		file, diags := hclsyntax.ParseConfig(src, path, hcl.InitialPos)
		if diags.HasErrors() {
			return fmt.Errorf("%s: %s", path, diags.Error())
		}
		body, ok := file.Body.(*hclsyntax.Body)
		if !ok {
			return fmt.Errorf("%s: unexpected HCL body", path)
		}
		for _, block := range body.Blocks {
			if block.Type != "resource" || len(block.Labels) != 2 {
				continue
			}
			prevent, err := literalPreventDestroy(block)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			key := blockKey(moduleAddr, block.Labels[0], block.Labels[1])
			if _, exists := idx[key]; exists {
				return fmt.Errorf("%s: duplicate resource %s.%s", path, block.Labels[0], block.Labels[1])
			}
			idx[key] = prevent
		}
	}
	return nil
}

// literalPreventDestroy reports whether lifecycle.prevent_destroy is the
// literal true. A non-literal expression is left unread.
func literalPreventDestroy(block *hclsyntax.Block) (bool, error) {
	for _, nested := range block.Body.Blocks {
		if nested.Type != "lifecycle" {
			continue
		}
		attr, ok := nested.Body.Attributes["prevent_destroy"]
		if !ok {
			return false, nil
		}
		lit, ok := attr.Expr.(*hclsyntax.LiteralValueExpr)
		if !ok {
			return false, nil
		}
		if lit.Val.Type() != cty.Bool {
			return false, fmt.Errorf("lifecycle.prevent_destroy on %s.%s is not a bool", block.Labels[0], block.Labels[1])
		}
		return lit.Val.True(), nil
	}
	return false, nil
}

// SourceLocation is the resource block in the Terraform module.
type SourceLocation struct {
	Path string
	Line int
}

func (s SourceLocation) String() string {
	if s.Line == 0 {
		return s.Path
	}
	return fmt.Sprintf("%s:%d", s.Path, s.Line)
}

// ResourceLocations maps a resource address, without a count or for_each
// index, to the HCL block that declares it. The path is the module directory
// name plus the file, such as infra/main.tf.
func ResourceLocations(moduleDir string) (map[string]SourceLocation, error) {
	if moduleDir == "" {
		return nil, nil
	}
	dirs, err := moduleDirs(moduleDir)
	if err != nil {
		return nil, err
	}
	out := map[string]SourceLocation{}
	for _, mod := range dirs {
		if err := indexLocations(out, moduleDir, mod.addr, mod.dir); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func indexLocations(out map[string]SourceLocation, root, moduleAddr, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("module %q: %w", dir, err)
	}
	vendored := isVendoredPath(root, dir)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tf") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		file, diags := hclsyntax.ParseConfig(src, path, hcl.InitialPos)
		if diags.HasErrors() {
			return fmt.Errorf("%s: %s", path, diags.Error())
		}
		body, ok := file.Body.(*hclsyntax.Body)
		if !ok {
			return fmt.Errorf("%s: unexpected HCL body", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = filepath.Base(path)
		}
		display := filepath.ToSlash(filepath.Join(filepath.Base(root), rel))
		for _, block := range body.Blocks {
			switch {
			case block.Type == "module" && len(block.Labels) == 1:
				call := moduleCallKey(moduleAddr, block.Labels[0])
				line := block.DefRange().Start.Line
				if line == 0 {
					line = block.TypeRange.Start.Line
				}
				out[call] = SourceLocation{Path: display, Line: line}
				if block.Body != nil {
					for name, attr := range block.Body.Attributes {
						argLine := attr.Expr.Range().Start.Line
						if argLine == 0 {
							argLine = attr.NameRange.Start.Line
						}
						out[call+"."+name] = SourceLocation{Path: display, Line: argLine}
					}
				}
			case !vendored && (block.Type == "resource" || block.Type == "data") && len(block.Labels) == 2:
				typ := block.Labels[0]
				if block.Type == "data" {
					typ = "data." + typ
				}
				addr := resourceAddress(moduleAddr, typ, block.Labels[1])
				line := block.DefRange().Start.Line
				if line == 0 {
					line = block.TypeRange.Start.Line
				}
				out[addr] = SourceLocation{Path: display, Line: line}
			}
		}
	}
	return nil
}

func isVendoredPath(root, dir string) bool {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		rel = dir
	}
	return strings.Contains(filepath.ToSlash(rel), ".terraform/modules/")
}

func moduleCallKey(parentModuleAddr, name string) string {
	if parentModuleAddr == "" {
		return "module." + name
	}
	return parentModuleAddr + ".module." + name
}

func resourceAddress(moduleAddr, typ, name string) string {
	if moduleAddr == "" {
		return typ + "." + name
	}
	return moduleAddr + "." + typ + "." + name
}

// LookupLocation strips a count or for_each index and returns the block location.
// Nested module resources resolve to the root module call site, never a path
// under .terraform/modules.
func LookupLocation(idx map[string]SourceLocation, address string) (SourceLocation, bool) {
	return LookupCauseLocation(idx, address, "")
}

// LookupCauseLocation is LookupLocation, and when field is set it prefers the
// module input argument that typically controls that attribute.
func LookupCauseLocation(idx map[string]SourceLocation, address, field string) (SourceLocation, bool) {
	if mc, ok := LookupModuleCause(idx, address, field); ok {
		return mc.Location, true
	}
	moduleAddr, typ, name, ok := splitResourceAddress(address)
	if !ok {
		return SourceLocation{}, false
	}
	loc, ok := idx[resourceAddress(moduleAddr, typ, name)]
	if !ok || strings.Contains(loc.Path, ".terraform/modules/") {
		return SourceLocation{}, false
	}
	return loc, true
}

// ModuleCause is the root module call that owns a nested resource, with the
// input arguments that typically control the failed field.
type ModuleCause struct {
	Call     string // module.uploads
	Inputs   []string
	Location SourceLocation // module call site (not an input line)
}

// LookupModuleCause resolves a nested module address to its root module call.
func LookupModuleCause(idx map[string]SourceLocation, address, field string) (ModuleCause, bool) {
	if idx == nil {
		return ModuleCause{}, false
	}
	call, ok := rootModuleCall(address)
	if !ok {
		return ModuleCause{}, false
	}
	loc, ok := idx[call]
	if !ok {
		return ModuleCause{}, false
	}
	var inputs []string
	for _, arg := range moduleArgHints(field) {
		if _, hit := idx[call+"."+arg]; hit {
			inputs = append(inputs, arg)
			// Secret scope is usually one widening input; prefer the first hit
			// in hint priority (task_exec_iam_statements before secret_arns).
			if strings.TrimPrefix(field, "attributes.") == "authz_scope" {
				break
			}
		}
	}
	return ModuleCause{Call: call, Inputs: inputs, Location: loc}, true
}

func rootModuleCall(address string) (string, bool) {
	if !strings.HasPrefix(address, "module.") {
		return "", false
	}
	rest := strings.TrimPrefix(address, "module.")
	i := 0
	for i < len(rest) && rest[i] != '.' && rest[i] != '[' {
		i++
	}
	if i == 0 {
		return "", false
	}
	return "module." + rest[:i], true
}

func moduleArgHints(field string) []string {
	field = strings.TrimPrefix(field, "attributes.")
	switch field {
	case "public_access_blocked", "public":
		return []string{
			"block_public_acls",
			"block_public_policy",
			"ignore_public_acls",
			"restrict_public_buckets",
			"public_access_prevention",
		}
	case "authz_scope":
		return []string{
			"task_exec_iam_statements",
			"task_exec_secret_arns",
			"task_exec_ssm_param_arns",
		}
	default:
		return nil
	}
}

// splitResourceAddress strips count and for_each indexes. The module address
// uses the module call path, not the instance key.
func splitResourceAddress(addr string) (moduleAddr, typ, name string, ok bool) {
	rest := addr
	var mods []string
	for strings.HasPrefix(rest, "module.") {
		rest = strings.TrimPrefix(rest, "module.")
		i := 0
		for i < len(rest) && rest[i] != '.' && rest[i] != '[' {
			i++
		}
		if i == 0 {
			return "", "", "", false
		}
		mods = append(mods, rest[:i])
		rest = rest[i:]
		if strings.HasPrefix(rest, "[") {
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				return "", "", "", false
			}
			rest = rest[end+1:]
		}
		if strings.HasPrefix(rest, ".") {
			rest = rest[1:]
		} else if rest != "" {
			return "", "", "", false
		}
	}
	data := false
	if strings.HasPrefix(rest, "data.") {
		data = true
		rest = strings.TrimPrefix(rest, "data.")
	}
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 || dot == len(rest)-1 {
		return "", "", "", false
	}
	typ = rest[:dot]
	name = rest[dot+1:]
	if i := strings.IndexByte(name, '['); i >= 0 {
		name = name[:i]
	}
	if name == "" || strings.Contains(typ, "[") {
		return "", "", "", false
	}
	if data {
		typ = "data." + typ
	}
	if len(mods) > 0 {
		parts := make([]string, len(mods))
		for i, m := range mods {
			parts[i] = "module." + m
		}
		moduleAddr = strings.Join(parts, ".")
	}
	return moduleAddr, typ, name, true
}
