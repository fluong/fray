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

// iamPolicyHCLIndex maps policy holder addresses in the root module to a
// literal jsonencode({...}) policy parsed from .tf source. Keys are
// aws_iam_role_policy.*, aws_iam_policy.*, or
// aws_iam_role.*#inline_policy.<name>.
type iamPolicyHCLIndex map[string]iamHCLPolicy

type iamHCLPolicy struct {
	version    string
	statements []iamHCLStatement
}

type iamHCLStatement struct {
	effect    string
	actions   []string
	resources []iamHCLResourcePattern
	condition map[string]any
}

type iamHCLResourcePattern struct {
	parts []iamHCLResourcePart
}

type iamHCLResourcePart struct {
	literal string
	ref     string // type.name.attr when set
}

func readRootIAMPolicyLiterals(moduleDir string) (iamPolicyHCLIndex, error) {
	if moduleDir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(moduleDir)
	if err != nil {
		return nil, err
	}
	out := iamPolicyHCLIndex{}
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
			typ, name := block.Labels[0], block.Labels[1]
			addr := typ + "." + name
			if _, hasCount := block.Body.Attributes["count"]; hasCount {
				continue
			}
			if _, hasForEach := block.Body.Attributes["for_each"]; hasForEach {
				continue
			}
			switch typ {
			case "aws_iam_role_policy", "aws_iam_policy":
				if dup[addr] || seen[addr] {
					dup[addr] = true
					delete(out, addr)
					continue
				}
				seen[addr] = true
				attr, ok := block.Body.Attributes["policy"]
				if !ok {
					continue
				}
				pol, ok := parseIAMJSONEncodePolicy(attr.Expr)
				if !ok {
					continue
				}
				out[addr] = pol
			case "aws_iam_role":
				if dup[addr] {
					continue
				}
				for _, ib := range block.Body.Blocks {
					if ib.Type != "inline_policy" {
						continue
					}
					if ib.Body == nil {
						continue
					}
					nameAttr, ok := ib.Body.Attributes["name"]
					if !ok {
						continue
					}
					inlineName, ok := literalString(nameAttr.Expr)
					if !ok || inlineName == "" {
						continue
					}
					polAttr, ok := ib.Body.Attributes["policy"]
					if !ok {
						continue
					}
					key := addr + "#inline_policy." + inlineName
					if seen[key] {
						dup[key] = true
						delete(out, key)
						continue
					}
					seen[key] = true
					pol, ok := parseIAMJSONEncodePolicy(polAttr.Expr)
					if !ok {
						continue
					}
					out[key] = pol
				}
			}
		}
	}
	for k := range dup {
		delete(out, k)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func parseIAMJSONEncodePolicy(expr hclsyntax.Expression) (iamHCLPolicy, bool) {
	call, ok := expr.(*hclsyntax.FunctionCallExpr)
	if !ok || call.Name != "jsonencode" || len(call.Args) != 1 {
		return iamHCLPolicy{}, false
	}
	obj, ok := call.Args[0].(*hclsyntax.ObjectConsExpr)
	if !ok {
		return iamHCLPolicy{}, false
	}
	var pol iamHCLPolicy
	pol.version = "2012-10-17"
	for _, item := range obj.Items {
		key, ok := attrName(item.KeyExpr)
		if !ok {
			return iamHCLPolicy{}, false
		}
		switch key {
		case "Version", "version":
			v, ok := literalString(item.ValueExpr)
			if !ok {
				return iamHCLPolicy{}, false
			}
			pol.version = v
		case "Statement", "statement":
			stmts, ok := parseIAMHCLStatements(item.ValueExpr)
			if !ok {
				return iamHCLPolicy{}, false
			}
			pol.statements = stmts
		default:
			// Sid, Id, etc. — ignore like JSON path
		}
	}
	if len(pol.statements) == 0 {
		return iamHCLPolicy{}, false
	}
	return pol, true
}

func parseIAMHCLStatements(expr hclsyntax.Expression) ([]iamHCLStatement, bool) {
	if obj, ok := expr.(*hclsyntax.ObjectConsExpr); ok {
		st, ok := parseOneIAMHCLStatement(obj)
		if !ok {
			return nil, false
		}
		return []iamHCLStatement{st}, true
	}
	tup, ok := expr.(*hclsyntax.TupleConsExpr)
	if !ok {
		return nil, false
	}
	var out []iamHCLStatement
	for _, item := range tup.Exprs {
		obj, ok := item.(*hclsyntax.ObjectConsExpr)
		if !ok {
			return nil, false
		}
		st, ok := parseOneIAMHCLStatement(obj)
		if !ok {
			return nil, false
		}
		out = append(out, st)
	}
	return out, len(out) > 0
}

func parseOneIAMHCLStatement(obj *hclsyntax.ObjectConsExpr) (iamHCLStatement, bool) {
	var st iamHCLStatement
	for _, item := range obj.Items {
		key, ok := attrName(item.KeyExpr)
		if !ok {
			return iamHCLStatement{}, false
		}
		switch key {
		case "Effect", "effect":
			e, ok := literalString(item.ValueExpr)
			if !ok {
				return iamHCLStatement{}, false
			}
			st.effect = e
		case "Action", "action":
			acts, ok := literalStringListExpr(item.ValueExpr)
			if !ok || len(acts) == 0 {
				return iamHCLStatement{}, false
			}
			st.actions = acts
		case "Resource", "resource":
			res, ok := parseIAMHCLResources(item.ValueExpr)
			if !ok || len(res) == 0 {
				return iamHCLStatement{}, false
			}
			st.resources = res
		case "Condition", "condition":
			cond, ok := literalObjectTree(item.ValueExpr)
			if !ok {
				return iamHCLStatement{}, false
			}
			st.condition = cond
		case "NotAction", "not_action", "NotResource", "not_resource":
			return iamHCLStatement{}, false
		default:
			// Sid, Principal — ignored
		}
	}
	if st.effect == "" || len(st.actions) == 0 || len(st.resources) == 0 {
		return iamHCLStatement{}, false
	}
	return st, true
}

func literalStringListExpr(expr hclsyntax.Expression) ([]string, bool) {
	if s, ok := literalString(expr); ok {
		return []string{s}, true
	}
	tup, ok := expr.(*hclsyntax.TupleConsExpr)
	if !ok {
		return nil, false
	}
	var out []string
	for _, item := range tup.Exprs {
		s, ok := literalString(item)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func parseIAMHCLResources(expr hclsyntax.Expression) ([]iamHCLResourcePattern, bool) {
	if pat, ok := parseOneIAMHCLResource(expr); ok {
		return []iamHCLResourcePattern{pat}, true
	}
	tup, ok := expr.(*hclsyntax.TupleConsExpr)
	if !ok {
		return nil, false
	}
	var out []iamHCLResourcePattern
	for _, item := range tup.Exprs {
		pat, ok := parseOneIAMHCLResource(item)
		if !ok {
			return nil, false
		}
		out = append(out, pat)
	}
	return out, len(out) > 0
}

func parseOneIAMHCLResource(expr hclsyntax.Expression) (iamHCLResourcePattern, bool) {
	if s, ok := literalString(expr); ok {
		return iamHCLResourcePattern{parts: []iamHCLResourcePart{{literal: s}}}, true
	}
	if ref, ok := rootModuleResourceRef(expr); ok {
		return iamHCLResourcePattern{parts: []iamHCLResourcePart{{ref: ref}}}, true
	}
	tpl, ok := expr.(*hclsyntax.TemplateExpr)
	if !ok {
		return iamHCLResourcePattern{}, false
	}
	var parts []iamHCLResourcePart
	var refCount int
	for _, part := range tpl.Parts {
		switch p := part.(type) {
		case *hclsyntax.LiteralValueExpr:
			if !p.Val.IsKnown() || p.Val.Type() != cty.String {
				return iamHCLResourcePattern{}, false
			}
			parts = append(parts, iamHCLResourcePart{literal: p.Val.AsString()})
		case *hclsyntax.TemplateWrapExpr:
			if ref, ok := rootModuleResourceRef(p.Wrapped); ok {
				parts = append(parts, iamHCLResourcePart{ref: ref})
				refCount++
			} else if s, ok := literalString(p.Wrapped); ok {
				parts = append(parts, iamHCLResourcePart{literal: s})
			} else {
				return iamHCLResourcePattern{}, false
			}
		default:
			return iamHCLResourcePattern{}, false
		}
	}
	if refCount > 1 {
		return iamHCLResourcePattern{}, false
	}
	if len(parts) == 0 {
		return iamHCLResourcePattern{}, false
	}
	return iamHCLResourcePattern{parts: parts}, true
}

func rootModuleResourceRef(expr hclsyntax.Expression) (string, bool) {
	vars := expr.Variables()
	if len(vars) != 1 {
		return "", false
	}
	var b strings.Builder
	for i, step := range vars[0] {
		switch s := step.(type) {
		case hcl.TraverseRoot:
			if s.Name == "local" || s.Name == "var" || s.Name == "data" || s.Name == "module" || s.Name == "path" || s.Name == "terraform" {
				return "", false
			}
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
	ref := b.String()
	if !strings.Contains(ref, ".") {
		return "", false
	}
	// Must be type.name.attr (exactly two dots minimum for attr)
	parts := strings.Split(ref, ".")
	if len(parts) != 3 {
		return "", false
	}
	return ref, true
}

func literalObjectTree(expr hclsyntax.Expression) (map[string]any, bool) {
	obj, ok := expr.(*hclsyntax.ObjectConsExpr)
	if !ok {
		return nil, false
	}
	out := map[string]any{}
	for _, item := range obj.Items {
		key, ok := attrName(item.KeyExpr)
		if !ok {
			return nil, false
		}
		v, ok := literalValueTree(item.ValueExpr)
		if !ok {
			return nil, false
		}
		out[key] = v
	}
	return out, true
}

func literalValueTree(expr hclsyntax.Expression) (any, bool) {
	if s, ok := literalString(expr); ok {
		return s, true
	}
	if _, ok := expr.(*hclsyntax.ObjectConsExpr); ok {
		return literalObjectTree(expr)
	}
	tup, ok := expr.(*hclsyntax.TupleConsExpr)
	if !ok {
		if lit, ok := expr.(*hclsyntax.LiteralValueExpr); ok && lit.Val.IsKnown() {
			switch {
			case lit.Val.Type() == cty.String:
				return lit.Val.AsString(), true
			case lit.Val.Type() == cty.Bool:
				return lit.Val.True(), true
			case lit.Val.Type() == cty.Number:
				f, _ := lit.Val.AsBigFloat().Float64()
				return f, true
			}
		}
		return nil, false
	}
	var out []any
	for _, item := range tup.Exprs {
		v, ok := literalValueTree(item)
		if !ok {
			return nil, false
		}
		out = append(out, v)
	}
	return out, true
}

func resolvePolicyFromHCL(cause, holderKey, module string, resources []planResource, idx configIndex) (planResource, bool) {
	if module != "" || idx.iamHCL == nil {
		return planResource{}, false
	}
	pol, ok := idx.iamHCL[holderKey]
	if !ok {
		return planResource{}, false
	}
	raw, ok := materializeIAMHCLPolicyJSON(pol, resources)
	if !ok {
		return planResource{}, false
	}
	return syntheticDocFromPolicyJSON(cause, raw)
}

func materializeIAMHCLPolicyJSON(pol iamHCLPolicy, resources []planResource) (string, bool) {
	type stmtOut struct {
		Effect    string         `json:"Effect"`
		Action    any            `json:"Action"`
		Resource  any            `json:"Resource"`
		Condition map[string]any `json:"Condition,omitempty"`
	}
	var stmts []stmtOut
	for _, st := range pol.statements {
		var resList []string
		for _, pat := range st.resources {
			s, ok := materializeIAMHCLResource(pat, resources)
			if !ok {
				return "", false
			}
			resList = append(resList, s)
		}
		var action any = st.actions
		if len(st.actions) == 1 {
			action = st.actions[0]
		}
		var resource any = resList
		if len(resList) == 1 {
			resource = resList[0]
		}
		out := stmtOut{
			Effect:   st.effect,
			Action:   action,
			Resource: resource,
		}
		if len(st.condition) > 0 {
			out.Condition = st.condition
		}
		stmts = append(stmts, out)
	}
	top := map[string]any{
		"Version":   pol.version,
		"Statement": stmts,
	}
	if len(stmts) == 1 {
		top["Statement"] = stmts[0]
	}
	b, err := json.Marshal(top)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func materializeIAMHCLResource(pat iamHCLResourcePattern, resources []planResource) (string, bool) {
	var b strings.Builder
	for _, part := range pat.parts {
		if part.ref != "" {
			v, ok := planRootResourceAttr(part.ref, resources)
			if !ok {
				return "", false
			}
			b.WriteString(v)
		} else {
			b.WriteString(part.literal)
		}
	}
	if b.Len() == 0 {
		return "", false
	}
	return b.String(), true
}

// planRootResourceAttr resolves type.name.attr on a root-module resource in the plan.
func planRootResourceAttr(ref string, resources []planResource) (string, bool) {
	parts := strings.SplitN(ref, ".", 3)
	if len(parts) != 3 {
		return "", false
	}
	addr := parts[0] + "." + parts[1]
	attr := parts[2]
	var r planResource
	found := false
	for i := range resources {
		if resources[i].address == addr {
			r = resources[i]
			found = true
			break
		}
	}
	if !found {
		return "", false
	}
	if v, ok := r.values[attr].(string); ok && v != "" && !attrAfterUnknown(r, attr) {
		return v, true
	}
	if attr == "arn" && attrAfterUnknown(r, attr) && r.typ == "aws_s3_bucket" {
		if arn, ok := synthesizeS3BucketARN(r); ok {
			return arn, true
		}
		return "", false
	}
	if v, ok := r.values[attr].(string); ok && v != "" && !attrAfterUnknown(r, attr) {
		return v, true
	}
	return "", false
}

// synthesizeS3BucketARN is the only ARN synthesis the HCL IAM path performs.
// It applies when the plan leaves arn unknown but bucket is a known literal name
// and the resource region is not cn-* or us-gov-* (partition cannot be inferred).
func synthesizeS3BucketARN(r planResource) (string, bool) {
	if r.typ != "aws_s3_bucket" || !attrAfterUnknown(r, "arn") {
		return "", false
	}
	if attrAfterUnknown(r, "bucket") {
		return "", false
	}
	bucket, ok := r.values["bucket"].(string)
	if !ok || bucket == "" {
		return "", false
	}
	region, _ := r.values["region"].(string)
	if region != "" && (strings.HasPrefix(region, "cn-") || strings.HasPrefix(region, "us-gov-")) {
		return "", false
	}
	return "arn:aws:s3:::" + bucket, true
}
