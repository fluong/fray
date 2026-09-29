package render

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/fluong/fray/client"
	apiv1 "github.com/fluong/fray/api/v1"
)

func ThreatModel(doc client.DFD, findings apiv1.Findings, texts map[string]apiv1.RuleText, accepted []MitigationEntry, locs map[string]client.SourceLocation) string {
	byID := indexElements(doc)
	flows := indexFlows(doc)
	var b strings.Builder
	b.WriteString("# Threat model\n\n")
	b.WriteString("This report describes how data moves through the system, which threats are still open, which risks were accepted, and which controls were checked in the infrastructure plan.\n\n")
	b.WriteString("## Summary\n\n")
	b.WriteString(summary(findings))
	b.WriteString("\n## Data flow\n\n")
	b.WriteString("Each box is a part of the system. An arrow is data moving from one part to another. A colored arrow crosses a trust boundary: the two sides do not trust each other the same way. A part can sit inside more than one boundary, so boundaries are the arrows that cross them, not boxes around groups of parts.\n\n")
	b.WriteString("Red is a network boundary, blue is a provider boundary, and orange is the operator boundary. A gray arrow stays inside one trust domain. The label is the boundary, or the kind of data when the arrow does not cross one.\n\n")
	b.WriteString(mermaid(doc, byID))
	b.WriteString("\n## Open threats\n\n")
	b.WriteString(openSection(findings, texts, byID, flows, locs))
	b.WriteString("\n## Accepted risks\n\n")
	b.WriteString("These threats are real. They were accepted on purpose, with a reason and, where one was set, a trigger to look again.\n\n")
	b.WriteString(acceptedSection(doc, findings, texts, accepted, byID, flows))
	b.WriteString("\n## Verified controls\n\n")
	b.WriteString("These controls were checked against the plan and passed.\n\n")
	b.WriteString(mitigatedSection(findings, texts, byID, flows))
	b.WriteString("\n## Unverified\n\n")
	b.WriteString(unverifiedSection(doc, findings, texts, byID, flows))
	return b.String()
}

func summary(findings apiv1.Findings) string {
	statuses := []string{"open", "mitigated", "accepted", "unverified"}
	count := map[string]map[string]int{}
	for _, s := range statuses {
		count[s] = map[string]int{}
	}
	for _, f := range findings.Findings {
		if count[f.Status] == nil {
			count[f.Status] = map[string]int{}
		}
		count[f.Status][f.Severity]++
	}
	var b strings.Builder
	b.WriteString("| Status | High | Medium | Low | Total |\n")
	b.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, s := range statuses {
		total := count[s]["high"] + count[s]["medium"] + count[s]["low"]
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d |\n", s, count[s]["high"], count[s]["medium"], count[s]["low"], total)
	}
	return b.String()
}

func mermaid(doc client.DFD, byID map[string]client.Element) string {
	bounds := map[string]client.Boundary{}
	for _, b := range doc.TrustBoundaries {
		bounds[b.ID] = b
	}
	els := slices.Clone(doc.Elements)
	slices.SortFunc(els, func(a, b client.Element) int {
		return strings.Compare(a.Name, b.Name)
	})
	type edge struct {
		from, to, label, style string
	}
	var edges []edge
	for _, f := range doc.Flows {
		if len(f.Boundaries) == 0 {
			edges = append(edges, edge{f.From, f.To, dataLabel(f.DataClass), ""})
			continue
		}
		for _, id := range f.Boundaries {
			b := bounds[id]
			edges = append(edges, edge{f.From, f.To, b.Kind + " boundary, " + dataLabel(f.DataClass), b.Kind})
		}
	}
	slices.SortFunc(edges, func(a, b edge) int {
		if c := strings.Compare(byID[a.from].Name, byID[b.from].Name); c != 0 {
			return c
		}
		if c := strings.Compare(byID[a.to].Name, byID[b.to].Name); c != 0 {
			return c
		}
		return strings.Compare(a.label, b.label)
	})
	var b strings.Builder
	b.WriteString("```mermaid\nflowchart LR\n")
	for _, el := range els {
		fmt.Fprintf(&b, "  %s[%q]\n", el.ID, el.Name)
	}
	for _, e := range edges {
		fmt.Fprintf(&b, "  %s -->|%q| %s\n", e.from, e.label, e.to)
	}
	for i, e := range edges {
		switch e.style {
		case "network":
			fmt.Fprintf(&b, "  linkStyle %d stroke:#b91c1c,stroke-width:3px\n", i)
		case "provider":
			fmt.Fprintf(&b, "  linkStyle %d stroke:#1d4ed8,stroke-dasharray:5 5\n", i)
		case "operator":
			fmt.Fprintf(&b, "  linkStyle %d stroke:#c2410c,stroke-width:2px\n", i)
		}
	}
	b.WriteString("```\n")
	return b.String()
}

func dataLabel(class string) string {
	switch class {
	case "customer_data":
		return "customer data"
	case "unknown":
		return "unclassified"
	default:
		return strings.ReplaceAll(class, "_", " ")
	}
}

func openSection(findings apiv1.Findings, texts map[string]apiv1.RuleText, byID map[string]client.Element, flows map[string]client.Flow, locs map[string]client.SourceLocation) string {
	var open []apiv1.Finding
	for _, f := range findings.Findings {
		if f.Status == "open" {
			open = append(open, f)
		}
	}
	if len(open) == 0 {
		return "No open threats.\n"
	}
	groups := issueGroups(open, texts, byID, flows)
	sortGroups(groups)
	return renderIssues(groups, texts, byID, flows, locs, nil, nil, false, nil)
}

func acceptedSection(doc client.DFD, findings apiv1.Findings, texts map[string]apiv1.RuleText, entries []MitigationEntry, byID map[string]client.Element, flows map[string]client.Flow) string {
	reasons := map[findingKey]MitigationEntry{}
	for _, e := range entries {
		id := resolveAddress(doc, e.Address)
		if id != "" {
			reasons[findingKey{e.RuleID, id}] = e
		}
	}
	var b strings.Builder
	n := 0
	for _, f := range findings.Findings {
		if f.Status != "accepted" {
			continue
		}
		if n > 0 {
			b.WriteByte('\n')
		}
		n++
		rule := texts[f.RuleID]
		entry := reasons[findingKey{f.RuleID, f.Target}]
		statement := rule.Threat
		if statement == "" {
			statement = rule.Title
		}
		fmt.Fprintf(&b, "- **%s** %s — %s.\n", f.RuleID, statement, where(f.Target, byID, flows))
		fmt.Fprintf(&b, "  Reason: %s\n", ensurePeriod(entry.Reason))
		if entry.Revisit != "" {
			fmt.Fprintf(&b, "  Revisit when %s\n", ensurePeriod(entry.Revisit))
		}
	}
	if n == 0 {
		return "None.\n"
	}
	return b.String()
}

func mitigatedSection(findings apiv1.Findings, texts map[string]apiv1.RuleText, byID map[string]client.Element, flows map[string]client.Flow) string {
	groups := map[string][]string{}
	var order []string
	for _, f := range findings.Findings {
		if f.Status != "mitigated" {
			continue
		}
		if _, ok := groups[f.RuleID]; !ok {
			order = append(order, f.RuleID)
		}
		groups[f.RuleID] = append(groups[f.RuleID], where(f.Target, byID, flows))
	}
	if len(order) == 0 {
		return "None.\n"
	}
	var b strings.Builder
	for _, id := range order {
		names := groups[id]
		slices.Sort(names)
		fmt.Fprintf(&b, "- %s %s — %s\n", id, texts[id].Title, strings.Join(names, ", "))
	}
	return b.String()
}

func unverifiedSection(doc client.DFD, findings apiv1.Findings, texts map[string]apiv1.RuleText, byID map[string]client.Element, flows map[string]client.Flow) string {
	var lines []string
	for _, f := range findings.Findings {
		if f.Status != "unverified" {
			continue
		}
		rule := texts[f.RuleID]
		missing := missingFields(rule.Pass, f.Target, byID, flows)
		lines = append(lines, fmt.Sprintf("- %s %s — %s. %s", f.RuleID, rule.Title, where(f.Target, byID, flows), missingSentence(missing)))
	}
	if len(lines) == 0 {
		return "None.\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<details>\n<summary>%d control", len(lines))
	if len(lines) != 1 {
		b.WriteString("s")
	}
	b.WriteString(" could not be checked</summary>\n\n")
	for _, line := range lines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString("\n</details>\n")
	return b.String()
}

func evidence(id, field, actual string, byID map[string]client.Element, flows map[string]client.Flow) string {
	place := resourcePlace(id, byID, flows)
	if field == "" {
		return place
	}
	return fmt.Sprintf("%s, `%s` is %s", place, fieldLabel(field), actual)
}

func resourcePlace(id string, byID map[string]client.Element, flows map[string]client.Flow) string {
	if el, ok := byID[id]; ok {
		return placeElement(el)
	}
	if f, ok := flows[id]; ok {
		return placeElement(byID[f.From]) + " → " + placeElement(byID[f.To])
	}
	return id
}

func placeElement(el client.Element) string {
	if len(el.Evidence.Addresses) > 0 {
		return "`" + strings.Join(el.Evidence.Addresses, "`, `") + "`"
	}
	return el.Name
}

func failedAttribute(rule apiv1.RuleText, id string, byID map[string]client.Element, flows map[string]client.Flow) (string, string) {
	el, flow := target(id, byID, flows)
	for _, c := range rule.Pass {
		state, field, actual := evalCond(c, el, flow, byID)
		if state == triFalse {
			return field, actual
		}
	}
	return "", ""
}

func missingFields(pass []apiv1.Condition, id string, byID map[string]client.Element, flows map[string]client.Flow) []string {
	el, flow := target(id, byID, flows)
	var out []string
	var walk func(apiv1.Condition)
	walk = func(c apiv1.Condition) {
		if c.Op == "not" && c.Cond != nil {
			state, field, _ := evalCond(*c.Cond, el, flow, byID)
			if state == triUnverified && field != "" {
				out = append(out, field)
			}
			return
		}
		state, field, _ := evalCond(c, el, flow, byID)
		if state == triUnverified && field != "" {
			out = append(out, field)
		}
	}
	for _, c := range pass {
		walk(c)
	}
	return out
}

func missingSentence(fields []string) string {
	if len(fields) == 0 {
		return "The plan does not include enough information to check this control."
	}
	names := make([]string, len(fields))
	for i, f := range fields {
		names[i] = fieldLabel(f)
	}
	if len(names) == 1 {
		return names[0] + " is not in the plan."
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1] + " are not in the plan."
}

const (
	triFalse = iota
	triTrue
	triUnverified
)

func evalCond(c apiv1.Condition, el *client.Element, f *client.Flow, byID map[string]client.Element) (int, string, string) {
	if c.Op == "not" && c.Cond != nil {
		state, field, actual := evalCond(*c.Cond, el, f, byID)
		switch state {
		case triTrue:
			return triFalse, field, actual
		case triFalse:
			return triTrue, field, actual
		default:
			return triUnverified, field, actual
		}
	}
	val, ok := lookup(c.Field, el, f, byID)
	shown := formatValue(val)
	switch c.Op {
	case "exists":
		if ok {
			return triTrue, c.Field, shown
		}
		return triFalse, c.Field, "absent"
	case "equals":
		if !ok {
			return triUnverified, c.Field, "absent"
		}
		if valuesEqual(val, c.Value) {
			return triTrue, c.Field, shown
		}
		return triFalse, c.Field, shown
	case "in":
		if !ok {
			return triUnverified, c.Field, "absent"
		}
		if valueIn(val, c.Value) {
			return triTrue, c.Field, shown
		}
		return triFalse, c.Field, shown
	case "lte", "gte":
		if !ok {
			return triUnverified, c.Field, "absent"
		}
		got, gotOK := asFloat(val)
		want, wantOK := asFloat(c.Value)
		if !gotOK || !wantOK {
			return triFalse, c.Field, shown
		}
		if c.Op == "lte" && got <= want || c.Op == "gte" && got >= want {
			return triTrue, c.Field, shown
		}
		return triFalse, c.Field, shown
	default:
		return triTrue, c.Field, shown
	}
}

func valuesEqual(got, want any) bool {
	if gf, ok := asFloat(got); ok {
		if wf, ok := asFloat(want); ok {
			return gf == wf
		}
	}
	return formatValue(got) == formatValue(want)
}

func valueIn(got, list any) bool {
	switch items := list.(type) {
	case []any:
		for _, item := range items {
			if valuesEqual(got, item) {
				return true
			}
		}
	case []string:
		for _, item := range items {
			if valuesEqual(got, item) {
				return true
			}
		}
	}
	return false
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func lookup(field string, el *client.Element, f *client.Flow, byID map[string]client.Element) (any, bool) {
	if side, rest, ok := strings.Cut(field, "."); ok && (side == "from" || side == "to") && f != nil {
		id := f.From
		if side == "to" {
			id = f.To
		}
		other, exists := byID[id]
		if !exists {
			return nil, false
		}
		return lookup(rest, &other, nil, byID)
	}
	if name, ok := strings.CutPrefix(field, "attributes."); ok {
		if el == nil || el.Attributes == nil {
			return nil, false
		}
		v, exists := el.Attributes[name]
		return v, exists
	}
	if el != nil {
		switch field {
		case "type":
			return el.Type, true
		case "kind":
			return el.Kind, true
		case "provenance":
			return el.Provenance, true
		case "provider":
			if el.Provider == "" {
				return nil, false
			}
			return el.Provider, true
		}
	}
	if f != nil {
		switch field {
		case "data_class":
			return f.DataClass, f.DataClass != ""
		case "transport":
			return f.Transport, f.Transport != ""
		case "authz_scope":
			if f.AuthzScope == "" {
				return nil, false
			}
			return f.AuthzScope, true
		case "secret_delivery":
			if f.SecretDelivery == "" {
				return nil, false
			}
			return f.SecretDelivery, true
		}
	}
	return nil, false
}

func target(id string, byID map[string]client.Element, flows map[string]client.Flow) (*client.Element, *client.Flow) {
	if el, ok := byID[id]; ok {
		return &el, nil
	}
	if f, ok := flows[id]; ok {
		return nil, &f
	}
	return nil, nil
}

func indexElements(doc client.DFD) map[string]client.Element {
	out := map[string]client.Element{}
	for _, el := range doc.Elements {
		out[el.ID] = el
	}
	return out
}

func indexFlows(doc client.DFD) map[string]client.Flow {
	out := map[string]client.Flow{}
	for _, f := range doc.Flows {
		out[f.ID] = f
	}
	return out
}

// resolveAddress mirrors the overlay address forms enough to attach a reason.
// Element addresses and "from -> to class" flow addresses are both accepted.
// ResolveAddress maps a mitigations.yaml address to an element or flow id.
func ResolveAddress(doc client.DFD, address string) string {
	return resolveAddress(doc, address)
}

func resolveAddress(doc client.DFD, address string) string {
	if left, right, ok := strings.Cut(address, " -> "); ok {
		i := strings.LastIndex(right, " ")
		if i <= 0 {
			return ""
		}
		from := matchElement(doc, left)
		to := matchElement(doc, right[:i])
		class := right[i+1:]
		if from == "" || to == "" {
			return ""
		}
		for _, f := range doc.Flows {
			if f.From == from && f.To == to && f.DataClass == class {
				return f.ID
			}
		}
		return ""
	}
	return matchElement(doc, address)
}

func matchElement(doc client.DFD, address string) string {
	switch {
	case strings.HasPrefix(address, "declared:"):
		key := strings.TrimPrefix(address, "declared:")
		for _, el := range doc.Elements {
			if el.Provenance == "declared" && el.Evidence.Key == key {
				return el.ID
			}
		}
	case strings.HasPrefix(address, "signal:"):
		rest := strings.TrimPrefix(address, "signal:")
		typ, name, ok := strings.Cut(rest, ":")
		if !ok {
			return ""
		}
		for _, el := range doc.Elements {
			for _, s := range el.Evidence.Signals {
				if s.Type == typ && s.Name == name {
					return el.ID
				}
			}
		}
	default:
		for _, el := range doc.Elements {
			if slices.Contains(el.Evidence.Addresses, address) {
				return el.ID
			}
		}
	}
	return ""
}

func formatValue(v any) string {
	switch n := v.(type) {
	case bool:
		return strconv.FormatBool(n)
	case string:
		return n
	case float64:
		if n == float64(int64(n)) {
			return strconv.FormatInt(int64(n), 10)
		}
		return strconv.FormatFloat(n, 'f', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

func fieldLabel(field string) string {
	field = strings.TrimPrefix(field, "attributes.")
	switch field {
	case "authz_scope":
		return "authorization scope"
	case "secret_delivery":
		return "secret delivery"
	case "image_pinned_by_digest":
		return "image digest"
	case "rotation_configured":
		return "rotation"
	case "deletion_protection":
		return "deletion protection"
	case "audit_logging":
		return "audit logging"
	case "max_instances":
		return "max instances"
	case "public_access_blocked":
		return "public access block"
	case "acls_disabled":
		return "ACLs"
	case "object_lock":
		return "object lock"
	default:
		return strings.ReplaceAll(field, "_", " ")
	}
}

func strideText(parts []string) string {
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = strings.ReplaceAll(p, "_", " ")
	}
	return strings.Join(out, ", ")
}

func sevRank(s string) int {
	switch s {
	case "high":
		return 0
	case "medium":
		return 1
	default:
		return 2
	}
}

func worst(list []apiv1.Finding) int {
	best := 3
	for _, f := range list {
		if r := sevRank(f.Severity); r < best {
			best = r
		}
	}
	return best
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return ""
	}
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

func ensurePeriod(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}
