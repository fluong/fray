package render

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/fluong/fray/client"
	apiv1 "github.com/fluong/fray/api/v1"
)

func PRComment(doc client.DFD, current, baseline apiv1.Findings, texts map[string]apiv1.RuleText, locs map[string]client.SourceLocation) string {
	byID := indexElements(doc)
	flows := indexFlows(doc)
	base := map[findingKey]apiv1.Finding{}
	for _, f := range baseline.Findings {
		base[findingKey{f.RuleID, f.Target}] = f
	}
	cur := map[findingKey]apiv1.Finding{}
	var opened, resolved []apiv1.Finding
	for _, f := range current.Findings {
		cur[findingKey{f.RuleID, f.Target}] = f
		if f.Status != "open" {
			continue
		}
		prev, ok := base[findingKey{f.RuleID, f.Target}]
		if !ok || prev.Status != "open" {
			opened = append(opened, f)
		}
	}
	for _, f := range baseline.Findings {
		if f.Status != "open" {
			continue
		}
		next, ok := cur[findingKey{f.RuleID, f.Target}]
		if !ok || next.Status != "open" {
			resolved = append(resolved, f)
		}
	}
	if len(opened) == 0 && len(resolved) == 0 {
		return "No change in open findings.\n"
	}
	groups := issueGroups(opened, texts, byID, flows)
	sortGroups(groups)
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", verdict(groups))
	if body := renderIssues(groups, texts, byID, flows, locs, base, true); body != "" {
		b.WriteString(body)
		b.WriteByte('\n')
	}
	if len(resolved) > 0 {
		b.WriteString("Resolved\n\n")
		resolvedGroups := issueGroups(resolved, texts, byID, flows)
		sortGroups(resolvedGroups)
		b.WriteString(renderIssues(resolvedGroups, texts, byID, flows, locs, base, false))
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "%s\n", footer(current.Findings, base, groups, len(resolved) == 0))
	return b.String()
}

func verdict(groups []causeGroup) string {
	n := len(groups)
	noun := "issues"
	if n == 1 {
		noun = "issue"
	}
	allHigh := n > 0
	anyHigh := false
	for _, g := range groups {
		if g.severity() == "high" {
			anyHigh = true
		} else {
			allHigh = false
		}
	}
	if anyHigh && allHigh {
		return fmt.Sprintf("Blocked: %d new high-severity %s", n, noun)
	}
	if anyHigh {
		return fmt.Sprintf("Blocked: %d new %s", n, noun)
	}
	return fmt.Sprintf("Not blocking: %d new %s", n, noun)
}

func footer(current []apiv1.Finding, base map[findingKey]apiv1.Finding, groups []causeGroup, nothingElse bool) string {
	same := 0
	for _, f := range current {
		prev, ok := base[findingKey{f.RuleID, f.Target}]
		if ok && prev.Status == f.Status {
			same++
		}
	}
	rules := map[string]bool{}
	for _, g := range groups {
		for _, f := range g.items {
			rules[f.RuleID] = true
		}
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	lead := fmt.Sprintf("%d findings unchanged", same)
	if nothingElse {
		lead = "Nothing else changed (" + lead + ")"
	}
	if len(ids) == 0 {
		return lead + "."
	}
	return lead + ". Rules: " + strings.Join(ids, ", ")
}

// issueGroups puts findings that share a causing resource in one block.
// Two rules stay together when they name the same element, as a public
// hostname does for both public access and the public-access block. Rules
// that only happen to cite the same resource stay separate.
func issueGroups(items []apiv1.Finding, texts map[string]apiv1.RuleText, byID map[string]client.Element, flows map[string]client.Flow) []causeGroup {
	var out []causeGroup
	for _, g := range groupByCause(items, func(f apiv1.Finding) apiv1.RuleText { return texts[f.RuleID] }, byID, flows) {
		if len(ruleIDs(g.items)) < 2 || sameTarget(g.items) {
			out = append(out, g)
			continue
		}
		byRule := map[string][]apiv1.Finding{}
		var order []string
		for _, f := range g.items {
			if _, ok := byRule[f.RuleID]; !ok {
				order = append(order, f.RuleID)
			}
			byRule[f.RuleID] = append(byRule[f.RuleID], f)
		}
		for _, id := range order {
			out = append(out, causeGroup{cause: g.cause, items: byRule[id]})
		}
	}
	return out
}

func ruleIDs(items []apiv1.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range items {
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		out = append(out, f.RuleID)
	}
	return out
}

func sameTarget(items []apiv1.Finding) bool {
	if len(items) == 0 {
		return true
	}
	id := items[0].Target
	for _, f := range items[1:] {
		if f.Target != id {
			return false
		}
	}
	return true
}

func sortGroups(groups []causeGroup) {
	slices.SortStableFunc(groups, func(a, b causeGroup) int {
		if ra, rb := sevRank(a.severity()), sevRank(b.severity()); ra != rb {
			return ra - rb
		}
		return strings.Compare(a.cause, b.cause)
	})
}

func (g causeGroup) severity() string {
	best := ""
	for _, f := range g.items {
		if best == "" || sevRank(f.Severity) < sevRank(best) {
			best = f.Severity
		}
	}
	return best
}

func renderIssues(groups []causeGroup, texts map[string]apiv1.RuleText, byID map[string]client.Element, flows map[string]client.Flow, locs map[string]client.SourceLocation, base map[findingKey]apiv1.Finding, accept bool) string {
	var b strings.Builder
	for i, g := range groups {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(renderIssue(g, texts, byID, flows, locs, base, accept))
	}
	return b.String()
}

func renderIssue(g causeGroup, texts map[string]apiv1.RuleText, byID map[string]client.Element, flows map[string]client.Flow, locs map[string]client.SourceLocation, base map[findingKey]apiv1.Finding, accept bool) string {
	rule := primaryRule(g.items, texts)
	fix, explanation := remedy(rule, g.cause)
	if explanation == "" {
		explanation = rule.Explanation
	}
	if rule.Before != "" && previouslyMitigated(g.items, base) {
		explanation = strings.TrimSpace(explanation) + " " + strings.TrimSpace(rule.Before)
	}
	repl := groupReplacements(g, byID, flows)
	var b strings.Builder
	fmt.Fprintf(&b, "**%s**\n", fill(headline(rule), repl))
	fmt.Fprintf(&b, "%s\n\n", metaLine(g, rule, locs))
	fmt.Fprintf(&b, "%s\n\n", wrap(fill(explanation, repl), 90))
	if names := affectedNames(g.items, byID, flows); len(names) > 1 {
		fmt.Fprintf(&b, "Affected: %s\n\n", strings.Join(names, ", "))
	}
	fmt.Fprintf(&b, "%s\n", wrap("Fix: "+fill(fix, repl), 90))
	if accept {
		b.WriteString("\n<details><summary>Accept this risk instead</summary>\n\n")
		b.WriteString(mitigationSnippet(g.items, byID, flows))
		b.WriteString("</details>\n")
	}
	return b.String()
}

func headline(r apiv1.RuleText) string {
	if r.GroupTitle != "" {
		return r.GroupTitle
	}
	if r.Threat != "" {
		return r.Threat
	}
	return r.Title
}

func primaryRule(items []apiv1.Finding, texts map[string]apiv1.RuleText) apiv1.RuleText {
	best := items[0]
	for _, f := range items[1:] {
		if sevRank(f.Severity) < sevRank(best.Severity) || (f.Severity == best.Severity && f.RuleID < best.RuleID) {
			best = f
		}
	}
	return texts[best.RuleID]
}

func remedy(rule apiv1.RuleText, cause string) (text, explanation string) {
	typ := resourceType(cause)
	provider := providerKey(typ)
	for _, r := range rule.Remediations {
		if r.Provider == provider && r.Resource == typ {
			return r.Text, r.Explanation
		}
	}
	return rule.Mitigation, ""
}

func previouslyMitigated(items []apiv1.Finding, base map[findingKey]apiv1.Finding) bool {
	if base == nil || len(items) == 0 {
		return false
	}
	for _, f := range items {
		prev, ok := base[findingKey{f.RuleID, f.Target}]
		if !ok || prev.Status != "mitigated" {
			return false
		}
	}
	return true
}

func metaLine(g causeGroup, rule apiv1.RuleText, locs map[string]client.SourceLocation) string {
	where := g.cause
	if loc, ok := client.LookupLocation(locs, g.cause); ok {
		where = loc.String()
	}
	return fmt.Sprintf("`%s` · %s · %s · %s", g.cause, where, g.severity(), strideText(rule.Stride))
}

func resourceType(address string) string {
	parts := strings.Split(address, ".")
	for i := 0; i < len(parts); i++ {
		if parts[i] == "module" && i+1 < len(parts) {
			i++
			continue
		}
		if parts[i] == "data" && i+1 < len(parts) {
			return parts[i+1]
		}
		return parts[i]
	}
	return address
}

func providerKey(typ string) string {
	switch {
	case strings.HasPrefix(typ, "google_"):
		return "gcp"
	case strings.HasPrefix(typ, "cloudflare_"):
		return "cloudflare"
	case strings.HasPrefix(typ, "aws_"):
		return "aws"
	default:
		return ""
	}
}

const commentWidth = 90

func wrap(s string, width int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var lines []string
	cur := words[0]
	for _, word := range words[1:] {
		if len(cur)+1+len(word) > width {
			lines = append(lines, cur)
			cur = word
			continue
		}
		cur += " " + word
	}
	lines = append(lines, cur)
	return strings.Join(lines, "\n")
}

func affectedNames(items []apiv1.Finding, byID map[string]client.Element, flows map[string]client.Flow) []string {
	var elems, froms, tos []string
	flowsOnly := true
	for _, f := range items {
		if flow, ok := flows[f.Target]; ok {
			froms = append(froms, byID[flow.From].Name)
			tos = append(tos, byID[flow.To].Name)
			continue
		}
		flowsOnly = false
		if el, ok := byID[f.Target]; ok {
			elems = append(elems, el.Name)
		}
	}
	if flowsOnly && len(froms) > 0 && allEqual(tos) && !allEqual(froms) {
		return uniqueSorted(froms)
	}
	if flowsOnly && len(tos) > 0 && allEqual(froms) && !allEqual(tos) {
		return uniqueSorted(tos)
	}
	if flowsOnly && len(froms) > 1 && allEqual(froms) && allEqual(tos) {
		return uniqueSorted(froms)
	}
	if flowsOnly && len(froms) == 1 {
		return []string{froms[0]}
	}
	if flowsOnly {
		both := make([]string, len(froms))
		for i := range froms {
			both[i] = froms[i] + " → " + tos[i]
		}
		return uniqueSorted(both)
	}
	return uniqueSorted(elems)
}

func allEqual(vals []string) bool {
	if len(vals) == 0 {
		return true
	}
	for _, v := range vals[1:] {
		if v != vals[0] {
			return false
		}
	}
	return true
}

func uniqueSorted(vals []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range vals {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

func mitigationSnippet(items []apiv1.Finding, byID map[string]client.Element, flows map[string]client.Flow) string {
	type row struct {
		rule, address string
	}
	rows := make([]row, 0, len(items))
	for _, f := range items {
		rows = append(rows, row{f.RuleID, humanAddress(f.Target, byID, flows)})
	}
	slices.SortFunc(rows, func(a, b row) int {
		if a.rule != b.rule {
			return strings.Compare(a.rule, b.rule)
		}
		return strings.Compare(a.address, b.address)
	})
	var b strings.Builder
	b.WriteString("```yaml\n")
	b.WriteString("schema_version: mitigation/v1\nentries:\n")
	for _, row := range rows {
		fmt.Fprintf(&b, "  - rule_id: %s\n", row.rule)
		if strings.ContainsAny(row.address, " :") {
			fmt.Fprintf(&b, "    address: %q\n", row.address)
		} else {
			fmt.Fprintf(&b, "    address: %s\n", row.address)
		}
		b.WriteString("    status: accepted\n")
		b.WriteString("    reason: reason\n")
	}
	b.WriteString("```\n")
	return b.String()
}

func humanAddress(id string, byID map[string]client.Element, flows map[string]client.Flow) string {
	if el, ok := byID[id]; ok {
		return elementAddress(el)
	}
	if f, ok := flows[id]; ok {
		return elementAddress(byID[f.From]) + " -> " + elementAddress(byID[f.To]) + " " + f.DataClass
	}
	return id
}

func elementAddress(el client.Element) string {
	switch el.Provenance {
	case "declared":
		return "declared:" + el.Evidence.Key
	case "inferred":
		if len(el.Evidence.Signals) > 0 {
			s := el.Evidence.Signals[0]
			return "signal:" + s.Type + ":" + s.Name
		}
	}
	if len(el.Evidence.Addresses) > 0 {
		return el.Evidence.Addresses[0]
	}
	return el.Name
}

func groupReplacements(g causeGroup, byID map[string]client.Element, flows map[string]client.Flow) map[string]string {
	var els []client.Element
	for _, f := range g.items {
		if flow, ok := flows[f.Target]; ok {
			els = append(els, byID[flow.From], byID[flow.To])
			continue
		}
		if el, ok := byID[f.Target]; ok {
			els = append(els, el)
		}
	}
	var targeted []string
	for _, f := range g.items {
		if el, ok := byID[f.Target]; ok {
			targeted = append(targeted, el.Name)
		}
	}
	element := ""
	if names := uniqueSorted(targeted); len(names) == 1 {
		element = names[0]
	}
	if element == "" {
		element = firstName(namesOf(els, func(el client.Element) bool { return el.Kind == "object_storage" })...)
	}
	if element == "" {
		element = firstName(namesOf(els, func(el client.Element) bool { return el.Kind == "container_service" })...)
	}
	repl := map[string]string{
		"{element}": element,
		"{process}": firstName(namesOf(els, func(el client.Element) bool { return el.Kind == "container_service" })...),
		"{secret}":  firstName(namesOf(els, func(el client.Element) bool { return el.Kind == "secret_store" })...),
		"{bucket}":  firstName(namesOf(els, func(el client.Element) bool { return el.Kind == "object_storage" })...),
		"{cause}":   g.cause,
		"{count}":   strconv.Itoa(len(g.items)),
		"{label}":   labelOf(element),
	}
	return repl
}

func namesOf(els []client.Element, match func(client.Element) bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, el := range els {
		if el.Name == "" || !match(el) || seen[el.Name] {
			continue
		}
		seen[el.Name] = true
		out = append(out, el.Name)
	}
	return out
}

func labelOf(name string) string {
	if i := strings.IndexByte(name, '-'); i > 0 && i < len(name)-1 {
		name = name[i+1:]
	}
	name = strings.ReplaceAll(name, "-", " ")
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

func fill(tmpl string, repl map[string]string) string {
	if tmpl == "" {
		return ""
	}
	out := tmpl
	for k, v := range repl {
		if v == "" {
			v = "this resource"
		}
		out = strings.ReplaceAll(out, k, v)
	}
	return out
}

type causeGroup struct {
	cause string
	items []apiv1.Finding
}

func groupByCause(items []apiv1.Finding, ruleFor func(apiv1.Finding) apiv1.RuleText, byID map[string]client.Element, flows map[string]client.Flow) []causeGroup {
	var order []string
	grouped := map[string][]apiv1.Finding{}
	for _, f := range items {
		cause := causeOf(f, ruleFor(f), byID, flows)
		if _, ok := grouped[cause]; !ok {
			order = append(order, cause)
		}
		grouped[cause] = append(grouped[cause], f)
	}
	out := make([]causeGroup, len(order))
	for i, cause := range order {
		out[i] = causeGroup{cause, grouped[cause]}
	}
	return out
}

func where(id string, byID map[string]client.Element, flows map[string]client.Flow) string {
	if el, ok := byID[id]; ok {
		return el.Name
	}
	if f, ok := flows[id]; ok {
		return byID[f.From].Name + " → " + byID[f.To].Name
	}
	return id
}

func causeOf(f apiv1.Finding, rule apiv1.RuleText, byID map[string]client.Element, flows map[string]client.Flow) string {
	if f.Status == "open" || f.Status == "" {
		if field, _ := failedAttribute(rule, f.Target, byID, flows); field != "" {
			if cause := causeForField(f.Target, field, byID, flows); cause != "" {
				return cause
			}
		}
	}
	return defaultCause(f.Target, byID, flows)
}

func causeForField(id, field string, byID map[string]client.Element, flows map[string]client.Flow) string {
	field = strings.TrimPrefix(field, "attributes.")
	if f, ok := flows[id]; ok {
		if c := f.Causes[field]; c != "" {
			return c
		}
	}
	if el, ok := byID[id]; ok {
		if c := el.Causes[field]; c != "" {
			return c
		}
	}
	return ""
}

func defaultCause(id string, byID map[string]client.Element, flows map[string]client.Flow) string {
	if el, ok := byID[id]; ok {
		if len(el.Evidence.Addresses) > 0 {
			return el.Evidence.Addresses[0]
		}
		return ""
	}
	if f, ok := flows[id]; ok {
		if el, ok := byID[f.To]; ok && len(el.Evidence.Addresses) > 0 {
			return el.Evidence.Addresses[0]
		}
		if el, ok := byID[f.From]; ok && len(el.Evidence.Addresses) > 0 {
			return el.Evidence.Addresses[0]
		}
	}
	return ""
}

func firstName(names ...string) string {
	for _, n := range names {
		if n != "" {
			return n
		}
	}
	return ""
}
