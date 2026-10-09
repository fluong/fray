package render

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
	"github.com/fluong/fray/usermsg"
)

// NoBaselineNote is the PR-comment line when there is no stored baseline yet.
const NoBaselineNote = usermsg.NoBaselineNote

func PRComment(doc client.DFD, current, baseline apiv1.Findings, texts map[string]apiv1.RuleText, locs map[string]client.SourceLocation, changedInputs map[string][]string, baselineNote string, advisory *apiv1.Advisory, enrichments []apiv1.FindingEnrichment, waivers *apiv1.Waivers, waiversReported bool) string {
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
		// Waiving an open finding is not "Resolved" — it belongs in Waivers.
		if ok && (next.Status == "waived" || next.Status == "accepted") {
			continue
		}
		if !ok || next.Status != "open" {
			resolved = append(resolved, f)
		}
	}
	waiverSection := WaiversSummary(waivers, waiversReported)
	if len(opened) == 0 && len(resolved) == 0 && baselineNote == "" && advisoryEmpty(advisory) && waiverSection == "" {
		return "No change in open findings.\n"
	}
	groups := issueGroups(opened, texts, byID, flows)
	sortGroups(groups)
	why := enrichmentIndex(enrichments)
	var b strings.Builder
	if baselineNote != "" {
		fmt.Fprintf(&b, "%s\n\n", baselineNote)
	}
	if len(opened) == 0 && len(resolved) == 0 {
		if waiverSection == "" || baselineNote != "" || !advisoryEmpty(advisory) {
			b.WriteString("No change in open findings.\n")
		}
		if waiverSection != "" {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(waiverSection)
		}
		if section := renderAdvisory(advisory, enrichments, opened, texts, byID, flows); section != "" {
			b.WriteByte('\n')
			b.WriteString(section)
		}
		if b.Len() == 0 {
			return "No change in open findings.\n"
		}
		return b.String()
	}
	fmt.Fprintf(&b, "%s\n\n", verdict(groups))
	if body := renderIssues(groups, texts, byID, flows, locs, changedInputs, base, true, why); body != "" {
		b.WriteString(body)
		b.WriteByte('\n')
	}
	if len(resolved) > 0 {
		b.WriteString("Resolved\n\n")
		resolvedGroups := issueGroups(resolved, texts, byID, flows)
		sortGroups(resolvedGroups)
		b.WriteString(renderIssues(resolvedGroups, texts, byID, flows, locs, changedInputs, base, false, why))
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "%s\n", footer(current.Findings, base, groups, len(resolved) == 0))
	if waiverSection != "" {
		b.WriteByte('\n')
		b.WriteString(waiverSection)
	}
	if section := renderAdvisory(advisory, enrichments, opened, texts, byID, flows); section != "" {
		b.WriteByte('\n')
		b.WriteString(section)
	}
	return b.String()
}

// WaiversSummary formats server waiver outcomes for the PR comment and job summary.
// When reported is false (older server), returns a short notice. Empty outcomes → "".
func WaiversSummary(w *apiv1.Waivers, reported bool) string {
	if !reported {
		return "### Waivers\n\nserver did not report waiver outcomes\n"
	}
	if w == nil {
		return ""
	}
	if len(w.Applied) == 0 && len(w.Expired) == 0 && len(w.Stale) == 0 &&
		len(w.ExpiringSoon) == 0 && len(w.NewInPR) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("### Waivers\n\n")
	if len(w.Applied) > 0 {
		fmt.Fprintf(&b, "**Applied** (%d): %s\n\n", len(w.Applied), strings.Join(w.Applied, ", "))
	}
	if len(w.NewInPR) > 0 {
		b.WriteString("**New in this PR:** ")
		b.WriteString(strings.Join(w.NewInPR, ", "))
		b.WriteString("\n\n")
		b.WriteString("Protect `.fray/` with CODEOWNERS so waiver changes get review.\n\n")
	}
	if len(w.ExpiringSoon) > 0 {
		fmt.Fprintf(&b, "**Expiring soon** (≤14 days): %s\n\n", strings.Join(w.ExpiringSoon, ", "))
	}
	if len(w.Expired) > 0 {
		fmt.Fprintf(&b, "**Expired** (finding is open again): %s\n\n", strings.Join(w.Expired, ", "))
	}
	if len(w.Stale) > 0 {
		b.WriteString("**Stale:**\n")
		for _, s := range w.Stale {
			fmt.Fprintf(&b, "- `%s`: %s\n", s.ID, s.Reason)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func advisoryEmpty(a *apiv1.Advisory) bool {
	return a == nil || (a.Note == "" && len(a.Observations) == 0)
}

type enrichmentText struct {
	WhyHere string
	FixHere string
}

func enrichmentIndex(items []apiv1.FindingEnrichment) map[findingKey]enrichmentText {
	out := map[findingKey]enrichmentText{}
	for _, e := range items {
		if e.WhyHere == "" && e.FixHere == "" {
			continue
		}
		out[findingKey{e.RuleID, e.Target}] = enrichmentText{WhyHere: e.WhyHere, FixHere: e.FixHere}
	}
	return out
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

func renderIssues(groups []causeGroup, texts map[string]apiv1.RuleText, byID map[string]client.Element, flows map[string]client.Flow, locs map[string]client.SourceLocation, changedInputs map[string][]string, base map[findingKey]apiv1.Finding, accept bool, enrich map[findingKey]enrichmentText) string {
	var b strings.Builder
	for i, g := range groups {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(renderIssue(g, texts, byID, flows, locs, changedInputs, base, accept, enrich))
	}
	return b.String()
}

func renderIssue(g causeGroup, texts map[string]apiv1.RuleText, byID map[string]client.Element, flows map[string]client.Flow, locs map[string]client.SourceLocation, changedInputs map[string][]string, base map[findingKey]apiv1.Finding, accept bool, enrich map[findingKey]enrichmentText) string {
	rule := primaryRule(g.items, texts)
	lost := previouslyMitigated(g.items, base)
	fix, explanation := remedy(rule, g.cause)
	if explanation == "" {
		explanation = rule.Explanation
	}
	if rule.Before != "" && lost {
		explanation = strings.TrimSpace(explanation) + " " + strings.TrimSpace(rule.Before)
	}
	repl := groupReplacements(g, byID, flows)
	title := fill(headline(rule), repl)
	if lost {
		title = noLongerTitle(title)
	}
	mod, hasMod := client.LookupModuleCause(locs, g.cause)
	if hasMod {
		mod.Inputs = changedInputs[mod.Call]
		if named := moduleInputFix(mod.Inputs); named != "" {
			fix = named
		}
	}
	names := displayNames(byID, flows)
	if line := fixHereLine(g.items, enrich, names); line != "" {
		fix = line
	}
	why := whyHereLine(g.items, enrich, names)
	// When rule context applies (why_here), drop ACL alternatives from the base
	// sentence — context already covers that ACLs are off / irrelevant.
	if why != "" {
		explanation = dropACLAlternative(explanation)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**%s**\n", title)
	fmt.Fprintf(&b, "%s\n\n", metaLine(g, rule, locs, mod, hasMod))
	fmt.Fprintf(&b, "%s\n\n", wrap(pluralizeCounts(fill(explanation, repl)), 90))
	if why != "" {
		fmt.Fprintf(&b, "%s\n\n", wrap(why, 90))
	}
	if line := findingEvidenceLine(g.items, names); line != "" {
		fmt.Fprintf(&b, "%s\n\n", wrap(line, 90))
	}
	if affected := affectedNames(g.items, byID, flows); len(affected) > 1 {
		fmt.Fprintf(&b, "Affected: %s\n\n", strings.Join(affected, ", "))
	}
	fmt.Fprintf(&b, "%s\n", wrap("Fix: "+pluralizeCounts(fill(fix, repl)), 90))
	if accept {
		b.WriteString("\n<details><summary>Accept this risk instead</summary>\n\n")
		if hasMod && g.cause != mod.Call {
			fmt.Fprintf(&b, "Resource: `%s`\n\n", g.cause)
		}
		b.WriteString(waiverSnippet(g.items, byID, flows))
		b.WriteString("</details>\n")
	}
	return b.String()
}

// dropACLAlternative removes "or ACL" wording from base explanations when
// rule context already states that ACLs are disabled.
func dropACLAlternative(s string) string {
	s = strings.ReplaceAll(s, " or an ACL", "")
	s = strings.ReplaceAll(s, " or ACL", "")
	return s
}

func whyHereLine(items []apiv1.Finding, enrich map[findingKey]enrichmentText, names map[string]string) string {
	for _, f := range items {
		if raw, ok := enrich[findingKey{f.RuleID, f.Target}]; ok && raw.WhyHere != "" {
			// Sanitize before filling names so underscore italics cannot eat
			// characters inside local display names (ecs_service, block_public_*).
			text := FillIDPlaceholders(SanitizeAdvisoryText(raw.WhyHere), names)
			if text == "" {
				return ""
			}
			return "Why this matters here: " + text
		}
	}
	return ""
}

func findingEvidenceLine(items []apiv1.Finding, names map[string]string) string {
	for _, f := range items {
		if len(f.Evidence) == 0 {
			continue
		}
		parts := make([]string, 0, len(f.Evidence))
		for _, e := range f.Evidence {
			parts = append(parts, FillIDPlaceholders(e, names))
		}
		return "Evidence: " + strings.Join(parts, "; ")
	}
	return ""
}

func fixHereLine(items []apiv1.Finding, enrich map[findingKey]enrichmentText, names map[string]string) string {
	for _, f := range items {
		if raw, ok := enrich[findingKey{f.RuleID, f.Target}]; ok && raw.FixHere != "" {
			text := FillIDPlaceholders(SanitizeAdvisoryText(raw.FixHere), names)
			if text == "" {
				return ""
			}
			return text
		}
	}
	return ""
}

func displayNames(byID map[string]client.Element, flows map[string]client.Flow) map[string]string {
	out := map[string]string{}
	for id, el := range byID {
		if el.Name != "" {
			out[id] = el.Name
		} else {
			out[id] = id
		}
	}
	for id, f := range flows {
		from, to := byID[f.From].Name, byID[f.To].Name
		if from == "" {
			from = f.From
		}
		if to == "" {
			to = f.To
		}
		out[id] = from + " → " + to
	}
	return out
}

func renderAdvisory(advisory *apiv1.Advisory, enrichments []apiv1.FindingEnrichment, opened []apiv1.Finding, texts map[string]apiv1.RuleText, byID map[string]client.Element, flows map[string]client.Flow) string {
	if advisoryEmpty(advisory) {
		return ""
	}
	names := displayNames(byID, flows)
	obs := novelObservations(advisory.Observations, enrichments, opened, texts, names)
	if len(obs) == 0 && advisory.Note == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("Advisory (AI)\n\n")
	b.WriteString("AI-generated — does not affect the merge gate.\n")
	if advisory.Note != "" && len(obs) == 0 {
		b.WriteByte('\n')
		b.WriteString(SanitizeAdvisoryText(advisory.Note))
		b.WriteByte('\n')
		return b.String()
	}
	if len(obs) > 3 {
		obs = obs[:3]
	}
	for _, o := range obs {
		b.WriteByte('\n')
		stride := strings.TrimSpace(o.Stride)
		if stride == "" {
			stride = "observation"
		}
		involved := make([]string, 0, len(o.ElementIDs))
		for _, id := range o.ElementIDs {
			if n, ok := names[id]; ok {
				involved = append(involved, "`"+n+"`")
			}
		}
		fmt.Fprintf(&b, "**%s**", strideLabel(stride))
		if len(involved) > 0 {
			fmt.Fprintf(&b, " · %s", strings.Join(involved, ", "))
		}
		b.WriteByte('\n')
		if text := FillIDPlaceholders(SanitizeAdvisoryText(o.Text), names); text != "" {
			fmt.Fprintf(&b, "%s\n", wrap(text, 90))
		}
		if sug := FillIDPlaceholders(SanitizeAdvisoryText(o.Suggestion), names); sug != "" {
			fmt.Fprintf(&b, "%s\n", wrap("Suggestion: "+sug, 90))
		}
	}
	return b.String()
}

// novelObservations drops advisory notes that restate a rule finding or a
// "Why this matters here" enrichment — the Advisory section is only for extras.
func novelObservations(obs []apiv1.AdvisoryObservation, enrichments []apiv1.FindingEnrichment, opened []apiv1.Finding, texts map[string]apiv1.RuleText, names map[string]string) []apiv1.AdvisoryObservation {
	said := make([]string, 0, len(enrichments)+len(opened)*3)
	for _, e := range enrichments {
		said = append(said, normAdvice(FillIDPlaceholders(e.WhyHere+" "+e.FixHere, names)))
	}
	for _, f := range opened {
		rt := texts[f.RuleID]
		said = append(said,
			normAdvice(rt.Explanation),
			normAdvice(rt.Threat),
			normAdvice(rt.GroupTitle),
			normAdvice(rt.Title),
			normAdvice(rt.Mitigation),
		)
	}
	var out []apiv1.AdvisoryObservation
	for _, o := range obs {
		blob := normAdvice(FillIDPlaceholders(o.Text+" "+o.Suggestion, names))
		if blob == "" || adviceRestates(blob, said) {
			continue
		}
		out = append(out, o)
	}
	return out
}

func normAdvice(s string) string {
	s = strings.ToLower(SanitizeAdvisoryText(s))
	s = strings.Join(strings.Fields(s), " ")
	s = strings.Trim(s, ".,:;!")
	return s
}

func adviceRestates(obs string, said []string) bool {
	for _, s := range said {
		if s == "" {
			continue
		}
		if obs == s || strings.Contains(obs, s) || strings.Contains(s, obs) {
			return true
		}
		if similarAdvice(obs, s) {
			return true
		}
	}
	return false
}

func similarAdvice(a, b string) bool {
	if len(a) < 24 || len(b) < 24 {
		return false
	}
	wa, wb := strings.Fields(a), strings.Fields(b)
	set := map[string]bool{}
	for _, w := range wa {
		if len(w) > 3 {
			set[w] = true
		}
	}
	if len(set) == 0 {
		return false
	}
	hit := 0
	for _, w := range wb {
		if len(w) > 3 && set[w] {
			hit++
		}
	}
	den := len(set)
	if n := 0; true {
		for _, w := range wb {
			if len(w) > 3 {
				n++
			}
		}
		if n < den {
			den = n
		}
	}
	if den == 0 {
		return false
	}
	return float64(hit)/float64(den) >= 0.6
}

func strideLabel(s string) string {
	// Same lowercase style as metaLine / strideText (e.g. "information disclosure").
	return strings.ReplaceAll(strings.TrimSpace(s), "_", " ")
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

// noLongerTitle rewrites a control-failure headline when the control was
// mitigated in the baseline ("does not block" → "no longer blocks").
func noLongerTitle(title string) string {
	const old = " does not "
	if i := strings.Index(title, old); i >= 0 {
		rest := title[i+len(old):]
		verb, after, ok := strings.Cut(rest, " ")
		if !ok {
			verb, after = rest, ""
		}
		if verb != "" && !strings.HasSuffix(verb, "s") {
			verb += "s"
		}
		if after != "" {
			return title[:i] + " no longer " + verb + " " + after
		}
		return title[:i] + " no longer " + verb
	}
	return title
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

func metaLine(g causeGroup, rule apiv1.RuleText, locs map[string]client.SourceLocation, mod client.ModuleCause, hasMod bool) string {
	sev := g.severity()
	stride := strideText(rule.Stride)
	if hasMod {
		where := mod.Location.String()
		if len(mod.Inputs) > 0 {
			// Agree with SARIF: point at the first attributed input line, not the module header.
			if region, ok := client.ModuleInputRegion(locs, mod.Call, mod.Inputs); ok {
				where = region.String()
			}
			return fmt.Sprintf("`%s` · %s · %s · %s · %s", mod.Call, formatInputs(mod.Inputs), where, sev, stride)
		}
		return fmt.Sprintf("`%s` · %s · %s · %s", mod.Call, where, sev, stride)
	}
	where := g.cause
	field := ""
	if len(rule.Pass) > 0 {
		field = rule.Pass[0].Field
	}
	if loc, ok := client.LookupCauseLocation(locs, g.cause, field); ok {
		where = loc.String()
	}
	return fmt.Sprintf("`%s` · %s · %s · %s", g.cause, where, sev, stride)
}

func formatInputs(inputs []string) string {
	parts := make([]string, len(inputs))
	for i, in := range inputs {
		parts[i] = "`" + in + "`"
	}
	return strings.Join(parts, ", ")
}

// moduleInputFix builds a fix line from known module inputs.
// An empty result means the caller should keep the rule remediation text.
// Each input gets a fix that matches its type; unknown inputs force a fallback.
func moduleInputFix(inputs []string) string {
	if len(inputs) == 0 {
		return ""
	}
	var boolInputs []string
	var parts []string
	for _, in := range inputs {
		switch in {
		case "block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets":
			boolInputs = append(boolInputs, in)
		case "public_access_prevention":
			parts = append(parts, "Set `"+in+"` to `\"enforced\"`")
		case "task_exec_secret_arns":
			parts = append(parts, "Set `"+in+"` to the specific secret ARN(s) instead of \"*\"")
		case "task_exec_ssm_param_arns":
			parts = append(parts, "Set `"+in+"` to the specific parameter ARN(s) instead of \"*\"")
		case "task_exec_iam_statements":
			parts = append(parts, "Scope GetSecretValue in `"+in+"` to the secret ARN in Resource, not \"*\"")
		default:
			return ""
		}
	}
	if len(boolInputs) > 0 {
		parts = append([]string{"Set " + formatInputs(boolInputs) + " to true"}, parts...)
	}
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += "; " + strings.ToLower(parts[i][:1]) + parts[i][1:]
	}
	return out + "."
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

func waiverSnippet(items []apiv1.Finding, byID map[string]client.Element, flows map[string]client.Flow) string {
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
	b.WriteString("Add to `.fray/waivers.yml`:\n\n")
	b.WriteString("```yaml\n")
	b.WriteString("version: 1\nwaivers:\n")
	for i, row := range rows {
		id := fmt.Sprintf("waiver-%d", i+1)
		fmt.Fprintf(&b, "  - id: %s\n", id)
		fmt.Fprintf(&b, "    rule: %s\n", row.rule)
		if strings.ContainsAny(row.address, " :") {
			fmt.Fprintf(&b, "    address: %q\n", row.address)
		} else {
			fmt.Fprintf(&b, "    address: %s\n", row.address)
		}
		b.WriteString("    reason: \"<why this risk is acceptable — min 10 chars>\"\n")
		b.WriteString("    owner: \"@security-eng\"\n")
		b.WriteString("    expires: \"YYYY-MM-DD\"\n")
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
		"{scope}":   scopeTerm(providerKey(resourceType(g.cause))),
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
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	// Display names from the parser (e.g. "uploads bucket") are already readable.
	if strings.Contains(name, " ") {
		return strings.ToUpper(name[:1]) + name[1:]
	}
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

// scopeTerm is the provider's word for the tenancy boundary that IAM grants cover.
func scopeTerm(provider string) string {
	switch provider {
	case "aws", "cloudflare":
		return "account"
	case "gcp":
		return "project"
	default:
		return "project"
	}
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

// pluralizeCounts turns "1 secrets" into "1 secret" (and the same for a few
// other known count nouns used in rule copy).
func pluralizeCounts(s string) string {
	for _, plural := range []string{"secrets", "buckets", "findings", "issues"} {
		singular := strings.TrimSuffix(plural, "s")
		s = strings.ReplaceAll(s, "1 "+plural, "1 "+singular)
	}
	return s
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

// CauseAddress is the Terraform address that caused the finding, used for
// source locations in PR comments and SARIF.
func CauseAddress(f apiv1.Finding, rule apiv1.RuleText, byID map[string]client.Element, flows map[string]client.Flow) string {
	if f.Status == "open" || f.Status == "" {
		if field, _ := failedAttribute(rule, f.Target, byID, flows); field != "" {
			if cause := causeForField(f.Target, field, byID, flows); cause != "" {
				return cause
			}
		}
	}
	return defaultCause(f.Target, byID, flows)
}

func causeOf(f apiv1.Finding, rule apiv1.RuleText, byID map[string]client.Element, flows map[string]client.Flow) string {
	return CauseAddress(f, rule, byID, flows)
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
