package version_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fluong/fray/version"
)

func TestRuleDocPagesAndHelpURIPattern(t *testing.T) {
	dir := filepath.Join("..", "docs", "rules")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "FR-") || !strings.HasSuffix(name, ".md") {
			continue
		}
		id := strings.TrimSuffix(name, ".md")
		if !version.RuleIDRe.MatchString(id) {
			t.Errorf("%s: filename id does not match RuleIDRe", name)
			continue
		}
		page := filepath.Join(dir, name)
		if _, err := os.Stat(page); err != nil {
			t.Errorf("missing page for %s: %v", id, err)
		}
		u := version.RuleDocURL(id)
		want := version.InformationURI + "/blob/main/docs/rules/" + id + ".md"
		if u != want {
			t.Errorf("RuleDocURL(%s)=%q want %q", id, u, want)
		}
		if !strings.HasSuffix(u, "/"+name) {
			t.Errorf("helpUri %q does not end with page filename %s", u, name)
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		t.Fatal("no docs/rules/FR-*.md pages found")
	}
	if version.RuleDocURL("not-a-rule") != "" {
		t.Fatal("RuleDocURL must reject non-catalog ids")
	}
}
