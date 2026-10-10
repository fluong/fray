package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCallReadinessProbeReadyTrue(t *testing.T) {
	body := []byte(`{"ready":true,"checks":[
		{"check":"oidc","status":"ok","code":"","message":""},
		{"check":"installation","status":"ok","code":"","message":""},
		{"check":"repo_cap","status":"ok","code":"","message":""},
		{"check":"repo_enrolled","status":"ok","code":"","message":""}
	]}`)
	prev := readinessGET
	t.Cleanup(func() { readinessGET = prev })
	readinessGET = func(baseURL, token string) (int, http.Header, []byte, error) {
		if token != "tok-secret" {
			t.Fatalf("token=%q", token)
		}
		return http.StatusOK, http.Header{}, body, nil
	}
	rows := callReadinessProbe(options{Remote: "https://api.getfray.dev", OIDCToken: "tok-secret"})
	if len(rows) != 4 {
		t.Fatalf("rows=%d %+v", len(rows), rows)
	}
	for _, r := range rows {
		if r.Outcome != checkPass {
			t.Fatalf("%+v", r)
		}
	}
	summary := renderSetupCheckSummary(rows)
	if !strings.Contains(summary, "| oidc | pass |") {
		t.Fatalf("summary:\n%s", summary)
	}
}

func TestCallReadinessProbeFailCodes(t *testing.T) {
	cases := []struct {
		code    string
		checks  string
		wantSub string
	}{
		{
			code: "installation_missing",
			checks: `[{"check":"oidc","status":"ok"},
				{"check":"installation","status":"fail","code":"installation_missing","message":"not installed"},
				{"check":"repo_cap","status":"skipped"},{"check":"repo_enrolled","status":"skipped"}]`,
			wantSub: "Install or re-enable",
		},
		{
			code: "installation_inactive",
			checks: `[{"check":"oidc","status":"ok"},
				{"check":"installation","status":"fail","code":"installation_inactive","message":"suspended"},
				{"check":"repo_cap","status":"skipped"},{"check":"repo_enrolled","status":"skipped"}]`,
			wantSub: "Install or re-enable",
		},
		{
			code: "installation_over_cap",
			checks: `[{"check":"oidc","status":"ok"},{"check":"installation","status":"ok"},
				{"check":"repo_cap","status":"fail","code":"installation_over_cap","message":"too many"},
				{"check":"repo_enrolled","status":"skipped"}]`,
			wantSub: "Reduce the repositories",
		},
		{
			code: "repo_not_enrolled",
			checks: `[{"check":"oidc","status":"ok"},{"check":"installation","status":"ok"},
				{"check":"repo_cap","status":"ok"},
				{"check":"repo_enrolled","status":"fail","code":"repo_not_enrolled","message":"not selected"}]`,
			wantSub: "Add this repository",
		},
		{
			code: "repo_mismatch",
			checks: `[{"check":"oidc","status":"fail","code":"repo_mismatch","message":"mismatch"},
				{"check":"installation","status":"skipped"},{"check":"repo_cap","status":"skipped"},
				{"check":"repo_enrolled","status":"skipped"}]`,
			wantSub: "Contact support",
		},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			raw := []byte(`{"ready":false,"checks":` + tc.checks + `}`)
			prev := readinessGET
			t.Cleanup(func() { readinessGET = prev })
			readinessGET = func(string, string) (int, http.Header, []byte, error) {
				return http.StatusOK, nil, raw, nil
			}
			rows := callReadinessProbe(options{Remote: "https://api.getfray.dev", OIDCToken: "t"})
			var fail *checkRow
			for i := range rows {
				if rows[i].Outcome == checkFail {
					fail = &rows[i]
					break
				}
			}
			if fail == nil {
				t.Fatalf("want fail: %+v", rows)
			}
			if !strings.Contains(fail.Detail, tc.code) {
				t.Fatalf("detail=%q", fail.Detail)
			}
			if !strings.Contains(fail.Detail, tc.wantSub) {
				t.Fatalf("detail=%q want remedy %q", fail.Detail, tc.wantSub)
			}
			if !strings.Contains(fail.Detail, "https://github.com/fluong/fray#troubleshooting") {
				t.Fatalf("detail=%q missing troubleshooting link", fail.Detail)
			}
		})
	}
}

func TestCallReadinessProbeSkippedRows(t *testing.T) {
	body := []byte(`{"ready":false,"checks":[
		{"check":"oidc","status":"ok"},
		{"check":"installation","status":"fail","code":"installation_inactive","message":"suspended"},
		{"check":"repo_cap","status":"skipped"},
		{"check":"repo_enrolled","status":"skipped"}
	]}`)
	prev := readinessGET
	t.Cleanup(func() { readinessGET = prev })
	readinessGET = func(string, string) (int, http.Header, []byte, error) {
		return http.StatusOK, nil, body, nil
	}
	rows := callReadinessProbe(options{Remote: "https://api.getfray.dev", OIDCToken: "t"})
	summary := renderSetupCheckSummary(rows)
	if !strings.Contains(summary, "| repo_cap | skipped |") {
		t.Fatalf("%s", summary)
	}
}

func TestCallReadinessProbeUnknownCheckAndCode(t *testing.T) {
	body := []byte(`{"ready":false,"checks":[
		{"check":"future_check","status":"fail","code":"brand_new_code","message":"something","extra":"ignored"}
	]}`)
	prev := readinessGET
	t.Cleanup(func() { readinessGET = prev })
	readinessGET = func(string, string) (int, http.Header, []byte, error) {
		return http.StatusOK, nil, body, nil
	}
	rows := callReadinessProbe(options{Remote: "https://api.getfray.dev", OIDCToken: "t"})
	if len(rows) != 1 || rows[0].Name != "future_check" || rows[0].Outcome != checkFail {
		t.Fatalf("%+v", rows)
	}
	if !strings.Contains(rows[0].Detail, "brand_new_code") {
		t.Fatalf("%q", rows[0].Detail)
	}
	_ = json.Valid(body)
}

func TestCallReadinessProbeHTTPStatuses(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		header      http.Header
		err         error
		wantOutcome checkOutcome
		wantSubstr  string
		wantExit    int
	}{
		{name: "401", status: 401, body: "unauthorized\n", wantOutcome: checkFail, wantSubstr: "token rejected by Fray", wantExit: 1},
		{name: "429", status: 429, body: `{"error":"rate_limited"}`, header: http.Header{"Retry-After": []string{"12"}}, wantOutcome: checkWarn, wantSubstr: "rate-limited", wantExit: 0},
		{name: "503", status: 503, body: `{"ready":false,"error":"temporarily_unavailable"}`, wantOutcome: checkFail, wantSubstr: "Fray API unavailable", wantExit: 1},
		{name: "500", status: 500, body: "oops", wantOutcome: checkFail, wantSubstr: "Fray API unavailable", wantExit: 1},
		{name: "timeout", err: &timeoutError{}, wantOutcome: checkFail, wantSubstr: "Fray API unavailable", wantExit: 1},
		{name: "malformed", status: 200, body: "{not-json", wantOutcome: checkFail, wantSubstr: "unexpected response", wantExit: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prev := readinessGET
			t.Cleanup(func() { readinessGET = prev })
			readinessGET = func(string, string) (int, http.Header, []byte, error) {
				if tc.err != nil {
					return 0, nil, nil, tc.err
				}
				return tc.status, tc.header, []byte(tc.body), nil
			}
			dir := t.TempDir()
			opt := writeCheckFixture(t, dir)
			opt.ExternalPlan = true
			opt.Plan = filepath.Join(dir, "plan.json")
			_ = os.WriteFile(opt.Plan, []byte(`{"format_version":"1.2"}`), 0o644)
			opt.OIDCToken = "t"
			opt.Remote = "https://api.getfray.dev"
			t.Setenv("GITHUB_STEP_SUMMARY", filepath.Join(dir, "summary.md"))
			prevTF := terraformCommand
			t.Cleanup(func() { terraformCommand = prevTF })
			terraformCommand = func(string, ...string) *exec.Cmd {
				t.Fatal("terraform")
				return nil
			}
			rows := callReadinessProbe(opt)
			if len(rows) != 1 || rows[0].Outcome != tc.wantOutcome {
				t.Fatalf("%+v", rows)
			}
			if !strings.Contains(rows[0].Detail, tc.wantSubstr) {
				t.Fatalf("detail=%q want %q", rows[0].Detail, tc.wantSubstr)
			}
			if code := runSetupCheck(opt); code != tc.wantExit {
				t.Fatalf("exit=%d want %d", code, tc.wantExit)
			}
		})
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "context deadline exceeded" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestCallReadinessProbeOversizedBody(t *testing.T) {
	prev := readinessGET
	t.Cleanup(func() { readinessGET = prev })
	big := make([]byte, maxReadinessBody+1)
	for i := range big {
		big[i] = 'a'
	}
	readinessGET = func(string, string) (int, http.Header, []byte, error) {
		return http.StatusOK, nil, big, nil
	}
	rows := callReadinessProbe(options{Remote: "https://api.getfray.dev", OIDCToken: "t"})
	if len(rows) != 1 || rows[0].Outcome != checkFail || !strings.Contains(rows[0].Detail, "unexpected response") {
		t.Fatalf("%+v", rows)
	}
}

func TestRunSetupCheckCallsReadinessNotScans(t *testing.T) {
	dir := t.TempDir()
	opt := writeCheckFixture(t, dir)
	opt.ExternalPlan = true
	opt.Plan = filepath.Join(dir, "plan.json")
	if err := os.WriteFile(opt.Plan, []byte(`{"format_version":"1.2"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	opt.OIDCToken = "secret-oidc"
	opt.Remote = "https://api.getfray.dev"
	t.Setenv("GITHUB_STEP_SUMMARY", filepath.Join(dir, "summary.md"))

	var gotToken string
	prev := readinessGET
	t.Cleanup(func() { readinessGET = prev })
	readinessGET = func(baseURL, token string) (int, http.Header, []byte, error) {
		gotToken = token
		if strings.Contains(baseURL, "/v1/scans") {
			t.Fatal("must not call /v1/scans")
		}
		return http.StatusOK, nil, []byte(`{"ready":true,"checks":[{"check":"oidc","status":"ok"},{"check":"installation","status":"ok"},{"check":"repo_cap","status":"ok"},{"check":"repo_enrolled","status":"ok"}]}`), nil
	}
	prevTF := terraformCommand
	t.Cleanup(func() { terraformCommand = prevTF })
	terraformCommand = func(string, ...string) *exec.Cmd {
		t.Fatal("terraform")
		return nil
	}

	if code := runSetupCheck(opt); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if gotToken != "secret-oidc" {
		t.Fatalf("token=%q", gotToken)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "summary.md"))
	if !strings.Contains(string(raw), "| oidc | pass |") {
		t.Fatalf("%s", raw)
	}
}

func TestRepoNotEnrolledSummaryRendering(t *testing.T) {
	body := []byte(`{"ready":false,"checks":[
		{"check":"oidc","status":"ok","message":""},
		{"check":"installation","status":"ok"},
		{"check":"repo_cap","status":"ok"},
		{"check":"repo_enrolled","status":"fail","code":"repo_not_enrolled","message":"repository not selected"}
	]}`)
	prev := readinessGET
	t.Cleanup(func() { readinessGET = prev })
	readinessGET = func(string, string) (int, http.Header, []byte, error) {
		return http.StatusOK, nil, body, nil
	}
	rows := callReadinessProbe(options{Remote: "https://api.getfray.dev", OIDCToken: "t"})
	summary := renderSetupCheckSummary(rows)
	if !strings.Contains(summary, "| repo_enrolled | fail |") {
		t.Fatalf("%s", summary)
	}
	want := "repo_not_enrolled: repository not selected. Add this repository"
	if !strings.Contains(summary, want) {
		t.Fatalf("want %q in:\n%s", want, summary)
	}
	if !strings.Contains(summary, "See https://github.com/fluong/fray#troubleshooting") {
		t.Fatalf("%s", summary)
	}
}

func TestReadinessFailMessageEscapesTableCell(t *testing.T) {
	body := []byte(`{"ready":false,"checks":[
		{"check":"repo_enrolled","status":"fail","code":"repo_not_enrolled","message":"a|b\nc"}
	]}`)
	prev := readinessGET
	t.Cleanup(func() { readinessGET = prev })
	readinessGET = func(string, string) (int, http.Header, []byte, error) {
		return http.StatusOK, nil, body, nil
	}
	rows := callReadinessProbe(options{Remote: "https://api.getfray.dev", OIDCToken: "t"})
	summary := formatSetupCheckSummary(rows)
	lines := strings.Split(strings.TrimRight(summary, "\n"), "\n")
	var dataRows []string
	for _, line := range lines {
		if strings.HasPrefix(line, "| ") && !strings.HasPrefix(line, "| Check") && !strings.HasPrefix(line, "|---") {
			dataRows = append(dataRows, line)
		}
	}
	if len(dataRows) != 1 {
		t.Fatalf("want 1 data row, got %d:\n%s", len(dataRows), summary)
	}
	row := dataRows[0]
	if strings.Contains(row, "\n") {
		t.Fatalf("row spans multiple lines: %q", row)
	}
	if !strings.Contains(row, `a\|b c`) {
		t.Fatalf("want escaped pipe and newline→space in %q", row)
	}
	// Unescaped '|' would create extra columns; a valid row is "| a | b | c |".
	cols := splitMarkdownTableRow(row)
	if len(cols) != 3 {
		t.Fatalf("want 3 columns, got %d from %q", len(cols), row)
	}
}

func TestFormatReadinessFailPeriod(t *testing.T) {
	withPeriod := formatReadinessFail("repo_not_enrolled", "already ended.")
	if strings.Contains(withPeriod, "ended..") {
		t.Fatalf("double period: %q", withPeriod)
	}
	if !strings.HasPrefix(withPeriod, "repo_not_enrolled: already ended. Add this") {
		t.Fatalf("%q", withPeriod)
	}
	without := formatReadinessFail("repo_not_enrolled", "no period")
	if !strings.HasPrefix(without, "repo_not_enrolled: no period. Add this") {
		t.Fatalf("%q", without)
	}
}

func TestMarkdownTableCell(t *testing.T) {
	if got := markdownTableCell("a|b\nc\rd"); got != `a\|b c d` {
		t.Fatalf("%q", got)
	}
	long := strings.Repeat("x", markdownTableCellMax+10)
	got := markdownTableCell(long)
	if len([]rune(got)) != markdownTableCellMax+1 || !strings.HasSuffix(got, "…") {
		t.Fatalf("len=%d got=%q", len([]rune(got)), got[:20])
	}
}

func renderSetupCheckSummary(rows []checkRow) string {
	return formatSetupCheckSummary(rows)
}

// splitMarkdownTableRow splits a "| a | b | c |" line into cells, respecting \|.
func splitMarkdownTableRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	var cells []string
	var cur strings.Builder
	escaped := false
	for _, r := range line {
		if escaped {
			cur.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '|' {
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteRune(r)
	}
	cells = append(cells, strings.TrimSpace(cur.String()))
	return cells
}

func TestDefaultReadinessGETUsesBearerAndPath(t *testing.T) {
	var gotAuth, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ready":true,"checks":[]}`))
	}))
	t.Cleanup(srv.Close)

	status, _, body, err := defaultReadinessGET(srv.URL, "oidc-tok")
	if err != nil {
		t.Fatal(err)
	}
	if status != 200 || !strings.Contains(string(body), "ready") {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if gotAuth != "Bearer oidc-tok" {
		t.Fatalf("Authorization=%q", gotAuth)
	}
	if gotPath != "/v1/readiness" || gotMethod != http.MethodGet {
		t.Fatalf("method=%s path=%q", gotMethod, gotPath)
	}
}
