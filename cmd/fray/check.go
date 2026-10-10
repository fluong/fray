package main

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fluong/fray/client"
	"github.com/fluong/fray/usermsg"
)

// checkOutcome is the result of one setup check row.
type checkOutcome string

const (
	checkPass checkOutcome = "pass"
	checkWarn checkOutcome = "warn"
	checkFail checkOutcome = "fail"
)

type checkRow struct {
	Name    string
	Outcome checkOutcome
	Detail  string // human text; includes remedy when fail/warn
}

// runSetupCheck validates local Action/CLI wiring and calls GET /v1/readiness.
// Returns process exit code: 0 if no failures (warnings/skipped OK), 1 if any fail.
func runSetupCheck(opt options) int {
	if opt.OIDCToken == "" {
		opt.OIDCToken = os.Getenv("FRAY_OIDC_TOKEN")
	}
	rows := runSetupChecks(opt)
	writeSetupCheckSummary(rows)
	for _, r := range rows {
		switch r.Outcome {
		case checkFail:
			annotateError(r.Name + ": " + r.Detail)
		case checkWarn:
			annotateWarning(r.Name + ": " + r.Detail)
		}
	}
	for _, r := range rows {
		if r.Outcome == checkFail {
			return 1
		}
	}
	return 0
}

func runSetupChecks(opt options) []checkRow {
	var rows []checkRow
	apiRow := checkAPIURL(opt.Remote)
	rows = append(rows, apiRow)
	rows = append(rows, checkWorkingDirectory(opt.Source, opt.ExternalPlan)...)
	rows = append(rows, checkFrayYAML(opt.Config))
	rows = append(rows, checkRedactionKey(opt.Config))
	rows = append(rows, checkWaiversFile(opt.Waivers))
	rows = append(rows, checkLegacyMitigationsRow(opt.Mitigations, opt.Waivers))
	rows = append(rows, checkPlanOrTerraform(opt))
	if apiRow.Outcome == checkPass {
		rows = append(rows, callReadinessProbe(opt)...)
	} else {
		rows = append(rows, checkRow{
			Name:    "server readiness",
			Outcome: checkSkipped,
			Detail:  "skipped: api-url invalid",
		})
	}
	return rows
}

func checkAPIURL(remote string) checkRow {
	const name = "api-url"
	if strings.TrimSpace(remote) == "" {
		return checkRow{
			Name:    name,
			Outcome: checkFail,
			Detail:  usermsg.SeeTroubleshooting("api-url is required and must be an https:// URL with a host"),
		}
	}
	u, err := url.Parse(remote)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return checkRow{
			Name:    name,
			Outcome: checkFail,
			Detail:  usermsg.SeeTroubleshooting("api-url must be an https:// URL with a host (for example https://api.getfray.dev)"),
		}
	}
	return checkRow{Name: name, Outcome: checkPass, Detail: "https URL with host"}
}

func checkWorkingDirectory(source string, externalPlan bool) []checkRow {
	const name = "working-directory"
	display := source
	if display == "" {
		display = "."
	}
	st, err := os.Stat(source)
	if err != nil || !st.IsDir() {
		return []checkRow{{
			Name:    name,
			Outcome: checkFail,
			Detail:  usermsg.SeeTroubleshooting(usermsg.WorkdirMissing(display)),
		}}
	}
	matches, _ := filepath.Glob(filepath.Join(source, "*.tf"))
	if len(matches) == 0 {
		row := checkRow{
			Name:    "terraform sources",
			Detail:  usermsg.SeeTroubleshooting(usermsg.NoTerraformFiles(display)),
			Outcome: checkWarn,
		}
		if !externalPlan {
			// validate needs .tf; fail closed when we would run terraform.
			row.Outcome = checkFail
		}
		return []checkRow{
			{Name: name, Outcome: checkPass, Detail: "directory exists"},
			row,
		}
	}
	return []checkRow{{
		Name:    name,
		Outcome: checkPass,
		Detail:  fmt.Sprintf("directory exists (%d .tf file(s))", len(matches)),
	}}
}

func checkFrayYAML(configPath string) checkRow {
	const name = "fray.yaml"
	raw, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return checkRow{
				Name:    name,
				Outcome: checkFail,
				Detail:  usermsg.SeeTroubleshooting(usermsg.FrayYAMLMissing(configPath)),
			}
		}
		return checkRow{
			Name:    name,
			Outcome: checkFail,
			Detail:  usermsg.SeeTroubleshooting("fray.yaml: " + err.Error()),
		}
	}
	if _, err := client.RedactionDisabled(raw); err != nil {
		return checkRow{
			Name:    name,
			Outcome: checkFail,
			Detail:  usermsg.SeeTroubleshooting("fray.yaml: " + err.Error()),
		}
	}
	return checkRow{Name: name, Outcome: checkPass, Detail: "present and parseable"}
}

func checkRedactionKey(configPath string) checkRow {
	const name = "redaction-key"
	raw, err := os.ReadFile(configPath)
	if err != nil {
		// fray.yaml check already failed; skip duplicate noise as pass-through warn.
		return checkRow{
			Name:    name,
			Outcome: checkWarn,
			Detail:  "skipped: fray.yaml not readable",
		}
	}
	off, err := client.RedactionDisabled(raw)
	if err != nil {
		return checkRow{
			Name:    name,
			Outcome: checkWarn,
			Detail:  "skipped: fray.yaml not parseable",
		}
	}
	if off {
		return checkRow{
			Name:    name,
			Outcome: checkPass,
			Detail:  "redaction: off in fray.yaml (key not required)",
		}
	}
	if _, err := client.LoadRedactionKey(); err != nil {
		return checkRow{
			Name:    name,
			Outcome: checkFail,
			Detail:  planFileUserError(err), // append troubleshooting only if missing
		}
	}
	return checkRow{Name: name, Outcome: checkPass, Detail: "FRAY_REDACTION_KEY present (64 hex)"}
}

func checkWaiversFile(path string) checkRow {
	const name = "waivers"
	if path == "" {
		return checkRow{Name: name, Outcome: checkPass, Detail: "no waivers path (OK)"}
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return checkRow{Name: name, Outcome: checkPass, Detail: "file missing (OK — no waivers)"}
		}
		return checkRow{
			Name:    name,
			Outcome: checkFail,
			Detail:  usermsg.SeeTroubleshooting(path + ": " + err.Error()),
		}
	}
	if _, err := loadWaivers(path, time.Now().UTC()); err != nil {
		return checkRow{
			Name:    name,
			Outcome: checkFail,
			Detail:  usermsg.SeeTroubleshooting(err.Error()),
		}
	}
	return checkRow{Name: name, Outcome: checkPass, Detail: "present and valid"}
}

func checkLegacyMitigationsRow(mitigationsPath, waiversPath string) checkRow {
	const name = "legacy mitigations.yaml"
	waiverCount := 0
	if waiversPath != "" {
		if entries, err := loadWaivers(waiversPath, time.Now().UTC()); err == nil {
			waiverCount = len(entries)
		}
	}
	if err := checkLegacyMitigations(mitigationsPath, waiverCount); err != nil {
		return checkRow{
			Name:    name,
			Outcome: checkFail,
			Detail:  usermsg.SeeTroubleshooting(err.Error()),
		}
	}
	return checkRow{Name: name, Outcome: checkPass, Detail: "absent or empty (OK)"}
}

func checkPlanOrTerraform(opt options) checkRow {
	const name = "plan / terraform"
	if opt.ExternalPlan {
		if opt.Plan == "" {
			return checkRow{
				Name:    name,
				Outcome: checkFail,
				Detail:  usermsg.SeeTroubleshooting("plan-file path is empty"),
			}
		}
		data, err := client.LoadPlanFile(opt.Plan)
		if err != nil {
			return checkRow{
				Name:    name,
				Outcome: checkFail,
				Detail:  planFileUserError(err),
			}
		}
		// LoadPlanFile already ValidatePlanJSON; keep explicit for the check name.
		if err := client.ValidatePlanJSON(data); err != nil {
			return checkRow{
				Name:    name,
				Outcome: checkFail,
				Detail:  planFileUserError(err),
			}
		}
		return checkRow{
			Name:    name,
			Outcome: checkPass,
			Detail:  "plan-file exists and is valid terraform show -json",
		}
	}
	return checkTerraformInitValidate(opt.Source)
}

// terraformCommand is overridden in tests.
var terraformCommand = func(dir string, args ...string) *exec.Cmd {
	cmd := exec.Command("terraform", args...)
	cmd.Dir = dir
	return cmd
}

func checkTerraformInitValidate(source string) checkRow {
	const name = "plan / terraform"
	display := source
	if display == "" {
		display = "."
	}
	initOut, err := runTerraform(source, "init", "-backend=false", "-input=false", "-no-color")
	if err != nil {
		return checkRow{
			Name:    name,
			Outcome: checkFail,
			Detail: usermsg.SeeTroubleshooting(
				"terraform init -backend=false failed in " + display +
					". Setup check runs init without a backend and terraform validate — ensure providers can download, or pass plan-file. " +
					strings.TrimSpace(initOut),
			),
		}
	}
	valOut, err := runTerraform(source, "validate", "-no-color")
	if err != nil {
		return checkRow{
			Name:    name,
			Outcome: checkFail,
			Detail: usermsg.SeeTroubleshooting(
				"terraform validate failed in " + display +
					". Fix configuration errors, or pass plan-file. " +
					strings.TrimSpace(valOut),
			),
		}
	}
	return checkRow{
		Name:    name,
		Outcome: checkPass,
		Detail:  "terraform init -backend=false and validate succeeded",
	}
}

func runTerraform(dir string, args ...string) (string, error) {
	cmd := terraformCommand(dir, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

const markdownTableCellMax = 300

// markdownTableCell makes a value safe for a GitHub Markdown table cell:
// pipes escaped, CR/LF → space, trimmed to 300 runes with an ellipsis.
func markdownTableCell(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", `\|`)
	runes := []rune(s)
	if len(runes) > markdownTableCellMax {
		s = string(runes[:markdownTableCellMax]) + "…"
	}
	return s
}

func writeSetupCheckSummary(rows []checkRow) {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	text := formatSetupCheckSummary(rows)
	fmt.Fprint(os.Stderr, text)
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	_, _ = f.WriteString(text)
	_ = f.Close()
}

func formatSetupCheckSummary(rows []checkRow) string {
	var b strings.Builder
	b.WriteString("## Fray — setup check\n\n")
	b.WriteString("| Check | Result | Detail |\n")
	b.WriteString("|-------|--------|--------|\n")
	for _, r := range rows {
		b.WriteString("| ")
		b.WriteString(markdownTableCell(r.Name))
		b.WriteString(" | ")
		b.WriteString(markdownTableCell(string(r.Outcome)))
		b.WriteString(" | ")
		b.WriteString(markdownTableCell(r.Detail))
		b.WriteString(" |\n")
	}
	return b.String()
}
