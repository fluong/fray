package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
	"github.com/fluong/fray/render"
	"github.com/fluong/fray/usermsg"
)

// errEnrollmentRejected is returned when fail-on-unenrolled is true and the
// API rejected the scan with a known enrollment code. Annotations are already
// written; main exits 1 without printing the error again.
var errEnrollmentRejected = errors.New("enrollment rejected")

func runRemote(opt options) (bool, error) {
	if opt.OIDCToken == "" {
		opt.OIDCToken = os.Getenv("FRAY_OIDC_TOKEN")
	}
	if opt.APIKey == "" {
		opt.APIKey = os.Getenv("FRAY_API_KEY")
	}
	if !opt.DryRun && opt.OIDCToken == "" && opt.APIKey == "" {
		return false, fmt.Errorf("-remote requires FRAY_OIDC_TOKEN/-oidc-token or FRAY_API_KEY/-api-key")
	}
	if opt.DefaultBranch == "" {
		return false, fmt.Errorf("-default-branch is required with -remote")
	}
	if opt.Branch == "" {
		opt.Branch = opt.DefaultBranch
	}
	isDefault := opt.Branch == opt.DefaultBranch

	plan, err := os.ReadFile(opt.Plan)
	if err != nil {
		return false, err
	}
	cfg, err := os.ReadFile(opt.Config)
	if err != nil {
		return false, err
	}
	redactionOff, err := client.RedactionDisabled(cfg)
	if err != nil {
		return false, err
	}

	doc, warnings, err := client.Parse(plan, cfg, opt.Declared, client.Source{
		Repo:     opt.Repo,
		Commit:   opt.Commit,
		Tool:     "terraform",
		Fidelity: "plan",
	}, opt.Source)
	if err != nil {
		return false, err
	}
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}

	now := time.Now().UTC()
	waiverEntries, err := loadWaivers(opt.Waivers, now)
	if err != nil {
		return false, err
	}
	if err := checkLegacyMitigations(opt.Mitigations, len(waiverEntries)); err != nil {
		return false, err
	}
	accepted, err := resolveWaivers(doc, waiverEntries)
	if err != nil {
		return false, err
	}

	wireDoc := doc
	idMap := client.IDMap{}
	repoForRequest := opt.Repo
	fieldsHashed := 0

	if redactionOff {
		fmt.Fprintln(os.Stderr, "WARNING: redaction is OFF — plaintext names and addresses will be sent to Fray.")
		fmt.Fprintln(os.Stderr, "WARNING: redaction: off is client-side only; the hosted API rejects unredacted payloads unless the org allows it.")
	} else {
		key, err := client.LoadRedactionKey()
		if err != nil {
			return false, err
		}
		var redacted client.DFD
		redacted, idMap, err = client.Redact(doc, key)
		if err != nil {
			return false, err
		}
		wireDoc = redacted
		fieldsHashed = idMap.FieldsHashed
		repoForRequest = wireDoc.Source.Repo
		for i := range accepted {
			accepted[i].TargetID = idMap.RemapAcceptedTarget(accepted[i].TargetID)
		}
	}

	rawDFD, err := client.Marshal(wireDoc)
	if err != nil {
		return false, err
	}

	reqBody, err := json.Marshal(apiv1.ScanRequest{
		DFD:                 rawDFD,
		AcceptedMitigations: accepted,
		Repo:                repoForRequest,
		Commit:              opt.Commit,
		IsDefaultBranch:     isDefault,
		BaseCommit:          opt.BaseCommit,
	})
	if err != nil {
		return false, err
	}

	if !redactionOff {
		if err := client.AssertNoPlaintext(reqBody, idMap.Plaintext); err != nil {
			return false, err
		}
	}

	if opt.ShowPayload || opt.DryRun {
		fmt.Println(string(reqBody))
		if redactionOff {
			fmt.Fprintf(os.Stderr, "payload summary: redaction off — plaintext names/addresses present\n")
		} else {
			// Full-fixture AWS web-app: 5 addresses + 1 signal + source.repo = 7 HMAC
			// fields. request.repo reuses the same digest (second slot); the guard
			// scans the entire POST body, including both.
			repoSlots := 0
			if wireDoc.Source.Repo != "" {
				repoSlots = 1
				if repoForRequest == wireDoc.Source.Repo {
					repoSlots = 2
				}
			}
			fmt.Fprintf(os.Stderr, "payload summary: %d fields hashed (%d repo slots in payload), 0 plaintext names/addresses\n", fieldsHashed, repoSlots)
		}
	}
	if opt.PayloadOut != "" {
		if err := os.WriteFile(opt.PayloadOut, reqBody, 0o644); err != nil {
			return false, err
		}
	}
	if opt.DryRun {
		return false, nil
	}

	url := strings.TrimRight(opt.Remote, "/") + "/v1/scans"
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return false, err
	}
	token := opt.OIDCToken
	if token == "" {
		token = opt.APIKey
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	clientHTTP := &http.Client{Timeout: 60 * time.Second}
	httpResp, err := clientHTTP.Do(httpReq)
	if err != nil {
		return false, errors.New(usermsg.SeeTroubleshooting(usermsg.APIRequestFailed(err.Error())))
	}
	defer httpResp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, maxEnrollmentBody+1))
	if err != nil {
		return false, err
	}
	if len(respBody) > maxEnrollmentBody {
		return false, fmt.Errorf("remote scan: response body too large")
	}
	if httpResp.StatusCode != http.StatusOK {
		ct := httpResp.Header.Get("Content-Type")
		if code, serverMsg, ok := parseEnrollmentRejection(httpResp.StatusCode, ct, respBody); ok {
			reportEnrollment(code, serverMsg, opt.FailOnUnenrolled)
			if err := writeEnrollmentMarker(opt.Out, code, opt.FailOnUnenrolled); err != nil {
				return false, err
			}
			if opt.FailOnUnenrolled {
				return false, errEnrollmentRejected
			}
			// Skip: no SARIF, no PR comment — marker tells scan.sh to set skipped.
			return false, nil
		}
		if msg, retryAfter, ok := parseRateLimited(httpResp.StatusCode, ct, respBody, httpResp.Header.Get("Retry-After")); ok {
			reportRateLimitedStderr(msg, retryAfter)
			if err := writeRateLimitedMarker(opt.Out, msg, retryAfter); err != nil {
				return false, err
			}
			// Soft-skip (same exit class as enrollment skip): marker tells
			// scan.sh to warn or fail based on fail-on-rate-limit.
			return false, nil
		}
		if msg := waiverErrorMessage(respBody); msg != "" {
			// Server validation (horizons, schema) — show verbatim.
			return false, errors.New(msg)
		}
		detail := fmt.Sprintf("%s: %s", httpResp.Status, truncate(respBody, 200))
		return false, errors.New(usermsg.SeeTroubleshooting(usermsg.APIRequestFailed(detail)))
	}

	var resp apiv1.ScanResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return false, err
	}
	var probe struct {
		Waivers json.RawMessage `json:"waivers"`
	}
	_ = json.Unmarshal(respBody, &probe)
	waiversReported := len(probe.Waivers) > 0 && string(probe.Waivers) != "null"

	if !redactionOff {
		remapFindings(&resp.Findings, idMap)
		remapFindingsSlice(resp.Diff.New, idMap)
		remapFindingsSlice(resp.Diff.Resolved, idMap)
		for i := range resp.Gate.Reasons {
			resp.Gate.Reasons[i].TargetID = idMap.RemapID(resp.Gate.Reasons[i].TargetID)
		}
		if resp.Baseline.Findings != nil {
			remapFindings(resp.Baseline.Findings, idMap)
		}
		remapAdvisory(resp.Advisory, idMap)
		remapEnrichments(resp.Enrichments, idMap)
	}

	locs, err := client.ResourceLocations(opt.Source)
	if err != nil {
		return false, err
	}
	headArgs, err := client.ModuleArguments(opt.Source)
	if err != nil {
		return false, err
	}
	var changedInputs map[string][]string
	if opt.BaseSource != "" {
		baseArgs, err := client.ModuleArguments(opt.BaseSource)
		if err != nil {
			return false, fmt.Errorf("base-source: %w", err)
		}
		changedInputs = client.ChangedInputsByCall(baseArgs, headArgs)
	}
	texts := resp.RuleTexts

	if err := os.MkdirAll(opt.Out, 0o755); err != nil {
		return false, err
	}
	body, err := apiv1.MarshalFindings(resp.Findings)
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(filepath.Join(opt.Out, "findings.json"), body, 0o644); err != nil {
		return false, err
	}
	report := render.ThreatModel(doc, resp.Findings, texts, toRenderWaiverEntries(waiverEntries), locs)
	if err := os.WriteFile(filepath.Join(opt.Out, "threat-model.md"), []byte(report), 0o644); err != nil {
		return false, err
	}
	sarif, err := render.SARIF(doc, resp.Findings, texts, locs, changedInputs)
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(filepath.Join(opt.Out, "findings.sarif"), sarif, 0o644); err != nil {
		return false, err
	}

	reportWaivers(resp.Waivers, waiversReported)

	// Always write a PR comment on a successful scan. With no baseline findings,
	// render absolute-mode open findings and explain that comparison starts later.
	baselineNote := resp.Baseline.Note
	var baseline apiv1.Findings
	if resp.Baseline.Findings != nil {
		baseline = *resp.Baseline.Findings
	} else {
		baseline = apiv1.Findings{SchemaVersion: "finding/v1"}
		if baselineNote == "" {
			baselineNote = render.NoBaselineNote
		}
	}
	comment := render.PRComment(doc, resp.Findings, baseline, texts, locs, changedInputs, baselineNote, resp.Advisory, resp.Enrichments, resp.Waivers, waiversReported)
	if err := os.WriteFile(filepath.Join(opt.Out, "pr-comment.md"), []byte(comment), 0o644); err != nil {
		return false, err
	}
	return resp.Gate.Blocked, nil
}

func waiverErrorMessage(body []byte) string {
	var errBody struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &errBody) != nil || errBody.Message == "" {
		return ""
	}
	return errBody.Message
}

func reportWaivers(w *apiv1.Waivers, reported bool) {
	text := render.WaiversSummary(w, reported)
	if text == "" {
		return
	}
	fmt.Fprint(os.Stderr, text)
	if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return
		}
		_, _ = f.WriteString(text)
		_ = f.Close()
	}
}

func remapFindings(f *apiv1.Findings, m client.IDMap) {
	if f == nil {
		return
	}
	remapFindingsSlice(f.Findings, m)
}

func remapFindingsSlice(findings []apiv1.Finding, m client.IDMap) {
	for i := range findings {
		findings[i].Target = m.RemapID(findings[i].Target)
	}
}

func remapAdvisory(a *apiv1.Advisory, m client.IDMap) {
	if a == nil {
		return
	}
	for i := range a.Observations {
		o := &a.Observations[i]
		for j := range o.ElementIDs {
			o.ElementIDs[j] = m.RemapID(o.ElementIDs[j])
		}
		o.Text = remapPlaceholders(o.Text, m)
		o.Suggestion = remapPlaceholders(o.Suggestion, m)
	}
}

func remapEnrichments(items []apiv1.FindingEnrichment, m client.IDMap) {
	for i := range items {
		items[i].Target = m.RemapID(items[i].Target)
		items[i].WhyHere = remapPlaceholders(items[i].WhyHere, m)
		items[i].FixHere = remapPlaceholders(items[i].FixHere, m)
	}
}

func remapPlaceholders(text string, m client.IDMap) string {
	return idPlaceholder.ReplaceAllStringFunc(text, func(tok string) string {
		id := tok[1 : len(tok)-1]
		return "{" + m.RemapID(id) + "}"
	})
}

var idPlaceholder = regexp.MustCompile(`\{([efb][0-9a-f]{6,})\}`)


func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
