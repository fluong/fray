package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
	"github.com/fluong/fray/render"
)

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

	entries, err := loadMitigations(opt.Mitigations)
	if err != nil {
		return false, err
	}
	accepted, err := resolveAccepted(doc, entries)
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
		return false, err
	}
	defer httpResp.Body.Close()
	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return false, err
	}
	if httpResp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("remote scan: %s: %s", httpResp.Status, truncate(respBody, 200))
	}

	var resp apiv1.ScanResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return false, err
	}

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
	report := render.ThreatModel(doc, resp.Findings, texts, toRenderEntries(entries), locs)
	if err := os.WriteFile(filepath.Join(opt.Out, "threat-model.md"), []byte(report), 0o644); err != nil {
		return false, err
	}
	sarif, err := render.SARIF(doc, resp.Findings, texts, locs)
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(filepath.Join(opt.Out, "findings.sarif"), sarif, 0o644); err != nil {
		return false, err
	}

	var baseline apiv1.Findings
	haveBaseline := resp.Baseline.Findings != nil
	if haveBaseline {
		baseline = *resp.Baseline.Findings
		comment := render.PRComment(doc, resp.Findings, baseline, texts, locs, changedInputs)
		if err := os.WriteFile(filepath.Join(opt.Out, "pr-comment.md"), []byte(comment), 0o644); err != nil {
			return false, err
		}
	}
	return resp.Gate.Blocked, nil
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

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
