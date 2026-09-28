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

	"github.com/fluong/fray/client"
	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/render"
)

func runRemote(opt options) (bool, error) {
	if opt.OIDCToken == "" {
		opt.OIDCToken = os.Getenv("FRAY_OIDC_TOKEN")
	}
	if opt.APIKey == "" {
		opt.APIKey = os.Getenv("FRAY_API_KEY")
	}
	if opt.OIDCToken == "" && opt.APIKey == "" {
		return false, fmt.Errorf("-remote requires FRAY_OIDC_TOKEN/-oidc-token or FRAY_API_KEY/-api-key")
	}
	if opt.DefaultBranch == "" {
		return false, fmt.Errorf("-default-branch is required with -remote")
	}
	if opt.Branch == "" {
		opt.Branch = opt.DefaultBranch
	}

	plan, err := os.ReadFile(opt.Plan)
	if err != nil {
		return false, err
	}
	cfg, err := os.ReadFile(opt.Config)
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
	rawDFD, err := client.Marshal(doc)
	if err != nil {
		return false, err
	}

	entries, err := loadMitigations(opt.Mitigations)
	if err != nil {
		return false, err
	}
	accepted, err := resolveAccepted(doc, entries)
	if err != nil {
		return false, err
	}

	reqBody, err := json.Marshal(apiv1.ScanRequest{
		DFD:                 rawDFD,
		AcceptedMitigations: accepted,
		Repo:                opt.Repo,
		Commit:              opt.Commit,
		Branch:              opt.Branch,
		DefaultBranch:       opt.DefaultBranch,
		BaseCommit:          opt.BaseCommit,
	})
	if err != nil {
		return false, err
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

	locs, err := client.ResourceLocations(opt.Source)
	if err != nil {
		return false, err
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
		comment := render.PRComment(doc, resp.Findings, baseline, texts, locs)
		if err := os.WriteFile(filepath.Join(opt.Out, "pr-comment.md"), []byte(comment), 0o644); err != nil {
			return false, err
		}
	}
	return resp.Gate.Blocked, nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
