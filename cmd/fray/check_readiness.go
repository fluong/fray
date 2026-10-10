package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fluong/fray/usermsg"
)

const (
	maxReadinessBody = 64 * 1024
	readinessTimeout = 10 * time.Second
	checkSkipped     = checkOutcome("skipped")
)

type readinessAPIResponse struct {
	Ready  bool                `json:"ready"`
	Checks []readinessAPICheck `json:"checks"`
	Error  string              `json:"error"`
}

type readinessAPICheck struct {
	Check   string `json:"check"`
	Status  string `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// readinessGET performs GET {base}/v1/readiness. Overridden in tests.
var readinessGET = defaultReadinessGET

func defaultReadinessGET(baseURL, token string) (status int, header http.Header, body []byte, err error) {
	url := strings.TrimRight(baseURL, "/") + "/v1/readiness"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: readinessTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxReadinessBody+1))
	if err != nil {
		return resp.StatusCode, resp.Header, nil, err
	}
	return resp.StatusCode, resp.Header.Clone(), body, nil
}

// readinessRemedy is the human fix text only (no trailing "See <link>").
func readinessRemedy(code string) string {
	switch code {
	case "installation_missing", "installation_inactive":
		return "Install or re-enable the Fray GitHub App and select this repository."
	case "installation_over_cap":
		return "Reduce the repositories in the App installation's repository access (free plan: 3), or upgrade."
	case "repo_not_enrolled":
		return "Add this repository to the App installation's repository access."
	case "repo_mismatch":
		return "Contact support — OIDC repository_id does not match the org binding."
	default:
		return ""
	}
}

// callReadinessProbe queries GET /v1/readiness and returns summary rows.
// Never logs the token or (unless ShowPayload) the raw response body.
func callReadinessProbe(opt options) []checkRow {
	token := opt.OIDCToken
	if token == "" {
		return []checkRow{{
			Name:    "server readiness",
			Outcome: checkFail,
			Detail:  usermsg.SeeTroubleshooting("OIDC token missing for readiness probe. Grant permissions: id-token: write."),
		}}
	}

	status, header, body, err := readinessGET(opt.Remote, token)
	if err != nil {
		return []checkRow{{
			Name:    "server readiness",
			Outcome: checkFail,
			Detail:  "Fray API unavailable; retry later.",
		}}
	}
	if len(body) > maxReadinessBody {
		return []checkRow{{
			Name:    "server readiness",
			Outcome: checkFail,
			Detail:  "unexpected response from Fray API",
		}}
	}

	if opt.ShowPayload && len(body) > 0 {
		fmt.Fprintf(os.Stderr, "readiness response (%d): %s\n", status, string(body))
	}

	switch {
	case status == http.StatusOK:
		return mapReadiness200(body)
	case status == http.StatusUnauthorized:
		return []checkRow{{
			Name:    "server readiness",
			Outcome: checkFail,
			Detail:  usermsg.SeeTroubleshooting("token rejected by Fray"),
		}}
	case status == http.StatusTooManyRequests:
		detail := "readiness probe rate-limited; retry later"
		if ra := header.Get("Retry-After"); ra != "" {
			detail += " (retry-after " + ra + "s)"
		}
		return []checkRow{{
			Name:    "server readiness",
			Outcome: checkWarn,
			Detail:  detail,
		}}
	case status == http.StatusServiceUnavailable || status >= 500:
		return []checkRow{{
			Name:    "server readiness",
			Outcome: checkFail,
			Detail:  "Fray API unavailable; retry later.",
		}}
	default:
		return []checkRow{{
			Name:    "server readiness",
			Outcome: checkFail,
			Detail:  "unexpected response from Fray API",
		}}
	}
}

func mapReadiness200(body []byte) []checkRow {
	var resp readinessAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return []checkRow{{
			Name:    "server readiness",
			Outcome: checkFail,
			Detail:  "unexpected response from Fray API",
		}}
	}
	if len(resp.Checks) == 0 {
		if resp.Ready {
			return []checkRow{{
				Name:    "server readiness",
				Outcome: checkPass,
				Detail:  "ready",
			}}
		}
		return []checkRow{{
			Name:    "server readiness",
			Outcome: checkFail,
			Detail:  "not ready",
		}}
	}

	rows := make([]checkRow, 0, len(resp.Checks))
	for _, c := range resp.Checks {
		name := c.Check
		if name == "" {
			name = "readiness"
		}
		switch strings.ToLower(c.Status) {
		case "ok":
			detail := "ok"
			if c.Message != "" {
				detail = c.Message
			}
			rows = append(rows, checkRow{Name: name, Outcome: checkPass, Detail: detail})
		case "skipped":
			detail := "skipped"
			if c.Message != "" {
				detail = c.Message
			}
			rows = append(rows, checkRow{Name: name, Outcome: checkSkipped, Detail: detail})
		case "fail":
			rows = append(rows, checkRow{Name: name, Outcome: checkFail, Detail: formatReadinessFail(c.Code, c.Message)})
		default:
			detail := c.Status
			if c.Code != "" {
				detail = c.Code
				if c.Status != "" {
					detail += " (" + c.Status + ")"
				}
			}
			if c.Message != "" {
				if detail != "" {
					detail += " — "
				}
				detail += c.Message
			}
			if detail == "" {
				detail = "unknown status"
			}
			rows = append(rows, checkRow{Name: name, Outcome: checkFail, Detail: detail})
		}
	}
	if !resp.Ready {
		hasFail := false
		for _, r := range rows {
			if r.Outcome == checkFail {
				hasFail = true
				break
			}
		}
		if !hasFail {
			rows = append(rows, checkRow{
				Name:    "server readiness",
				Outcome: checkFail,
				Detail:  "not ready",
			})
		}
	}
	return rows
}

// formatReadinessFail builds "<code>: <server message>. <remedy> See <link>".
// No extra period is added when the server message already ends with one.
func formatReadinessFail(code, message string) string {
	msg := strings.TrimSpace(message)
	remedy := readinessRemedy(code)
	link := usermsg.TroubleshootingURL

	var b strings.Builder
	switch {
	case code != "" && msg != "":
		b.WriteString(code)
		b.WriteString(": ")
		b.WriteString(msg)
		if !strings.HasSuffix(msg, ".") {
			b.WriteByte('.')
		}
		b.WriteByte(' ')
	case code != "":
		b.WriteString(code)
		b.WriteString(". ")
	case msg != "":
		b.WriteString(msg)
		if !strings.HasSuffix(msg, ".") {
			b.WriteByte('.')
		}
		b.WriteByte(' ')
	default:
		b.WriteString("fail. ")
	}
	if remedy != "" {
		b.WriteString(remedy)
		if !strings.HasSuffix(remedy, ".") {
			b.WriteByte('.')
		}
		b.WriteByte(' ')
	}
	b.WriteString("See ")
	b.WriteString(link)
	return b.String()
}
