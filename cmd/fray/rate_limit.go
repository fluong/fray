package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fluong/fray/usermsg"
)

// Rate-limit outcome from POST /v1/scans (HTTP 429).
const (
	codeRateLimited   = "rate_limited"
	statusRateLimited = "rate_limited"
)

type rateLimitedBody struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	RetryAfter int    `json:"retry_after"`
}

// rateLimitedMarker is written to ${FRAY_OUT}/enrollment.json when the API
// returns a rate_limited 429. Message is truncated but otherwise preserved for
// Action annotations; treat it as untrusted and escape before workflow commands.
type rateLimitedMarker struct {
	Status     string `json:"status"`
	Message    string `json:"message"`
	RetryAfter int    `json:"retry_after"`
}

// parseRateLimited returns the server message and retry_after when the response
// is exactly a rate_limited 429. Any other 429 or malformed body is ok=false
// (caller fails as a normal transport error). No automatic retries.
func parseRateLimited(status int, contentType string, body []byte, retryAfterHdr string) (msg string, retryAfter int, ok bool) {
	if status != 429 {
		return "", 0, false
	}
	media := strings.TrimSpace(strings.Split(contentType, ";")[0])
	if !strings.EqualFold(media, "application/json") {
		return "", 0, false
	}
	if len(body) == 0 {
		return "", 0, false
	}
	var parsed rateLimitedBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", 0, false
	}
	if parsed.Error != codeRateLimited {
		return "", 0, false
	}
	ra := parsed.RetryAfter
	if ra < 1 {
		ra = parseRetryAfterHeader(retryAfterHdr)
	}
	// Server contract: retry_after is at least 1. Raise a zero/omitted body
	// value (and missing/invalid header) to 1 rather than rejecting the 429.
	if ra < 1 {
		ra = 1
	}
	return parsed.Message, ra, true
}

func parseRetryAfterHeader(h string) int {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	n, err := strconv.Atoi(h)
	if err != nil || n < 1 {
		return 0
	}
	return n
}

// writeRateLimitedMarker records a rate_limited outcome for action/scan.sh.
func writeRateLimitedMarker(outDir, serverMsg string, retryAfter int) error {
	if retryAfter < 1 {
		return fmt.Errorf("write rate_limited marker: retry_after must be >= 1")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	msg := truncateRunes(strings.TrimSpace(serverMsg), maxServerMessageChars)
	msg = strings.ReplaceAll(msg, "\r\n", " ")
	msg = strings.ReplaceAll(msg, "\r", " ")
	msg = strings.ReplaceAll(msg, "\n", " ")
	body, err := json.Marshal(rateLimitedMarker{
		Status:     statusRateLimited,
		Message:    msg,
		RetryAfter: retryAfter,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, enrollmentMarkerFile), append(body, '\n'), 0o644)
}

// formatRateLimitedNotice builds the human-readable rate-limit line (unescaped).
func formatRateLimitedNotice(serverMsg string, retryAfter int) string {
	msg := strings.TrimSpace(serverMsg)
	if msg == "" {
		msg = "Scan rate limit reached"
	} else {
		msg = truncateRunes(msg, maxServerMessageChars)
	}
	notice := fmt.Sprintf("%s (retry after %d s)", msg, retryAfter) + usermsg.RateLimitFreePlan
	return usermsg.SeeTroubleshooting(notice)
}

// reportRateLimitedStderr prints a single clear line on stderr for local/CI logs.
// Workflow annotations and the step summary are left to action/scan.sh so
// fail-on-rate-limit can choose ::warning:: vs ::error::.
func reportRateLimitedStderr(serverMsg string, retryAfter int) {
	notice := formatRateLimitedNotice(serverMsg, retryAfter)
	// Collapse control characters so a hostile message cannot break the log line.
	notice = strings.ReplaceAll(notice, "\r", " ")
	notice = strings.ReplaceAll(notice, "\n", " ")
	fmt.Fprintf(os.Stderr, "fray: rate limited: %s\n", notice)
}
