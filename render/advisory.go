package render

import (
	"html"
	"regexp"
	"strings"
)

var (
	mdLink    = regexp.MustCompile(`!?\[([^\]]*)\]\([^)]*\)`)
	htmlTag   = regexp.MustCompile(`(?i)</?[a-z][^>]*>`)
	mdFence   = regexp.MustCompile("(?s)```.*?```")
	mdInline  = regexp.MustCompile("`([^`]*)`")
	mdHeading = regexp.MustCompile(`(?m)^#{1,6}\s+`)
	mdBold    = regexp.MustCompile(`\*\*([^*]+)\*\*|__([^_]+)__`)
	// Underscore italics only when flanked by whitespace/punctuation so names
	// like ecs_service and block_public_acls survive.
	mdItalic = regexp.MustCompile(`(?:^|[^\w*])\*([^*]+)\*(?:[^\w*]|$)`)
	idToken  = regexp.MustCompile(`\{([efb][0-9a-f]{6,})\}`)
)

// SanitizeAdvisoryText strips links, images, HTML and markdown syntax so
// untrusted LLM prose renders as plain text in PR comments.
func SanitizeAdvisoryText(s string) string {
	s = mdFence.ReplaceAllString(s, "")
	s = mdLink.ReplaceAllString(s, "$1")
	s = htmlTag.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	s = mdHeading.ReplaceAllString(s, "")
	s = mdBold.ReplaceAllString(s, "$1$2")
	s = mdItalic.ReplaceAllString(s, "$1")
	s = mdInline.ReplaceAllString(s, "$1")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.TrimSpace(s)
}

// FillIDPlaceholders replaces {element_or_flow_id} with local display names.
func FillIDPlaceholders(text string, names map[string]string) string {
	return idToken.ReplaceAllStringFunc(text, func(m string) string {
		id := m[1 : len(m)-1]
		if name, ok := names[id]; ok && name != "" {
			return name
		}
		return id
	})
}
