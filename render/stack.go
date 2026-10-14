package render

import "fmt"

// StackCommentHeading is prepended to the PR comment body when stack is named.
// Empty stack keeps today's comment body (no heading).
func StackCommentHeading(stack string) string {
	if stack == "" {
		return ""
	}
	return fmt.Sprintf("## Fray · stack `%s`\n\n", stack)
}
