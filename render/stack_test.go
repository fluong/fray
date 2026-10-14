package render

import "testing"

func TestStackCommentHeading(t *testing.T) {
	if got := StackCommentHeading(""); got != "" {
		t.Fatalf("default heading must be empty, got %q", got)
	}
	want := "## Fray · stack `infra-aws`\n\n"
	if got := StackCommentHeading("infra-aws"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
