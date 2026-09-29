package client

import (
	"slices"
	"testing"
)

func TestNormalizeAuthzGrants(t *testing.T) {
	got := normalizeAuthzGrants("account", "resource", "account", "bogus")
	want := []string{"resource", "account"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
	if effectiveAuthzScope(got) != "account" {
		t.Fatalf("effective %q", effectiveAuthzScope(got))
	}
	if normalizeAuthzGrants() != nil {
		t.Fatal("empty should be nil")
	}
}
