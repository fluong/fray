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

func TestEffectiveAuthzScopeAuthenticated(t *testing.T) {
	got := normalizeAuthzGrants("resource", "authenticated")
	want := []string{"resource", "authenticated"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
	if effectiveAuthzScope(got) != "authenticated" {
		t.Fatalf("effective %q want authenticated", effectiveAuthzScope(got))
	}

	got = normalizeAuthzGrants("authenticated", "public")
	want = []string{"authenticated", "public"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
	if effectiveAuthzScope(got) != "public" {
		t.Fatalf("effective %q want public", effectiveAuthzScope(got))
	}
}
