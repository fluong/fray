package render

import "testing"

func TestPluralizeCounts(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Before this change it could read only the 1 secrets it uses.", "Before this change it could read only the 1 secret it uses."},
		{"Before this change it could read only the 3 secrets it uses.", "Before this change it could read only the 3 secrets it uses."},
		{"1 buckets do not block public access", "1 bucket do not block public access"},
		{"2 buckets do not block public access", "2 buckets do not block public access"},
		{"1 findings unchanged", "1 finding unchanged"},
		{"14 findings unchanged", "14 findings unchanged"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := pluralizeCounts(tc.in); got != tc.want {
			t.Errorf("pluralizeCounts(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestNoLongerTitle(t *testing.T) {
	got := noLongerTitle("Uploads bucket does not block public access")
	want := "Uploads bucket no longer blocks public access"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got := noLongerTitle("Secret access widened to the whole account"); got != "Secret access widened to the whole account" {
		t.Fatalf("unchanged title became %q", got)
	}
}
