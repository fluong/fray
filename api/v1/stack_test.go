package v1

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateStack(t *testing.T) {
	cases := []struct {
		stack string
		ok    bool
	}{
		{"", true},
		{"infra", true},
		{"infra-aws", true},
		{"a", true},
		{"a" + strings.Repeat("b", 31), true},
		{"Infra", false},
		{"a/b", false},
		{"-x", false},
		{"a" + strings.Repeat("b", 32), false},
		{"has_under", false},
	}
	for _, tc := range cases {
		err := ValidateStack(tc.stack)
		if tc.ok && err != nil {
			t.Fatalf("%q: %v", tc.stack, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%q: want error", tc.stack)
		}
	}
}

func TestScanRequestOmitsEmptyStack(t *testing.T) {
	base := ScanRequest{
		DFD:             json.RawMessage(`{}`),
		Repo:            "acme/app",
		Commit:          "abc",
		IsDefaultBranch: true,
		ClientVersion:   "0.26.1",
	}
	without, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	withEmpty := base
	withEmpty.Stack = ""
	gotEmpty, err := json.Marshal(withEmpty)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(without, gotEmpty) {
		t.Fatalf("empty Stack must omit field\nwithout=%s\nempty=%s", without, gotEmpty)
	}
	if bytes.Contains(without, []byte(`"stack"`)) {
		t.Fatalf("unexpected stack key: %s", without)
	}

	named := base
	named.Stack = "infra-aws"
	gotNamed, err := json.Marshal(named)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(gotNamed, []byte(`"stack":"infra-aws"`)) {
		t.Fatalf("named stack missing: %s", gotNamed)
	}
}

func TestStackNaming(t *testing.T) {
	if CommentMarker("") != "<!-- fray -->" {
		t.Fatal(CommentMarker(""))
	}
	if CommentMarker("infra-aws") != "<!-- fray:infra-aws -->" {
		t.Fatal(CommentMarker("infra-aws"))
	}
	if OutDirName("") != "fray-out" || OutDirName("infra-aws") != "fray-out-infra-aws" {
		t.Fatal(OutDirName(""), OutDirName("infra-aws"))
	}
	if ArtifactName("") != "fray-payload" || ArtifactName("infra-aws") != "fray-payload-infra-aws" {
		t.Fatal(ArtifactName(""), ArtifactName("infra-aws"))
	}
	if SARIFCategory("") != "fray" || SARIFCategory("infra-aws") != "fray/infra-aws" {
		t.Fatal(SARIFCategory(""), SARIFCategory("infra-aws"))
	}
}

func TestCommentMatchesMarkerNoCross(t *testing.T) {
	def := CommentMarker("")
	named := CommentMarker("infra-aws")
	other := CommentMarker("infra-gcp")

	defBody := def + "\n## findings\n"
	namedBody := named + "\n## Fray · stack `infra-aws`\n"
	otherBody := other + "\n## Fray · stack `infra-gcp`\n"

	// Default marker matches only the default comment.
	if !CommentMatchesMarker(defBody, def) {
		t.Fatal("default must match default body")
	}
	if !CommentMatchesMarker(def, def) {
		t.Fatal("exact marker-only body must match")
	}
	if CommentMatchesMarker(namedBody, def) {
		t.Fatal("default must not match named body")
	}
	if CommentMatchesMarker(otherBody, def) {
		t.Fatal("default must not match other named body")
	}

	// Named marker matches only its own comment.
	if !CommentMatchesMarker(namedBody, named) {
		t.Fatal("named must match its body")
	}
	if CommentMatchesMarker(defBody, named) {
		t.Fatal("named must not match default body")
	}
	if CommentMatchesMarker(otherBody, named) {
		t.Fatal("named must not match another stack")
	}

	// Prefix traps: shorter named must not steal a longer sibling.
	short := CommentMarker("infra")
	longBody := CommentMarker("infra-aws") + "\nbody\n"
	if CommentMatchesMarker(longBody, short) {
		t.Fatal("infra must not match infra-aws body")
	}
}
