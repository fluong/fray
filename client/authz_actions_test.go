package client

import (
	"slices"
	"testing"
)

func TestClassifyS3WriteActionsWildcards(t *testing.T) {
	all := []string{
		"BypassGovernanceRetention",
		"DeleteObject",
		"DeleteObjectVersion",
		"PutBucketPolicy",
		"PutBucketVersioning",
		"PutLifecycleConfiguration",
		"PutObject",
		"PutObjectLockConfiguration",
		"PutObjectRetention",
	}
	cases := []struct {
		name    string
		actions []string
		want    []string
	}{
		{name: "*", actions: []string{"*"}, want: all},
		{name: "s3:*", actions: []string{"s3:*"}, want: all},
		{name: "s3:Delete*", actions: []string{"s3:Delete*"}, want: []string{"DeleteObject", "DeleteObjectVersion"}},
		{name: "s3:Put*", actions: []string{"s3:Put*"}, want: []string{
			"PutBucketPolicy", "PutBucketVersioning", "PutLifecycleConfiguration",
			"PutObject", "PutObjectLockConfiguration", "PutObjectRetention",
		}},
		{name: "s3:*Object", actions: []string{"s3:*Object"}, want: []string{"DeleteObject", "PutObject"}},
		{name: "s3:Get?bject", actions: []string{"s3:Get?bject"}, want: nil},
		{name: "S3:DELETEOBJECT", actions: []string{"S3:DELETEOBJECT"}, want: []string{"DeleteObject"}},
		{name: "concrete PutObject+DeleteObject", actions: []string{"s3:PutObject", "s3:DeleteObject"}, want: []string{"DeleteObject", "PutObject"}},
		{name: "DeleteObjectVersion", actions: []string{"s3:DeleteObjectVersion"}, want: []string{"DeleteObjectVersion"}},
		{name: "PutBucketVersioning", actions: []string{"s3:PutBucketVersioning"}, want: []string{"PutBucketVersioning"}},
		{name: "BypassGovernanceRetention", actions: []string{"s3:BypassGovernanceRetention"}, want: []string{"BypassGovernanceRetention"}},
		{name: "PutObjectLockConfiguration", actions: []string{"s3:PutObjectLockConfiguration"}, want: []string{"PutObjectLockConfiguration"}},
		{name: "PutObjectRetention", actions: []string{"s3:PutObjectRetention"}, want: []string{"PutObjectRetention"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, unknown, warn := classifyS3WriteActions(iamStatement{actions: tc.actions, doc: "data.aws_iam_policy_document.x"})
			if unknown || warn != "" {
				t.Fatalf("unexpected unknown=%v warn=%q", unknown, warn)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestClassifyS3WriteActionsUnknown(t *testing.T) {
	cases := []struct {
		name string
		st   iamStatement
		sub  string
	}{
		{
			name: "NotAction",
			st:   iamStatement{actions: []string{"s3:*"}, notActions: []string{"s3:GetObject"}, doc: "data.aws_iam_policy_document.x"},
			sub:  "NotAction",
		},
		{
			name: "Condition",
			st:   iamStatement{actions: []string{"s3:PutObject"}, condition: true, doc: "data.aws_iam_policy_document.x"},
			sub:  "Condition",
		},
		{
			name: "bucket-policy-sourced",
			st:   iamStatement{actions: []string{"s3:PutObject"}, doc: "aws_s3_bucket_policy.this"},
			sub:  "bucket-policy",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, unknown, warn := classifyS3WriteActions(tc.st)
			if !unknown || len(got) != 0 {
				t.Fatalf("want unknown with empty actions, got unknown=%v actions=%v", unknown, got)
			}
			if !containsSub(warn, tc.sub) {
				t.Fatalf("warn %q want substring %q", warn, tc.sub)
			}
		})
	}
}

func containsSub(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || len(s) > 0 && stringIndex(s, sub) >= 0))
}

func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestAuthzActionsExcludedFromFlowID(t *testing.T) {
	// Flow ids are from\nto\ndata_class only — authz_actions must not change them.
	mk := func(actions []string) DFD {
		svc := Element{
			Name: "svc", Type: "process", Kind: "container_service", Provenance: "iac",
			Evidence: Evidence{Addresses: []string{"aws_ecs_service.this"}}, Provider: "aws",
		}
		bucket := Element{
			Name: "bucket", Type: "datastore", Kind: "object_storage", Provenance: "iac",
			Evidence: Evidence{Addresses: []string{"aws_s3_bucket.this"}}, Provider: "aws",
		}
		f := Flow{
			From: svc.canonicalKey(), To: bucket.canonicalKey(),
			DataClass: "unknown", Transport: "tls",
			AuthzScope: "resource", AuthzGrants: []string{"resource"},
			AuthzActions: actions,
		}
		f.identityClass = "unknown"
		return DFD{
			SchemaVersion: "dfd/v1",
			Source:        Source{Repo: "a/b", Commit: "abc", Tool: "terraform", Fidelity: "plan"},
			Elements:      []Element{svc, bucket},
			Flows:         []Flow{f},
		}
	}
	without := mk(nil)
	with := mk([]string{"DeleteObject", "PutObject"})
	finalize(&without)
	finalize(&with)
	if without.Flows[0].ID != with.Flows[0].ID {
		t.Fatalf("flow id changed when authz_actions added:\n  without=%s\n  with=%s", without.Flows[0].ID, with.Flows[0].ID)
	}
	if len(with.Flows[0].AuthzActions) != 2 {
		t.Fatalf("authz_actions dropped: %v", with.Flows[0].AuthzActions)
	}
	// Golden: id depends only on finalized from, to, and identity data_class.
	want := digest("f", without.Flows[0].From+"\n"+without.Flows[0].To+"\nunknown")
	if without.Flows[0].ID != want {
		t.Fatalf("id %s want %s", without.Flows[0].ID, want)
	}
}
