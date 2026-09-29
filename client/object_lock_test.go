package client

import "testing"

func TestAWSObjectLockTruthTable(t *testing.T) {
	idx := configIndex{}
	cases := []struct {
		name       string
		bucket     planResource
		sib        *planResource
		wantVal    bool
		wantOK     bool
		wantReason string
	}{
		{
			name: "enabled=false → known false",
			bucket: planResource{
				typ: "aws_s3_bucket", address: "aws_s3_bucket.a",
				values: map[string]any{"object_lock_enabled": false},
			},
			wantVal: false, wantOK: true,
		},
		{
			name: "COMPLIANCE default_retention → known true",
			bucket: planResource{
				typ: "aws_s3_bucket", address: "aws_s3_bucket.a",
				values: map[string]any{"object_lock_enabled": true},
			},
			sib: &planResource{
				typ: "aws_s3_bucket_object_lock_configuration", address: "aws_s3_bucket_object_lock_configuration.a",
				values: map[string]any{
					"rule": []any{map[string]any{
						"default_retention": []any{map[string]any{"mode": "COMPLIANCE", "days": float64(30)}},
					}},
				},
			},
			wantVal: true, wantOK: true,
		},
		{
			name: "GOVERNANCE → absent (bypassable)",
			bucket: planResource{
				typ: "aws_s3_bucket", address: "aws_s3_bucket.a",
				values: map[string]any{"object_lock_enabled": true},
			},
			sib: &planResource{
				typ: "aws_s3_bucket_object_lock_configuration", address: "aws_s3_bucket_object_lock_configuration.a",
				values: map[string]any{
					"rule": []any{map[string]any{
						"default_retention": []any{map[string]any{"mode": "GOVERNANCE", "days": float64(30)}},
					}},
				},
			},
			wantVal: false, wantOK: false, wantReason: "s3:BypassGovernanceRetention",
		},
		{
			name: "enabled=true, no default retention → absent",
			bucket: planResource{
				typ: "aws_s3_bucket", address: "aws_s3_bucket.a",
				values: map[string]any{"object_lock_enabled": true},
			},
			sib: &planResource{
				typ: "aws_s3_bucket_object_lock_configuration", address: "aws_s3_bucket_object_lock_configuration.a",
				values: map[string]any{"rule": []any{map[string]any{}}},
			},
			wantVal: false, wantOK: false,
		},
		{
			name: "enabled=true no config resource → absent",
			bucket: planResource{
				typ: "aws_s3_bucket", address: "aws_s3_bucket.a",
				values: map[string]any{"object_lock_enabled": true},
			},
			wantVal: false, wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resources := []planResource{tc.bucket}
			if tc.sib != nil {
				resources = append(resources, *tc.sib)
			}
			got, ok := awsObjectLock(tc.bucket, resources, idx)
			if got != tc.wantVal || ok != tc.wantOK {
				t.Fatalf("got (%v,%v) want (%v,%v)", got, ok, tc.wantVal, tc.wantOK)
			}
			reason := awsObjectLockAbsentReason(tc.bucket, resources, idx)
			if reason != tc.wantReason {
				t.Fatalf("reason %q want %q", reason, tc.wantReason)
			}
		})
	}
}

func TestGCSRetentionTruthTable(t *testing.T) {
	cases := []struct {
		name    string
		policy  any
		wantVal bool
		wantOK  bool
	}{
		{name: "is_locked=true → known true", policy: []any{map[string]any{"is_locked": true, "retention_period": float64(100)}}, wantVal: true, wantOK: true},
		{name: "unlocked retention → absent", policy: []any{map[string]any{"is_locked": false, "retention_period": float64(100)}}, wantVal: false, wantOK: false},
		{name: "no retention_policy → known false", policy: nil, wantVal: false, wantOK: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := gcsRetentionLocked(tc.policy)
			if got != tc.wantVal || ok != tc.wantOK {
				t.Fatalf("got (%v,%v) want (%v,%v)", got, ok, tc.wantVal, tc.wantOK)
			}
		})
	}
}
