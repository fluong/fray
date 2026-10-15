package client

import (
	"encoding/json"
	"testing"
)

func TestCustomerManagedKeyAWSTable(t *testing.T) {
	bucket := planResource{
		typ: "aws_s3_bucket", address: "aws_s3_bucket.app",
		values: map[string]any{"bucket": "app-data"},
	}
	sseVals := func(algo string, key any) map[string]any {
		def := map[string]any{"sse_algorithm": algo}
		if key != nil {
			def["kms_master_key_id"] = key
		}
		return map[string]any{
			"rule": []any{map[string]any{
				"apply_server_side_encryption_by_default": []any{def},
			}},
		}
	}
	sibling := func(vals map[string]any, refs []string, afterUnknown map[string]any) (planResource, configIndex) {
		sib := planResource{
			typ:          "aws_s3_bucket_server_side_encryption_configuration",
			address:      "aws_s3_bucket_server_side_encryption_configuration.app",
			values:       vals,
			afterUnknown: afterUnknown,
		}
		idx := configIndex{
			resources: map[string]exprSet{
				sib.address: {
					refs: map[string][]string{
						"bucket": {"aws_s3_bucket.app.id", "aws_s3_bucket.app"},
						"rule":   refs,
					},
				},
			},
			calls: map[string]exprSet{},
		}
		return sib, idx
	}
	keyUnknownAU := map[string]any{
		"rule": []any{map[string]any{
			"apply_server_side_encryption_by_default": []any{map[string]any{
				"kms_master_key_id": true,
			}},
		}},
	}

	type want struct {
		val   bool
		known bool
	}
	cases := []struct {
		name  string
		build func() (planResource, []planResource, configIndex)
		want  want
	}{
		{
			name: "no SSE → false (SSE-S3 default)",
			build: func() (planResource, []planResource, configIndex) {
				return bucket, []planResource{bucket}, configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
			},
			want: want{false, true},
		},
		{
			name: "sibling present, sse_algorithm after_unknown → omit",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(
					map[string]any{
						"rule": []any{map[string]any{
							"apply_server_side_encryption_by_default": []any{map[string]any{}},
						}},
					},
					nil,
					map[string]any{
						"rule": []any{map[string]any{
							"apply_server_side_encryption_by_default": []any{map[string]any{
								"sse_algorithm": true,
							}},
						}},
					},
				)
				return bucket, []planResource{bucket, sib}, idx
			},
			want: want{false, false},
		},
		{
			name: "sibling present, after_unknown rule=true → omit",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(
					map[string]any{},
					nil,
					map[string]any{"rule": true},
				)
				return bucket, []planResource{bucket, sib}, idx
			},
			want: want{false, false},
		},
		{
			name: "legacy inline present, sse_algorithm after_unknown → omit",
			build: func() (planResource, []planResource, configIndex) {
				b := planResource{
					typ: "aws_s3_bucket", address: "aws_s3_bucket.app",
					values: map[string]any{
						"bucket": "app-data",
						"server_side_encryption_configuration": []any{map[string]any{
							"rule": []any{map[string]any{
								"apply_server_side_encryption_by_default": []any{map[string]any{}},
							}},
						}},
					},
					afterUnknown: map[string]any{
						"server_side_encryption_configuration": []any{map[string]any{
							"rule": []any{map[string]any{
								"apply_server_side_encryption_by_default": []any{map[string]any{
									"sse_algorithm": true,
								}},
							}},
						}},
					},
				}
				return b, []planResource{b}, configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
			},
			want: want{false, false},
		},
		{
			name: "sibling AES256 → false",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(sseVals("AES256", nil), nil, nil)
				return bucket, []planResource{bucket, sib}, idx
			},
			want: want{false, true},
		},
		{
			name: "sibling aws:kms known absent (no key, no refs) → false",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(sseVals("aws:kms", nil), nil, nil)
				return bucket, []planResource{bucket, sib}, idx
			},
			want: want{false, true},
		},
		{
			name: "sibling aws:kms empty key known absent → false",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(sseVals("aws:kms", ""), nil, nil)
				return bucket, []planResource{bucket, sib}, idx
			},
			want: want{false, true},
		},
		{
			name: "sibling aws:kms alias/aws/s3 → false",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(sseVals("aws:kms", "alias/aws/s3"), nil, nil)
				return bucket, []planResource{bucket, sib}, idx
			},
			want: want{false, true},
		},
		{
			name: "sibling aws:kms ARN ending :alias/aws/s3 → false",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(sseVals("aws:kms", "arn:aws:kms:us-east-1:123456789012:alias/aws/s3"), nil, nil)
				return bucket, []planResource{bucket, sib}, idx
			},
			want: want{false, true},
		},
		{
			name: "sibling aws:kms alias/my-key → true",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(sseVals("aws:kms", "alias/my-key"), nil, nil)
				return bucket, []planResource{bucket, sib}, idx
			},
			want: want{true, true},
		},
		{
			name: "sibling aws:kms:dsse alias/orders → true",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(sseVals("aws:kms:dsse", "alias/orders"), nil, nil)
				return bucket, []planResource{bucket, sib}, idx
			},
			want: want{true, true},
		},
		{
			name: "sibling aws:kms literal key ARN → omit",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(sseVals("aws:kms", "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"), nil, nil)
				return bucket, []planResource{bucket, sib}, idx
			},
			want: want{false, false},
		},
		{
			name: "sibling aws:kms bare UUID → omit",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(sseVals("aws:kms", "12345678-1234-1234-1234-123456789012"), nil, nil)
				return bucket, []planResource{bucket, sib}, idx
			},
			want: want{false, false},
		},
		{
			name: "sibling aws:kms unknown key + aws_kms_key ref → true",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(sseVals("aws:kms", nil), []string{"aws_kms_key.uploads.arn", "aws_kms_key.uploads"}, keyUnknownAU)
				key := planResource{typ: "aws_kms_key", address: "aws_kms_key.uploads", values: map[string]any{}}
				return bucket, []planResource{bucket, sib, key}, idx
			},
			want: want{true, true},
		},
		{
			name: "sibling aws:kms unknown key + aws_kms_alias ref → true",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(sseVals("aws:kms", nil), []string{"aws_kms_alias.app.arn", "aws_kms_alias.app"}, keyUnknownAU)
				alias := planResource{typ: "aws_kms_alias", address: "aws_kms_alias.app", values: map[string]any{}}
				return bucket, []planResource{bucket, sib, alias}, idx
			},
			want: want{true, true},
		},
		{
			name: "sibling aws:kms unknown key + data.aws_kms_key → omit",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(sseVals("aws:kms", nil), []string{"data.aws_kms_key.ext.arn", "data.aws_kms_key.ext"}, keyUnknownAU)
				return bucket, []planResource{bucket, sib}, idx
			},
			want: want{false, false},
		},
		{
			name: "sibling aws:kms key after_unknown + local.key_arn → omit",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(sseVals("aws:kms", nil), []string{"local.key_arn"}, keyUnknownAU)
				return bucket, []planResource{bucket, sib}, idx
			},
			want: want{false, false},
		},
		{
			name: "sibling aws:kms key after_unknown + each.value → omit",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(sseVals("aws:kms", nil), []string{"each.value"}, keyUnknownAU)
				return bucket, []planResource{bucket, sib}, idx
			},
			want: want{false, false},
		},
		{
			name: "sibling aws:kms key after_unknown + no refs → omit",
			build: func() (planResource, []planResource, configIndex) {
				sib, idx := sibling(sseVals("aws:kms", nil), nil, keyUnknownAU)
				return bucket, []planResource{bucket, sib}, idx
			},
			want: want{false, false},
		},
		{
			name: "module path with module.kms.key_arn → omit",
			build: func() (planResource, []planResource, configIndex) {
				b := planResource{
					typ: "aws_s3_bucket", address: "module.uploads.aws_s3_bucket.this[0]",
					values: map[string]any{"bucket_prefix": "uploads-"},
				}
				sib := planResource{
					typ:     "aws_s3_bucket_server_side_encryption_configuration",
					address: "module.uploads.aws_s3_bucket_server_side_encryption_configuration.this[0]",
					values:  sseVals("aws:kms", nil),
					afterUnknown: keyUnknownAU,
				}
				idx := configIndex{
					resources: map[string]exprSet{
						sib.address: {
							refs: map[string][]string{
								"bucket": {"aws_s3_bucket.this[0].id", "aws_s3_bucket.this[0]"},
								"rule":   {"module.kms.key_arn", "module.kms"},
							},
						},
					},
					calls: map[string]exprSet{
						"module.uploads": {},
					},
				}
				return b, []planResource{b, sib}, idx
			},
			want: want{false, false},
		},
		{
			name: "legacy inline AES256 → false",
			build: func() (planResource, []planResource, configIndex) {
				b := planResource{
					typ: "aws_s3_bucket", address: "aws_s3_bucket.app",
					values: map[string]any{
						"bucket": "app-data",
						"server_side_encryption_configuration": []any{map[string]any{
							"rule": []any{map[string]any{
								"apply_server_side_encryption_by_default": []any{map[string]any{
									"sse_algorithm": "AES256",
								}},
							}},
						}},
					},
				}
				return b, []planResource{b}, configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
			},
			want: want{false, true},
		},
		{
			name: "legacy inline aws:kms + aws_kms_key ref → true",
			build: func() (planResource, []planResource, configIndex) {
				b := planResource{
					typ: "aws_s3_bucket", address: "aws_s3_bucket.app",
					values: map[string]any{
						"bucket": "app-data",
						"server_side_encryption_configuration": []any{map[string]any{
							"rule": []any{map[string]any{
								"apply_server_side_encryption_by_default": []any{map[string]any{
									"sse_algorithm": "aws:kms",
								}},
							}},
						}},
					},
					afterUnknown: map[string]any{
						"server_side_encryption_configuration": []any{map[string]any{
							"rule": []any{map[string]any{
								"apply_server_side_encryption_by_default": []any{map[string]any{
									"kms_master_key_id": true,
								}},
							}},
						}},
					},
				}
				idx := configIndex{
					resources: map[string]exprSet{
						b.address: {refs: map[string][]string{
							"server_side_encryption_configuration": {"aws_kms_key.app.arn", "aws_kms_key.app"},
						}},
					},
					calls: map[string]exprSet{},
				}
				key := planResource{typ: "aws_kms_key", address: "aws_kms_key.app", values: map[string]any{}}
				return b, []planResource{b, key}, idx
			},
			want: want{true, true},
		},
		{
			name: "module input AES256 constant-only → false",
			build: func() (planResource, []planResource, configIndex) {
				b := planResource{
					typ: "aws_s3_bucket", address: "module.uploads.aws_s3_bucket.this[0]",
					values: map[string]any{"bucket_prefix": "uploads-"},
				}
				idx := configIndex{
					resources: map[string]exprSet{},
					calls: map[string]exprSet{
						"module.uploads": {
							constants: map[string]any{
								"server_side_encryption_configuration": map[string]any{
									"rule": map[string]any{
										"apply_server_side_encryption_by_default": map[string]any{
											"sse_algorithm": "AES256",
										},
									},
								},
							},
						},
					},
				}
				return b, []planResource{b}, idx
			},
			want: want{false, true},
		},
		{
			name: "module input aws:kms refs-only + root aws_kms_key → true",
			build: func() (planResource, []planResource, configIndex) {
				b := planResource{
					typ: "aws_s3_bucket", address: "module.uploads.aws_s3_bucket.this[0]",
					values: map[string]any{"bucket_prefix": "uploads-"},
				}
				idx := configIndex{
					resources: map[string]exprSet{},
					calls: map[string]exprSet{
						"module.uploads": {
							refs: map[string][]string{
								"server_side_encryption_configuration": {
									"aws_kms_key.uploads.arn", "aws_kms_key.uploads",
								},
							},
						},
					},
				}
				key := planResource{typ: "aws_kms_key", address: "aws_kms_key.uploads", values: map[string]any{"enable_key_rotation": true}}
				return b, []planResource{b, key}, idx
			},
			want: want{true, true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, resources, idx := tc.build()
			got, known := customerManagedKey(b, resources, idx)
			if known != tc.want.known || (known && got != tc.want.val) {
				t.Fatalf("got val=%v known=%v want val=%v known=%v", got, known, tc.want.val, tc.want.known)
			}
		})
	}
}

func TestCustomerManagedKeyGCPTable(t *testing.T) {
	cases := []struct {
		name         string
		values       map[string]any
		afterUnknown map[string]any
		want         bool
		known        bool
	}{
		{
			name:   "no encryption block → false",
			values: map[string]any{"name": "assets"},
			want:   false, known: true,
		},
		{
			name: "encryption with literal key name → true",
			values: map[string]any{
				"name": "assets",
				"encryption": []any{map[string]any{
					"default_kms_key_name": "projects/p/locations/us/keyRings/r/cryptoKeys/k",
				}},
			},
			want: true, known: true,
		},
		// Refs no longer matter: any non-empty encryption block is CMEK.
		// Nested after_unknown for default_kms_key_name (same-config
		// google_kms_crypto_key) still yields true when after has [{}].
		{
			name: "encryption [{}] + nested after_unknown default_kms_key_name → true",
			values: map[string]any{
				"name":       "assets",
				"encryption": []any{map[string]any{}},
			},
			afterUnknown: map[string]any{
				"encryption": []any{map[string]any{
					"default_kms_key_name": true,
				}},
			},
			want: true, known: true,
		},
		{
			name:         "encryption attribute unknown → omit",
			values:       map[string]any{"name": "assets"},
			afterUnknown: map[string]any{"encryption": true},
			want:         false, known: false,
		},
		{
			name:   "encryption empty list → false",
			values: map[string]any{"name": "assets", "encryption": []any{}},
			want:   false, known: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := planResource{
				typ: "google_storage_bucket", address: "google_storage_bucket.assets",
				values: tc.values, afterUnknown: tc.afterUnknown,
			}
			got, known := gcsCustomerManagedKey(r, configIndex{})
			if known != tc.known || (known && got != tc.want) {
				t.Fatalf("got val=%v known=%v want val=%v known=%v", got, known, tc.want, tc.known)
			}
		})
	}
}

// TestCustomerManagedKeyDemoUploadsModule reproduces the public demo shape:
// root aws_kms_key.uploads (rotation on) + module.uploads (s3-bucket 5.16.1)
// with sse_algorithm=aws:kms, kms_master_key_id=aws_kms_key.uploads.arn,
// bucket_key_enabled=true, and the key ARN unknown in planned values.
// Module-call SSE is references-only (no constant_value), as Terraform emits
// for a non-constant expression.
func TestCustomerManagedKeyDemoUploadsModule(t *testing.T) {
	plan := demoUploadsCMKPlan(t)
	doc, warnings, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "fray.yaml", Source{
		Repo: "example/demo", Commit: "abc1234", Tool: "terraform", Fidelity: "plan",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if w == "no mapping for aws_kms_key.uploads; skipped" {
			t.Fatalf("aws_kms_key must be ignored, not warned: %v", warnings)
		}
	}
	var bucket *Element
	for i := range doc.Elements {
		el := &doc.Elements[i]
		if el.Kind != "object_storage" {
			continue
		}
		for _, addr := range el.Evidence.Addresses {
			if addr == "module.uploads.aws_s3_bucket.this[0]" {
				bucket = el
			}
		}
	}
	if bucket == nil {
		t.Fatal("uploads bucket element missing")
	}
	got, ok := bucket.Attributes["customer_managed_key"].(bool)
	if !ok || !got {
		t.Fatalf("customer_managed_key=%#v want true", bucket.Attributes["customer_managed_key"])
	}
}

func demoUploadsCMKPlan(t *testing.T) []byte {
	t.Helper()
	root := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			map[string]any{
				"address": "aws_kms_key.uploads", "mode": "managed", "type": "aws_kms_key", "name": "uploads",
				"change": map[string]any{
					"actions": []any{"create"},
					"after": map[string]any{
						"description":             "Customer-managed key for the uploads bucket",
						"deletion_window_in_days": 7,
						"enable_key_rotation":     true,
					},
					"after_unknown": map[string]any{"arn": true, "key_id": true, "id": true},
				},
			},
			map[string]any{
				"address": "module.uploads.aws_s3_bucket.this[0]", "mode": "managed", "type": "aws_s3_bucket", "name": "this",
				"index": 0,
				"change": map[string]any{
					"actions": []any{"create"},
					"after": map[string]any{
						"bucket_prefix": "fray-aws-web-app-uploads-",
						"force_destroy": true,
					},
					"after_unknown": map[string]any{"bucket": true, "id": true, "arn": true},
				},
			},
			map[string]any{
				"address": "module.uploads.aws_s3_bucket_server_side_encryption_configuration.this[0]",
				"mode":    "managed", "type": "aws_s3_bucket_server_side_encryption_configuration", "name": "this",
				"index": 0,
				"change": map[string]any{
					"actions": []any{"create"},
					"after": map[string]any{
						"rule": []any{map[string]any{
							"bucket_key_enabled": true,
							"apply_server_side_encryption_by_default": []any{map[string]any{
								"sse_algorithm": "aws:kms",
							}},
						}},
					},
					"after_unknown": map[string]any{
						"bucket": true,
						"rule": []any{map[string]any{
							"apply_server_side_encryption_by_default": []any{map[string]any{
								"kms_master_key_id": true,
							}},
						}},
					},
				},
			},
		},
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": []any{
					map[string]any{
						"address": "aws_kms_key.uploads", "type": "aws_kms_key", "name": "uploads", "mode": "managed",
						"expressions": map[string]any{
							"description":             map[string]any{"constant_value": "Customer-managed key for the uploads bucket"},
							"deletion_window_in_days": map[string]any{"constant_value": 7},
							"enable_key_rotation":     map[string]any{"constant_value": true},
						},
					},
				},
				"module_calls": map[string]any{
					"uploads": map[string]any{
						"source":  "registry.terraform.io/terraform-aws-modules/s3-bucket/aws",
						"version": "5.16.1",
						"expressions": map[string]any{
							"bucket_prefix": map[string]any{"constant_value": "fray-aws-web-app-uploads-"},
							"force_destroy": map[string]any{"constant_value": true},
							// Non-constant expression: Terraform emits references only.
							"server_side_encryption_configuration": map[string]any{
								"references": []any{"aws_kms_key.uploads.arn", "aws_kms_key.uploads"},
							},
						},
						"module": map[string]any{
							"resources": []any{
								map[string]any{
									"address": "aws_s3_bucket.this", "type": "aws_s3_bucket", "name": "this", "mode": "managed",
									"expressions": map[string]any{},
								},
								map[string]any{
									"address": "aws_s3_bucket_server_side_encryption_configuration.this",
									"type":    "aws_s3_bucket_server_side_encryption_configuration", "name": "this", "mode": "managed",
									"expressions": map[string]any{
										"bucket": map[string]any{"references": []any{
											"aws_s3_bucket.this[0].id", "aws_s3_bucket.this[0]", "aws_s3_bucket.this",
										}},
										"rule": map[string]any{"references": []any{
											"var.server_side_encryption_configuration",
										}},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
