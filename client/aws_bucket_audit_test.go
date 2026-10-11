package client

import (
	"testing"
)

func TestBucketAuditTable(t *testing.T) {
	bucket := planResource{
		typ: "aws_s3_bucket", address: "aws_s3_bucket.app",
		values: map[string]any{"bucket": "app-data"},
	}
	cases := []struct {
		name      string
		build     func() ([]planResource, configIndex)
		wantVal   bool
		wantKnown bool
	}{
		{
			name: "s3 bucket logging",
			build: func() ([]planResource, configIndex) {
				log := planResource{
					typ: "aws_s3_bucket_logging", address: "aws_s3_bucket_logging.app",
					values: map[string]any{"target_bucket": "logs"},
				}
				idx := configIndex{resources: map[string]exprSet{
					log.address: {refs: map[string][]string{
						"bucket": {"aws_s3_bucket.app.id", "aws_s3_bucket.app"},
					}},
				}, calls: map[string]exprSet{}}
				return []planResource{bucket, log}, idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "trail selects this bucket",
			build: func() ([]planResource, configIndex) {
				trail := planResource{
					typ: "aws_cloudtrail", address: "aws_cloudtrail.main",
					values: map[string]any{
						"event_selector": []any{map[string]any{
							"read_write_type": "All",
							"data_resource": []any{map[string]any{
								"type":   "AWS::S3::Object",
								"values": []any{"arn:aws:s3:::app-data/"},
							}},
						}},
					},
				}
				return []planResource{bucket, trail}, configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "trail selects different bucket",
			build: func() ([]planResource, configIndex) {
				trail := planResource{
					typ: "aws_cloudtrail", address: "aws_cloudtrail.main",
					values: map[string]any{
						"event_selector": []any{map[string]any{
							"read_write_type": "All",
							"data_resource": []any{map[string]any{
								"type":   "AWS::S3::Object",
								"values": []any{"arn:aws:s3:::other-bucket/"},
							}},
						}},
					},
				}
				return []planResource{bucket, trail}, configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "all-buckets trail",
			build: func() ([]planResource, configIndex) {
				trail := planResource{
					typ: "aws_cloudtrail", address: "aws_cloudtrail.main",
					values: map[string]any{
						"event_selector": []any{map[string]any{
							"read_write_type": "All",
							"data_resource": []any{map[string]any{
								"type":   "AWS::S3::Object",
								"values": []any{"arn:aws:s3"},
							}},
						}},
					},
				}
				return []planResource{bucket, trail}, configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "advanced selector",
			build: func() ([]planResource, configIndex) {
				trail := planResource{
					typ: "aws_cloudtrail", address: "aws_cloudtrail.main",
					values: map[string]any{
						"advanced_event_selector": []any{map[string]any{
							"field_selector": []any{
								map[string]any{"field": "eventCategory", "equals": []any{"Data"}},
								map[string]any{"field": "resources.type", "equals": []any{"AWS::S3::Object"}},
								map[string]any{"field": "resources.ARN", "starts_with": []any{"arn:aws:s3:::app-data/"}},
							},
						}},
					},
				}
				return []planResource{bucket, trail}, configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "WriteOnly trail absent",
			build: func() ([]planResource, configIndex) {
				trail := planResource{
					typ: "aws_cloudtrail", address: "aws_cloudtrail.main",
					values: map[string]any{
						"event_selector": []any{map[string]any{
							"read_write_type": "WriteOnly",
							"data_resource": []any{map[string]any{
								"type":   "AWS::S3::Object",
								"values": []any{"arn:aws:s3:::app-data/"},
							}},
						}},
					},
				}
				return []planResource{bucket, trail}, configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "advanced readOnly false only absent",
			build: func() ([]planResource, configIndex) {
				trail := planResource{
					typ: "aws_cloudtrail", address: "aws_cloudtrail.main",
					values: map[string]any{
						"advanced_event_selector": []any{map[string]any{
							"field_selector": []any{
								map[string]any{"field": "eventCategory", "equals": []any{"Data"}},
								map[string]any{"field": "resources.type", "equals": []any{"AWS::S3::Object"}},
								map[string]any{"field": "readOnly", "equals": []any{"false"}},
							},
						}},
					},
				}
				return []planResource{bucket, trail}, configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "computed ARN via reference",
			build: func() ([]planResource, configIndex) {
				trail := planResource{
					typ: "aws_cloudtrail", address: "aws_cloudtrail.main",
					values: map[string]any{
						"event_selector": []any{map[string]any{
							"read_write_type": "All",
							"data_resource": []any{map[string]any{
								"type":   "AWS::S3::Object",
								"values": []any{},
							}},
						}},
					},
				}
				idx := configIndex{resources: map[string]exprSet{
					trail.address: {refs: map[string][]string{
						"event_selector": {
							"aws_s3_bucket.app.arn", "aws_s3_bucket.app",
						},
					}},
				}, calls: map[string]exprSet{}}
				return []planResource{bucket, trail}, idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "enable_logging false ignored",
			build: func() ([]planResource, configIndex) {
				trail := planResource{
					typ: "aws_cloudtrail", address: "aws_cloudtrail.main",
					values: map[string]any{
						"enable_logging": false,
						"event_selector": []any{map[string]any{
							"read_write_type": "All",
							"data_resource": []any{map[string]any{
								"type":   "AWS::S3::Object",
								"values": []any{"arn:aws:s3"},
							}},
						}},
					},
				}
				return []planResource{bucket, trail}, configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "no coverage false",
			build: func() ([]planResource, configIndex) {
				return []planResource{bucket}, configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
			},
			wantVal: false, wantKnown: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resources, idx := tc.build()
			got, known := bucketAudit(bucket, resources, idx)
			if known != tc.wantKnown || (known && got != tc.wantVal) {
				t.Fatalf("got (%v,%v) want (%v,%v)", got, known, tc.wantVal, tc.wantKnown)
			}
		})
	}
}

func TestBucketAuditOwnedGate(t *testing.T) {
	plan := []byte(`{
	  "resource_changes": [
	    {"address":"aws_s3_bucket.app","mode":"managed","type":"aws_s3_bucket","change":{"after":{"bucket":"app-data"}}},
	    {"address":"aws_cloudtrail.main","mode":"managed","type":"aws_cloudtrail","change":{"after":{
	      "event_selector":[{"read_write_type":"All","data_resource":[{"type":"AWS::S3::Object","values":["arn:aws:s3:::app-data/"]}]}]
	    }}}
	  ],
	  "configuration": {"root_module":{"resources":[
	    {"address":"aws_s3_bucket.app","type":"aws_s3_bucket","name":"app","mode":"managed","expressions":{"bucket":{"constant_value":"app-data"}}},
	    {"address":"aws_cloudtrail.main","type":"aws_cloudtrail","name":"main","mode":"managed","expressions":{}}
	  ]}}
	}`)
	t.Run("owned", func(t *testing.T) {
		doc, _, err := Parse(plan, []byte("schema_version: fray-config/v1\naudit_config: owned_by_this_root\n"), "", Source{
			Repo: "a/b", Commit: "x", Tool: "terraform", Fidelity: "plan",
		}, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		el := findKind(doc, "object_storage")
		if el.Attributes["audit_logging"] != true {
			t.Fatalf("owned: audit_logging=%#v", el.Attributes["audit_logging"])
		}
	})
	t.Run("not owned", func(t *testing.T) {
		doc, _, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "", Source{
			Repo: "a/b", Commit: "x", Tool: "terraform", Fidelity: "plan",
		}, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		el := findKind(doc, "object_storage")
		if _, ok := el.Attributes["audit_logging"]; ok {
			t.Fatalf("not owned: audit_logging should be absent, got %#v", el.Attributes["audit_logging"])
		}
	})
}

func findKind(doc DFD, kind string) *Element {
	for i := range doc.Elements {
		if doc.Elements[i].Kind == kind {
			return &doc.Elements[i]
		}
	}
	return &Element{}
}
