package client

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestCloudSQLElementAttributes(t *testing.T) {
	cases := []struct {
		name    string
		r       planResource
		prevent bool
		want    map[string]any
		absent  []string
	}{
		{
			name: "public IP, no authorized networks",
			r: cloudSQLRes(map[string]any{
				"ipv4_enabled": true,
			}, nil, true, false),
			want: map[string]any{
				"public":              true,
				"network_restricted":  true,
				"encrypted_at_rest":   true,
				"deletion_protection": true,
			},
			absent: []string{"tls_enforced"},
		},
		{
			name: "public IP, world authorized network",
			r: cloudSQLRes(map[string]any{
				"ipv4_enabled": true,
				"authorized_networks": []any{
					map[string]any{"value": "0.0.0.0/0"},
				},
			}, nil, true, false),
			want: map[string]any{
				"public":             true,
				"network_restricted": false,
				"encrypted_at_rest":  true,
			},
		},
		{
			name: "public IP, narrow/private authorized networks only",
			r: cloudSQLRes(map[string]any{
				"ipv4_enabled": true,
				"authorized_networks": []any{
					map[string]any{"value": "10.0.0.0/8"},
					map[string]any{"value": "203.0.113.5/32"},
				},
			}, nil, true, false),
			want: map[string]any{
				"public":             true,
				"network_restricted": true,
				"encrypted_at_rest":  true,
			},
		},
		{
			name: "ipv4 disabled + private_network",
			r: cloudSQLRes(map[string]any{
				"ipv4_enabled":    false,
				"private_network": "projects/p/global/networks/default",
			}, nil, true, false),
			want: map[string]any{
				"public":            false,
				"encrypted_at_rest": true,
			},
			absent: []string{"network_restricted"},
		},
		{
			name: "ssl_mode ENCRYPTED_ONLY",
			r: cloudSQLRes(map[string]any{
				"ipv4_enabled": false,
				"ssl_mode":     "ENCRYPTED_ONLY",
			}, nil, true, false),
			want: map[string]any{"tls_enforced": true, "encrypted_at_rest": true},
		},
		{
			name: "ssl_mode TRUSTED_CLIENT_CERTIFICATE_REQUIRED",
			r: cloudSQLRes(map[string]any{
				"ipv4_enabled": false,
				"ssl_mode":     "TRUSTED_CLIENT_CERTIFICATE_REQUIRED",
			}, nil, true, false),
			want: map[string]any{"tls_enforced": true},
		},
		{
			name: "ssl_mode ALLOW_UNENCRYPTED_AND_ENCRYPTED",
			r: cloudSQLRes(map[string]any{
				"ipv4_enabled": false,
				"ssl_mode":     "ALLOW_UNENCRYPTED_AND_ENCRYPTED",
			}, nil, true, false),
			want: map[string]any{"tls_enforced": false},
		},
		{
			name: "legacy require_ssl only",
			r: cloudSQLRes(map[string]any{
				"ipv4_enabled": false,
				"require_ssl":  true,
			}, nil, true, false),
			want: map[string]any{"tls_enforced": true},
		},
		{
			name: "ssl_mode wins over require_ssl",
			r: cloudSQLRes(map[string]any{
				"ipv4_enabled": false,
				"ssl_mode":     "ALLOW_UNENCRYPTED_AND_ENCRYPTED",
				"require_ssl":  true,
			}, nil, true, false),
			want: map[string]any{"tls_enforced": false},
		},
		{
			name: "ssl unset",
			r: cloudSQLRes(map[string]any{
				"ipv4_enabled": false,
			}, nil, true, false),
			want:   map[string]any{"encrypted_at_rest": true},
			absent: []string{"tls_enforced"},
		},
		{
			name: "unknown ipv4_enabled",
			r: planResource{
				typ: "google_sql_database_instance", address: "google_sql_database_instance.db",
				values: map[string]any{
					"name":                "db",
					"database_version":    "POSTGRES_15",
					"region":              "europe-west1",
					"project":             "demo",
					"deletion_protection": true,
					"settings": []any{map[string]any{
						"ip_configuration": []any{map[string]any{}},
					}},
				},
				afterUnknown: map[string]any{
					"settings": []any{map[string]any{
						"ip_configuration": []any{map[string]any{"ipv4_enabled": true}},
					}},
				},
			},
			want:   map[string]any{"encrypted_at_rest": true, "deletion_protection": true},
			absent: []string{"public", "network_restricted"},
		},
		{
			name: "unknown authorized network value",
			r: planResource{
				typ: "google_sql_database_instance", address: "google_sql_database_instance.db",
				values: map[string]any{
					"name": "db", "database_version": "POSTGRES_15",
					"deletion_protection": true,
					"settings": []any{map[string]any{
						"ip_configuration": []any{map[string]any{
							"ipv4_enabled": true,
							"authorized_networks": []any{
								map[string]any{"value": nil},
							},
						}},
					}},
				},
				afterUnknown: map[string]any{
					"settings": []any{map[string]any{
						"ip_configuration": []any{map[string]any{
							"authorized_networks": []any{
								map[string]any{"value": true},
							},
						}},
					}},
				},
			},
			want: map[string]any{
				"public":            true,
				"encrypted_at_rest": true,
			},
			absent: []string{"network_restricted"},
		},
		{
			name: "deletion_protection tf true, settings false",
			r: cloudSQLRes(map[string]any{"ipv4_enabled": false},
				boolPtr(false), true, false),
			want: map[string]any{"deletion_protection": true},
		},
		{
			name: "deletion_protection tf false, settings true",
			r: cloudSQLRes(map[string]any{"ipv4_enabled": false},
				boolPtr(true), false, false),
			want: map[string]any{"deletion_protection": true},
		},
		{
			name: "deletion_protection both false",
			r: cloudSQLRes(map[string]any{"ipv4_enabled": false},
				boolPtr(false), false, false),
			want: map[string]any{"deletion_protection": false},
		},
		{
			name: "prevent_destroy wins",
			r: cloudSQLRes(map[string]any{"ipv4_enabled": false},
				boolPtr(false), false, false),
			prevent: true,
			want:    map[string]any{"deletion_protection": true},
		},
		{
			name: "deletion_protection unknown, none true",
			r: planResource{
				typ: "google_sql_database_instance", address: "google_sql_database_instance.db",
				values: map[string]any{
					"name": "db", "database_version": "POSTGRES_15",
					"settings": []any{map[string]any{
						"ip_configuration": []any{map[string]any{"ipv4_enabled": false}},
					}},
				},
				afterUnknown: map[string]any{"deletion_protection": true},
			},
			want:   map[string]any{"encrypted_at_rest": true},
			absent: []string{"deletion_protection"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			el := cloudSQLElement(tc.r, tc.prevent)
			if el.Kind != "relational_db" || el.Provider != "gcp" || el.Provenance != "iac" {
				t.Fatalf("kind/provider/provenance: %+v", el)
			}
			for k, want := range tc.want {
				got, ok := el.Attributes[k]
				if !ok {
					t.Errorf("attr %s absent, want %#v", k, want)
					continue
				}
				if got != want {
					t.Errorf("attr %s: got %#v want %#v", k, got, want)
				}
			}
			for _, k := range tc.absent {
				if _, ok := el.Attributes[k]; ok {
					t.Errorf("attr %s present (%#v), want absent", k, el.Attributes[k])
				}
			}
		})
	}
}

func TestCloudSQLFROutcomes(t *testing.T) {
	// Per-fixture FR-029 / FR-030 / FR-031 / FR-033 from modelled attributes.
	type row struct {
		name                       string
		r                          planResource
		prevent                    bool
		fr029, fr030, fr031, fr033 string
	}
	rows := []row{
		{
			name:  "public IP, no authorized networks",
			r:     cloudSQLRes(map[string]any{"ipv4_enabled": true}, nil, true, false),
			fr029: "mitigated", fr030: "mitigated", fr031: "unverified", fr033: "mitigated",
		},
		{
			name: "public IP, world authorized network",
			r: cloudSQLRes(map[string]any{
				"ipv4_enabled":        true,
				"authorized_networks": []any{map[string]any{"value": "0.0.0.0/0"}},
			}, nil, true, false),
			fr029: "open", fr030: "mitigated", fr031: "unverified", fr033: "mitigated",
		},
		{
			name: "public IP, narrow/private authorized networks only",
			r: cloudSQLRes(map[string]any{
				"ipv4_enabled": true,
				"authorized_networks": []any{
					map[string]any{"value": "10.0.0.0/8"},
					map[string]any{"value": "203.0.113.0/24"},
				},
			}, nil, true, false),
			fr029: "mitigated", fr030: "mitigated", fr031: "unverified", fr033: "mitigated",
		},
		{
			name:  "ipv4 disabled + private_network",
			r:     cloudSQLRes(map[string]any{"ipv4_enabled": false, "private_network": "projects/p/global/networks/n"}, nil, true, false),
			fr029: "mitigated", fr030: "mitigated", fr031: "unverified", fr033: "mitigated",
		},
		{
			name:  "ssl_mode ENCRYPTED_ONLY",
			r:     cloudSQLRes(map[string]any{"ipv4_enabled": false, "ssl_mode": "ENCRYPTED_ONLY"}, nil, true, false),
			fr029: "mitigated", fr030: "mitigated", fr031: "mitigated", fr033: "mitigated",
		},
		{
			name:  "ssl_mode TRUSTED_CLIENT_CERTIFICATE_REQUIRED",
			r:     cloudSQLRes(map[string]any{"ipv4_enabled": false, "ssl_mode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}, nil, true, false),
			fr029: "mitigated", fr030: "mitigated", fr031: "mitigated", fr033: "mitigated",
		},
		{
			name:  "ssl_mode ALLOW_UNENCRYPTED_AND_ENCRYPTED",
			r:     cloudSQLRes(map[string]any{"ipv4_enabled": false, "ssl_mode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}, nil, true, false),
			fr029: "mitigated", fr030: "mitigated", fr031: "open", fr033: "mitigated",
		},
		{
			name:  "legacy require_ssl only",
			r:     cloudSQLRes(map[string]any{"ipv4_enabled": false, "require_ssl": true}, nil, true, false),
			fr029: "mitigated", fr030: "mitigated", fr031: "mitigated", fr033: "mitigated",
		},
		{
			name:  "ssl unset",
			r:     cloudSQLRes(map[string]any{"ipv4_enabled": false}, nil, true, false),
			fr029: "mitigated", fr030: "mitigated", fr031: "unverified", fr033: "mitigated",
		},
		{
			name: "unknown ipv4_enabled",
			r: planResource{
				typ: "google_sql_database_instance", address: "google_sql_database_instance.db",
				values: map[string]any{
					"name": "db", "database_version": "POSTGRES_15", "deletion_protection": true,
					"settings": []any{map[string]any{"ip_configuration": []any{map[string]any{}}}},
				},
				afterUnknown: map[string]any{
					"settings": []any{map[string]any{
						"ip_configuration": []any{map[string]any{"ipv4_enabled": true}},
					}},
				},
			},
			fr029: "unverified", fr030: "mitigated", fr031: "unverified", fr033: "mitigated",
		},
		{
			name: "unknown authorized network",
			r: planResource{
				typ: "google_sql_database_instance", address: "google_sql_database_instance.db",
				values: map[string]any{
					"name": "db", "database_version": "POSTGRES_15", "deletion_protection": true,
					"settings": []any{map[string]any{
						"ip_configuration": []any{map[string]any{
							"ipv4_enabled":        true,
							"authorized_networks": []any{map[string]any{}},
						}},
					}},
				},
				afterUnknown: map[string]any{
					"settings": []any{map[string]any{
						"ip_configuration": []any{map[string]any{
							"authorized_networks": []any{map[string]any{"value": true}},
						}},
					}},
				},
			},
			fr029: "unverified", fr030: "mitigated", fr031: "unverified", fr033: "mitigated",
		},
		{
			name:  "deletion: tf true × settings false × no prevent",
			r:     cloudSQLRes(map[string]any{"ipv4_enabled": false}, boolPtr(false), true, false),
			fr029: "mitigated", fr030: "mitigated", fr031: "unverified", fr033: "mitigated",
		},
		{
			name:  "deletion: tf false × settings true × no prevent",
			r:     cloudSQLRes(map[string]any{"ipv4_enabled": false}, boolPtr(true), false, false),
			fr029: "mitigated", fr030: "mitigated", fr031: "unverified", fr033: "mitigated",
		},
		{
			name:  "deletion: tf false × settings false × no prevent",
			r:     cloudSQLRes(map[string]any{"ipv4_enabled": false}, boolPtr(false), false, false),
			fr029: "mitigated", fr030: "mitigated", fr031: "unverified", fr033: "open",
		},
		{
			name:    "deletion: tf false × settings false × prevent_destroy",
			r:       cloudSQLRes(map[string]any{"ipv4_enabled": false}, boolPtr(false), false, false),
			prevent: true,
			fr029:   "mitigated", fr030: "mitigated", fr031: "unverified", fr033: "mitigated",
		},
		{
			name: "deletion: unknown tf × settings false",
			r: planResource{
				typ: "google_sql_database_instance", address: "google_sql_database_instance.db",
				values: map[string]any{
					"name": "db", "database_version": "POSTGRES_15",
					"settings": []any{map[string]any{
						"deletion_protection_enabled": false,
						"ip_configuration":            []any{map[string]any{"ipv4_enabled": false}},
					}},
				},
				afterUnknown: map[string]any{"deletion_protection": true},
			},
			fr029: "mitigated", fr030: "mitigated", fr031: "unverified", fr033: "unverified",
		},
	}

	var report strings.Builder
	report.WriteString("| fixture | FR-029 | FR-030 | FR-031 | FR-033 |\n")
	report.WriteString("|---|---|---|---|---|\n")
	for _, tc := range rows {
		el := cloudSQLElement(tc.r, tc.prevent)
		got029 := fr029Outcome(el.Attributes)
		got030 := frBoolOutcome(el.Attributes, "encrypted_at_rest")
		got031 := frBoolOutcome(el.Attributes, "tls_enforced")
		got033 := frBoolOutcome(el.Attributes, "deletion_protection")
		if got029 != tc.fr029 || got030 != tc.fr030 || got031 != tc.fr031 || got033 != tc.fr033 {
			t.Errorf("%s: got 029=%s 030=%s 031=%s 033=%s want 029=%s 030=%s 031=%s 033=%s",
				tc.name, got029, got030, got031, got033, tc.fr029, tc.fr030, tc.fr031, tc.fr033)
		}
		fmt.Fprintf(&report, "| %s | %s | %s | %s | %s |\n", tc.name, got029, got030, got031, got033)
	}
	t.Log("\n" + report.String())
}

func TestCloudSQLFlowsAndDATABASEURL(t *testing.T) {
	cfg := []byte("schema_version: fray-config/v1\n")
	src := Source{Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}

	t.Run("postgres + DATABASE_URL with cloud_sql volume", func(t *testing.T) {
		plan := []byte(cloudSQLPlanJSON(cloudSQLPlanOpts{
			withVolume: true, withDATABASEURL: true, instances: 1,
		}))
		doc, _, err := Parse(plan, cfg, "fray.yaml", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		assertRelational(t, doc, 1, "iac")
		assertNoInferredDB(t, doc)
		assertFlowTo(t, doc, "google_cloud_run_v2_service.api", "google_sql_database_instance.db")
	})

	t.Run("postgres + DATABASE_URL without cloud_sql volume", func(t *testing.T) {
		plan := []byte(cloudSQLPlanJSON(cloudSQLPlanOpts{
			withVolume: false, withDATABASEURL: true, instances: 1,
		}))
		doc, _, err := Parse(plan, cfg, "fray.yaml", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		assertRelational(t, doc, 2, "")                             // iac + inferred
		assertFlowTo(t, doc, "google_cloud_run_v2_service.api", "") // inferred target
		var inferred, iac int
		for _, el := range doc.Elements {
			if el.Kind != "relational_db" {
				continue
			}
			switch el.Provenance {
			case "inferred":
				inferred++
			case "iac":
				iac++
			}
		}
		if inferred != 1 || iac != 1 {
			t.Fatalf("want 1 inferred + 1 iac relational_db, got inferred=%d iac=%d", inferred, iac)
		}
		// Flow must target inferred, not Cloud SQL.
		svc := findElByAddr(doc, "google_cloud_run_v2_service.api")
		sql := findElByAddr(doc, "google_sql_database_instance.db")
		for _, f := range doc.Flows {
			if f.From == svc.ID && f.To == sql.ID {
				t.Fatal("unexpected flow to Cloud SQL without volume attachment")
			}
		}
	})

	t.Run("two instances + DATABASE_URL", func(t *testing.T) {
		plan := []byte(cloudSQLPlanJSON(cloudSQLPlanOpts{
			withVolume: true, withDATABASEURL: true, instances: 2,
		}))
		doc, _, err := Parse(plan, cfg, "fray.yaml", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		assertRelational(t, doc, 3, "") // 2 iac + inferred
		svc := findElByAddr(doc, "google_cloud_run_v2_service.api")
		for _, f := range doc.Flows {
			if f.From != svc.ID {
				continue
			}
			to := findElByID(doc, f.To)
			if to != nil && to.Kind == "relational_db" && to.Provenance == "iac" {
				t.Fatal("ambiguous two-instance volume must not create iac DB flow")
			}
		}
	})

	t.Run("Cloud Run v1 annotation", func(t *testing.T) {
		plan := []byte(`{
		  "resource_changes": [
		    {"address":"google_cloud_run_service.api","mode":"managed","type":"google_cloud_run_service","change":{"after":{
		      "name":"api","location":"europe-west1",
		      "template":[{"metadata":[{"annotations":{
		        "run.googleapis.com/cloudsql-instances":"demo:europe-west1:db"
		      }}],"spec":[{"containers":[{"image":"example"}]}]}]
		    }}},
		    {"address":"google_sql_database_instance.db","mode":"managed","type":"google_sql_database_instance","change":{"after":{
		      "name":"db","project":"demo","region":"europe-west1","database_version":"POSTGRES_15",
		      "connection_name":"demo:europe-west1:db","deletion_protection":true,
		      "settings":[{"ip_configuration":[{"ipv4_enabled":false}]}]
		    }}}
		  ]
		}`)
		doc, warnings, err := Parse(plan, cfg, "fray.yaml", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range warnings {
			if strings.Contains(w, "no mapping") {
				t.Fatal(w)
			}
		}
		assertFlowTo(t, doc, "google_cloud_run_service.api", "google_sql_database_instance.db")
	})
}

func TestCloudSQLProviderDeletionProtection(t *testing.T) {
	cases := []struct {
		name    string
		r       planResource
		prevent bool
		want    any // bool, or nil to assert omitted
		fr033   any // expected deletion_protection (bool or nil omitted)
	}{
		{
			name:  "settings true",
			r:     cloudSQLRes(map[string]any{"ipv4_enabled": false}, boolPtr(true), false, false),
			want:  true,
			fr033: true,
		},
		{
			name:  "settings false",
			r:     cloudSQLRes(map[string]any{"ipv4_enabled": false}, boolPtr(false), false, false),
			want:  false,
			fr033: false,
		},
		{
			name:  "settings absent",
			r:     cloudSQLRes(map[string]any{"ipv4_enabled": false}, nil, true, false),
			want:  nil,
			fr033: true, // Terraform deletion_protection alone
		},
		{
			name: "settings unknown",
			r: planResource{
				typ: "google_sql_database_instance", address: "google_sql_database_instance.db",
				values: map[string]any{
					"name": "db", "database_version": "POSTGRES_15",
					"deletion_protection": true,
					"settings": []any{map[string]any{
						"ip_configuration": []any{map[string]any{"ipv4_enabled": false}},
					}},
				},
				afterUnknown: map[string]any{
					"settings": []any{map[string]any{"deletion_protection_enabled": true}},
				},
			},
			want:  nil,
			fr033: true, // Terraform flag known true → FR-033 mitigated despite settings unknown
		},
		{
			name:  "top-level true settings false",
			r:     cloudSQLRes(map[string]any{"ipv4_enabled": false}, boolPtr(false), true, false),
			want:  false,
			fr033: true,
		},
		{
			name:    "prevent_destroy flag false",
			r:       cloudSQLRes(map[string]any{"ipv4_enabled": false}, boolPtr(false), false, false),
			prevent: true,
			want:    false,
			fr033:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			el := cloudSQLElement(tc.r, tc.prevent)
			got, ok := el.Attributes["provider_deletion_protection"]
			if tc.want == nil {
				if ok {
					t.Fatalf("provider_deletion_protection present (%#v), want omitted", got)
				}
			} else if !ok || got != tc.want {
				t.Fatalf("provider_deletion_protection: got %#v (ok=%v) want %#v", got, ok, tc.want)
			}
			got033, ok033 := el.Attributes["deletion_protection"]
			if tc.fr033 == nil {
				if ok033 {
					t.Fatalf("deletion_protection present (%#v), want omitted", got033)
				}
			} else if !ok033 || got033 != tc.fr033 {
				t.Fatalf("deletion_protection: got %#v (ok=%v) want %#v", got033, ok033, tc.fr033)
			}
		})
	}
}

func boolPtr(v bool) *bool { return &v }

func cloudSQLRes(ip map[string]any, settingsDP *bool, tfDP bool, _ bool) planResource {
	const instName = "db"
	settings := map[string]any{
		"ip_configuration": []any{ip},
	}
	if settingsDP != nil {
		settings["deletion_protection_enabled"] = *settingsDP
	}
	return planResource{
		typ: "google_sql_database_instance", address: "google_sql_database_instance.db",
		values: map[string]any{
			"name":                instName,
			"database_version":    "POSTGRES_15",
			"region":              "europe-west1",
			"project":             "demo",
			"connection_name":     "demo:europe-west1:" + instName,
			"deletion_protection": tfDP,
			"settings":            []any{settings},
		},
	}
}

func fr029Outcome(attrs map[string]any) string {
	pub, pubOK := attrs["public"].(bool)
	nr, nrOK := attrs["network_restricted"].(bool)
	if !pubOK {
		return "unverified"
	}
	if !pub {
		return "mitigated"
	}
	if !nrOK {
		return "unverified"
	}
	if nr {
		return "mitigated"
	}
	return "open"
}

func frBoolOutcome(attrs map[string]any, key string) string {
	v, ok := attrs[key].(bool)
	if !ok {
		return "unverified"
	}
	if v {
		return "mitigated"
	}
	return "open"
}

type cloudSQLPlanOpts struct {
	withVolume, withDATABASEURL bool
	instances                   int
}

func cloudSQLPlanJSON(o cloudSQLPlanOpts) string {
	if o.instances < 1 {
		o.instances = 1
	}
	var volumes string
	if o.withVolume {
		instList := `"demo:europe-west1:db"`
		if o.instances >= 2 {
			instList = `"demo:europe-west1:db","demo:europe-west1:db2"`
		}
		volumes = fmt.Sprintf(`,"volumes":[{"name":"cloudsql","cloud_sql_instance":[{"instances":[%s]}]}]`, instList)
	}
	env := ""
	if o.withDATABASEURL {
		env = `,"env":[{"name":"DATABASE_URL","value_source":[{"secret_key_ref":[{"secret":"fray-database-url"}]}]}]`
	}
	resources := fmt.Sprintf(`
	    {"address":"google_cloud_run_v2_service.api","mode":"managed","type":"google_cloud_run_v2_service","change":{"after":{
	      "name":"api","location":"europe-west1",
	      "template":[{"service_account":"api@demo.iam.gserviceaccount.com","containers":[{"image":"example"%s}]%s}]
	    }}},
	    {"address":"google_secret_manager_secret.database_url","mode":"managed","type":"google_secret_manager_secret","change":{"after":{"secret_id":"fray-database-url","rotation":[]}}},
	    {"address":"google_sql_database_instance.db","mode":"managed","type":"google_sql_database_instance","change":{"after":{
	      "name":"db","project":"demo","region":"europe-west1","database_version":"POSTGRES_15",
	      "connection_name":"demo:europe-west1:db","deletion_protection":true,
	      "settings":[{"ip_configuration":[{"ipv4_enabled":false,"ssl_mode":"ENCRYPTED_ONLY"}]}]
	    }}}`, env, volumes)
	if o.instances >= 2 {
		resources += `,
	    {"address":"google_sql_database_instance.db2","mode":"managed","type":"google_sql_database_instance","change":{"after":{
	      "name":"db2","project":"demo","region":"europe-west1","database_version":"POSTGRES_15",
	      "connection_name":"demo:europe-west1:db2","deletion_protection":true,
	      "settings":[{"ip_configuration":[{"ipv4_enabled":false}]}]
	    }}}`
	}
	return `{"resource_changes":[` + resources + `]}`
}

func assertRelational(t *testing.T, doc DFD, n int, onlyProv string) {
	t.Helper()
	count := 0
	for _, el := range doc.Elements {
		if el.Kind != "relational_db" {
			continue
		}
		count++
		if onlyProv != "" && el.Provenance != onlyProv {
			t.Fatalf("relational_db provenance %q want %q", el.Provenance, onlyProv)
		}
	}
	if count != n {
		t.Fatalf("relational_db count %d want %d", count, n)
	}
}

func assertNoInferredDB(t *testing.T, doc DFD) {
	t.Helper()
	for _, el := range doc.Elements {
		if el.Kind == "relational_db" && el.Provenance == "inferred" {
			t.Fatal("inferred DATABASE_URL database should be suppressed")
		}
	}
}

func assertFlowTo(t *testing.T, doc DFD, fromAddr, toAddr string) {
	t.Helper()
	from := findElByAddr(doc, fromAddr)
	if from == nil {
		t.Fatalf("missing from %s", fromAddr)
	}
	var to *Element
	if toAddr != "" {
		to = findElByAddr(doc, toAddr)
		if to == nil {
			t.Fatalf("missing to %s", toAddr)
		}
	}
	for _, f := range doc.Flows {
		if f.From != from.ID || f.Transport != "tls" {
			continue
		}
		el := findElByID(doc, f.To)
		if el == nil || el.Kind != "relational_db" {
			continue
		}
		if toAddr == "" {
			if el.Provenance == "inferred" {
				return
			}
			continue
		}
		if el.ID == to.ID {
			return
		}
	}
	t.Fatalf("no tls flow from %s to relational_db %q", fromAddr, toAddr)
}

func findElByAddr(doc DFD, addr string) *Element {
	for i := range doc.Elements {
		if len(doc.Elements[i].Evidence.Addresses) == 1 && doc.Elements[i].Evidence.Addresses[0] == addr {
			return &doc.Elements[i]
		}
	}
	return nil
}

func findElByID(doc DFD, id string) *Element {
	for i := range doc.Elements {
		if doc.Elements[i].ID == id {
			return &doc.Elements[i]
		}
	}
	return nil
}

// Ensure plan JSON helpers stay valid JSON.
func TestCloudSQLPlanJSONValid(t *testing.T) {
	var v any
	if err := json.Unmarshal([]byte(cloudSQLPlanJSON(cloudSQLPlanOpts{withVolume: true, withDATABASEURL: true, instances: 2})), &v); err != nil {
		t.Fatal(err)
	}
}
