package client

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestAuditDataRead(t *testing.T) {
	secret := "secretmanager.googleapis.com"
	storage := "storage.googleapis.com"
	cases := []struct {
		name    string
		audits  []planResource
		service string
		want    bool
	}{
		{
			name: "exact service DATA_READ",
			audits: []planResource{{
				typ: "google_project_iam_audit_config", address: "google_project_iam_audit_config.secret",
				values: map[string]any{
					"service": secret,
					"audit_log_config": []any{
						map[string]any{"log_type": "DATA_READ"},
					},
				},
			}},
			service: secret, want: true,
		},
		{
			name: "allServices DATA_READ",
			audits: []planResource{{
				typ: "google_project_iam_audit_config", address: "google_project_iam_audit_config.all",
				values: map[string]any{
					"service": "allServices",
					"audit_log_config": []any{
						map[string]any{"log_type": "DATA_READ"},
					},
				},
			}},
			service: secret, want: true,
		},
		{
			name: "ADMIN_READ only",
			audits: []planResource{{
				typ: "google_project_iam_audit_config", address: "google_project_iam_audit_config.admin",
				values: map[string]any{
					"service": secret,
					"audit_log_config": []any{
						map[string]any{"log_type": "ADMIN_READ"},
					},
				},
			}},
			service: secret, want: false,
		},
		{
			name: "folder-level DATA_READ",
			audits: []planResource{{
				typ: "google_folder_iam_audit_config", address: "google_folder_iam_audit_config.secret",
				values: map[string]any{
					"service": secret,
					"audit_log_config": []any{
						map[string]any{"log_type": "DATA_READ"},
					},
				},
			}},
			service: secret, want: true,
		},
		{
			name: "organization-level DATA_READ",
			audits: []planResource{{
				typ: "google_organization_iam_audit_config", address: "google_organization_iam_audit_config.storage",
				values: map[string]any{
					"service": storage,
					"audit_log_config": []any{
						map[string]any{"log_type": "DATA_READ"},
					},
				},
			}},
			service: storage, want: true,
		},
		{
			name: "exempted_members still covers",
			audits: []planResource{{
				typ: "google_project_iam_audit_config", address: "google_project_iam_audit_config.exempt",
				values: map[string]any{
					"service": secret,
					"audit_log_config": []any{
						map[string]any{
							"log_type":         "DATA_READ",
							"exempted_members": []any{"serviceAccount:bot@example.iam.gserviceaccount.com"},
						},
					},
				},
			}},
			service: secret, want: true,
		},
		{
			name: "other service ignored",
			audits: []planResource{{
				typ: "google_project_iam_audit_config", address: "google_project_iam_audit_config.other",
				values: map[string]any{
					"service": "compute.googleapis.com",
					"audit_log_config": []any{
						map[string]any{"log_type": "DATA_READ"},
					},
				},
			}},
			service: secret, want: false,
		},
		{
			name:    "no config",
			audits:  nil,
			service: secret, want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := auditDataRead(tc.audits, tc.service)
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestGCPAuditParseRecognition(t *testing.T) {
	// Item 1: recognition via Parse. Secrets still always emit a bool.
	cases := []struct {
		name      string
		auditType string
		service   string
		logType   string
		extra     map[string]any
		want      bool
	}{
		{name: "exact service DATA_READ", auditType: "google_project_iam_audit_config", service: "secretmanager.googleapis.com", logType: "DATA_READ", want: true},
		{name: "allServices DATA_READ", auditType: "google_project_iam_audit_config", service: "allServices", logType: "DATA_READ", want: true},
		{name: "folder-level DATA_READ", auditType: "google_folder_iam_audit_config", service: "secretmanager.googleapis.com", logType: "DATA_READ", want: true},
		{name: "org-level DATA_READ", auditType: "google_organization_iam_audit_config", service: "secretmanager.googleapis.com", logType: "DATA_READ", want: true},
		{name: "exempted_members still true", auditType: "google_project_iam_audit_config", service: "secretmanager.googleapis.com", logType: "DATA_READ",
			extra: map[string]any{"exempted_members": []any{"user:a@example.com"}}, want: true},
		{name: "ADMIN_READ only false", auditType: "google_project_iam_audit_config", service: "secretmanager.googleapis.com", logType: "ADMIN_READ", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logCfg := map[string]any{"log_type": tc.logType}
			for k, v := range tc.extra {
				logCfg[k] = v
			}
			plan := gcpAuditPlanJSON(tc.auditType, tc.service, []any{logCfg})
			doc, _, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "", Source{
				Repo: "a/b", Commit: "x", Tool: "terraform", Fidelity: "plan",
			}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			sec := findKind(doc, "secret_store")
			if sec.Attributes["audit_logging"] != tc.want {
				t.Fatalf("secret audit_logging=%#v want %v", sec.Attributes["audit_logging"], tc.want)
			}
			bucket := findKind(doc, "object_storage")
			// Storage only emits when owned; without owned_by_this_root it stays absent.
			if _, ok := bucket.Attributes["audit_logging"]; ok {
				t.Fatalf("bucket audit_logging should be absent without owned, got %#v", bucket.Attributes["audit_logging"])
			}
		})
	}
}

func gcpAuditPlanJSON(auditType, service string, logConfigs []any) []byte {
	after := map[string]any{
		"service":          service,
		"audit_log_config": logConfigs,
	}
	auditAfter, err := json.Marshal(after)
	if err != nil {
		panic(err)
	}
	auditAddr := auditType + ".cfg"
	return []byte(fmt.Sprintf(`{
	  "resource_changes": [
	    {"address":"google_secret_manager_secret.app","mode":"managed","type":"google_secret_manager_secret","change":{"after":{"secret_id":"app-secret","rotation":[]}}},
	    {"address":"google_storage_bucket.assets","mode":"managed","type":"google_storage_bucket","change":{"after":{"name":"assets","uniform_bucket_level_access":true,"public_access_prevention":"enforced"}}},
	    {"address":%q,"mode":"managed","type":%q,"change":{"after":%s}}
	  ],
	  "configuration": {"root_module":{"resources":[
	    {"address":"google_secret_manager_secret.app","type":"google_secret_manager_secret","name":"app","mode":"managed","expressions":{}},
	    {"address":"google_storage_bucket.assets","type":"google_storage_bucket","name":"assets","mode":"managed","expressions":{}},
	    {"address":%q,"type":%q,"name":"cfg","mode":"managed","expressions":{}}
	  ]}}
	}`, auditAddr, auditType, auditAfter, auditAddr, auditType))
}
