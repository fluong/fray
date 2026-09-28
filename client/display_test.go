package client

import "testing"

func TestDisplayName(t *testing.T) {
	cases := []struct {
		addr, resource, kind, want string
	}{
		{"module.uploads.aws_s3_bucket.this[0]", "fray-aws-web-app-uploads-", "object_storage", "uploads bucket"},
		{"module.ecs_service.aws_ecs_service.this[0]", "fray-aws-web-app", "container_service", "ecs_service"},
		{"module.db_password.aws_secretsmanager_secret.this[0]", "db", "secret_store", "db_password secret"},
		{"aws_s3_bucket.archive", "archive", "object_storage", "archive"},
		{"google_cloud_run_v2_service.fray", "fray-api", "container_service", "fray-api"},
		{"", "", "object_storage", ""},
	}
	for _, tc := range cases {
		if got := DisplayName(tc.addr, tc.resource, tc.kind); got != tc.want {
			t.Errorf("DisplayName(%q,%q,%q)=%q want %q", tc.addr, tc.resource, tc.kind, got, tc.want)
		}
	}
}
