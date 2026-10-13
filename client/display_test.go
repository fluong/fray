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
		{"module.bastion.aws_instance.this[0]", "bastion", "virtual_machine", "bastion instance"},
		{"aws_instance.web", "web", "virtual_machine", "web"},
		{"", "", "object_storage", ""},
	}
	for _, tc := range cases {
		if got := DisplayName(tc.addr, tc.resource, tc.kind); got != tc.want {
			t.Errorf("DisplayName(%q,%q,%q)=%q want %q", tc.addr, tc.resource, tc.kind, got, tc.want)
		}
	}
}

func TestASGDisplayName(t *testing.T) {
	cases := []struct {
		addr, resource, want string
	}{
		{"aws_autoscaling_group.web", "web", "web Auto Scaling group"},
		{"module.asg.aws_autoscaling_group.this[0]", "this", "asg Auto Scaling group"},
		{"module.workers.aws_autoscaling_group.app", "app", "workers Auto Scaling group"},
		{"", "", "Auto Scaling group"},
	}
	for _, tc := range cases {
		if got := ASGDisplayName(tc.addr, tc.resource); got != tc.want {
			t.Errorf("ASGDisplayName(%q,%q)=%q want %q", tc.addr, tc.resource, got, tc.want)
		}
	}
}

func TestEKSNodeGroupDisplayName(t *testing.T) {
	cases := []struct {
		addr, resource, want string
	}{
		{"aws_eks_node_group.workers", "workers", "workers EKS node group"},
		{"module.eks_managed_node_group.aws_eks_node_group.this[0]", "this", "eks_managed_node_group EKS node group"},
		{"module.workers.aws_eks_node_group.app", "app", "workers EKS node group"},
		{"", "", "EKS node group"},
	}
	for _, tc := range cases {
		if got := EKSNodeGroupDisplayName(tc.addr, tc.resource); got != tc.want {
			t.Errorf("EKSNodeGroupDisplayName(%q,%q)=%q want %q", tc.addr, tc.resource, got, tc.want)
		}
	}
}
