package client

import (
	"slices"
	"testing"
)

func TestRDSControlActionClassTable(t *testing.T) {
	tableCases := []struct {
		action string
		want   []string
	}{
		{"rds:ModifyDBInstance", []string{"reset_credentials"}},
		{"rds:ModifyDBCluster", []string{"reset_credentials"}},
		{"rds:CreateDBSnapshot", []string{"snapshot_exfiltrate"}},
		{"rds:CreateDBClusterSnapshot", []string{"snapshot_exfiltrate"}},
		{"rds:ModifyDBSnapshotAttribute", []string{"snapshot_exfiltrate"}},
		{"rds:ModifyDBClusterSnapshotAttribute", []string{"snapshot_exfiltrate"}},
		{"rds:CopyDBSnapshot", []string{"snapshot_exfiltrate"}},
		{"rds:CopyDBClusterSnapshot", []string{"snapshot_exfiltrate"}},
		{"rds:StartExportTask", []string{"snapshot_exfiltrate"}},
		{"rds:RestoreDBInstanceFromDBSnapshot", []string{"restore_clone"}},
		{"rds:RestoreDBInstanceToPointInTime", []string{"restore_clone"}},
		{"rds:RestoreDBClusterFromSnapshot", []string{"restore_clone"}},
		{"rds:RestoreDBClusterToPointInTime", []string{"restore_clone"}},
		{"rds:DeleteDBInstance", []string{"delete"}},
		{"rds:DeleteDBCluster", []string{"delete"}},
		{"rds:DeleteDBSnapshot", []string{"delete"}},
		{"rds:DeleteDBClusterSnapshot", []string{"delete"}},
	}
	for _, tc := range tableCases {
		t.Run(tc.action, func(t *testing.T) {
			got := rdsControlClassesForAction(tc.action)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}

	negatives := []string{
		"rds:ModifyDBParameterGroup",
		"rds:ModifyDBSubnetGroup",
		"rds:DescribeDBInstances",
		"rds-db:connect",
		"rds:RebootDBInstance",
	}
	for _, action := range negatives {
		t.Run("neg_"+action, func(t *testing.T) {
			if got := rdsControlClassesForAction(action); len(got) != 0 {
				t.Fatalf("got %v want none", got)
			}
		})
	}

	wildcards := []struct {
		pattern string
		want    []string
	}{
		{"rds:Modify*", []string{"reset_credentials", "snapshot_exfiltrate"}},
		{"rds:Delete*", []string{"delete"}},
		{"rds:*", dbControlClassOrder},
		{"*", dbControlClassOrder},
	}
	for _, tc := range wildcards {
		t.Run("glob_"+tc.pattern, func(t *testing.T) {
			got := rdsControlClassesForAction(tc.pattern)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestDBControlWildcardInlineAccount(t *testing.T) {
	dest := &Element{Kind: "relational_db", Evidence: Evidence{Addresses: []string{"aws_db_instance.main"}}}
	destRes := planResource{
		address: "aws_db_instance.main", typ: "aws_db_instance",
		values: map[string]any{"arn": "arn:aws:rds:us-east-1:111122223333:db:main", "identifier": "main"},
	}
	raw := `{"Version":"2012-10-17","Statement":[{"Action":"rds:*","Effect":"Allow","Resource":"*"}]}`
	syn, ok := syntheticDocFromPolicyJSON("aws_iam_role_policy.db_control_wildcard", raw)
	if !ok {
		t.Fatal("synthetic doc")
	}
	classes, scope, cause, unreadable := awsDBControlFromDocs(dest, []planResource{syn}, configIndex{}, []planResource{destRes}, nil)
	if unreadable || len(classes) != 4 || scope != "account" {
		t.Fatalf("classes=%v scope=%q unreadable=%v cause=%q", classes, scope, unreadable, cause)
	}
}

func TestSubtractDBControlDenyWithoutCondition(t *testing.T) {
	dest := &Element{
		Kind:     "relational_db",
		Evidence: Evidence{Addresses: []string{"aws_db_instance.main"}},
	}
	destRes := planResource{
		address: "aws_db_instance.main",
		typ:     "aws_db_instance",
		values:  map[string]any{"arn": "arn:aws:rds:us-east-1:111122223333:db:main", "identifier": "main"},
	}
	grantDoc := iamPolicyDoc("data.aws_iam_policy_document.grant", []iamStatement{
		{actions: []string{"rds:CreateDBSnapshot", "rds:DeleteDBInstance"}, allow: true, resources: []any{"arn:aws:rds:us-east-1:111122223333:db:main"}, doc: "data.aws_iam_policy_document.grant"},
	})
	denyDoc := iamPolicyDoc("data.aws_iam_policy_document.deny", []iamStatement{
		{actions: []string{"rds:DeleteDBInstance"}, allow: false, resources: []any{"arn:aws:rds:us-east-1:111122223333:db:main"}, doc: "data.aws_iam_policy_document.deny"},
	})
	docs := []planResource{grantDoc, denyDoc}
	classes, scope, _, _ := awsDBControlFromDocs(dest, []planResource{grantDoc}, configIndex{}, []planResource{destRes}, nil)
	classes = subtractDBControlDenies(classes, scope, dest, docs, configIndex{}, []planResource{destRes}, nil)
	if len(classes) != 1 || classes[0] != "snapshot_exfiltrate" {
		t.Fatalf("classes=%v want [snapshot_exfiltrate]", classes)
	}
}

func TestSubtractDBControlDenyWithConditionIgnored(t *testing.T) {
	dest := &Element{
		Kind:     "relational_db",
		Evidence: Evidence{Addresses: []string{"aws_db_instance.main"}},
	}
	destRes := planResource{
		address: "aws_db_instance.main",
		typ:     "aws_db_instance",
		values:  map[string]any{"arn": "arn:aws:rds:us-east-1:111122223333:db:main", "identifier": "main"},
	}
	grantDoc := iamPolicyDoc("data.aws_iam_policy_document.grant", []iamStatement{
		{actions: []string{"rds:CreateDBSnapshot", "rds:DeleteDBInstance"}, allow: true, resources: []any{"arn:aws:rds:us-east-1:111122223333:db:main"}, doc: "data.aws_iam_policy_document.grant"},
	})
	denyDoc := iamPolicyDoc("data.aws_iam_policy_document.deny", []iamStatement{
		{
			actions: []string{"rds:DeleteDBInstance"}, allow: false, condition: true,
			resources: []any{"arn:aws:rds:us-east-1:111122223333:db:main"}, doc: "data.aws_iam_policy_document.deny",
		},
	})
	docs := []planResource{grantDoc, denyDoc}
	classes, scope, _, _ := awsDBControlFromDocs(dest, []planResource{grantDoc}, configIndex{}, []planResource{destRes}, nil)
	classes = subtractDBControlDenies(classes, scope, dest, docs, configIndex{}, []planResource{destRes}, nil)
	if len(classes) != 2 {
		t.Fatalf("classes=%v want both grant classes", classes)
	}
}

func TestDBControlUnreadableResourceOmits(t *testing.T) {
	dest := &Element{
		Kind:     "relational_db",
		Evidence: Evidence{Addresses: []string{"aws_db_instance.main"}},
	}
	destRes := planResource{
		address: "aws_db_instance.main",
		typ:     "aws_db_instance",
		values:  map[string]any{"arn": "arn:aws:rds:us-east-1:111122223333:db:main", "identifier": "main"},
	}
	grantDoc := iamPolicyDoc("data.aws_iam_policy_document.grant", []iamStatement{
		{actions: []string{"rds:ModifyDBInstance"}, allow: true, resources: []any{nil}, doc: "data.aws_iam_policy_document.grant"},
	})
	idx := configIndex{resources: map[string]exprSet{}}
	_, _, _, unreadable := awsDBControlFromDocs(dest, []planResource{grantDoc}, idx, []planResource{destRes}, nil)
	if !unreadable {
		t.Fatal("want unreadable resource → omit")
	}
}

func TestAmazonRDSFullAccessDBControlAccountWide(t *testing.T) {
	src := &Element{
		Kind:     "virtual_machine",
		Evidence: Evidence{Addresses: []string{"aws_lambda_function.fn"}},
	}
	dest := &Element{
		Kind:     "relational_db",
		Evidence: Evidence{Addresses: []string{"aws_db_instance.main"}},
	}
	resources := []planResource{
		{address: "aws_lambda_function.fn", typ: "aws_lambda_function", values: map[string]any{"function_name": "fn", "role": "arn:aws:iam::111122223333:role/app"}},
		{address: "aws_iam_role.app", typ: "aws_iam_role", values: map[string]any{"name": "app"}},
		{
			address: "aws_iam_role_policy.app_rds",
			typ:     "aws_iam_role_policy",
			values:  map[string]any{"name": "connect", "role": "app", "policy": "{}"},
		},
		{
			address: "aws_iam_role_policy_attachment.rds_full",
			typ:     "aws_iam_role_policy_attachment",
			values: map[string]any{
				"role":       "app",
				"policy_arn": "arn:aws:iam::aws:policy/AmazonRDSFullAccess",
			},
		},
		{
			address: "aws_db_instance.main", typ: "aws_db_instance",
			values: map[string]any{"arn": "arn:aws:rds:us-east-1:111122223333:db:main", "identifier": "main"},
		},
	}
	data := []planResource{
		iamPolicyDoc("data.aws_iam_policy_document.connect", []iamStatement{
			{actions: []string{"rds-db:connect"}, allow: true, resources: []any{"arn:aws:rds-db:us-east-1:111122223333:dbuser:main/app"}, doc: "data.aws_iam_policy_document.connect"},
		}),
	}
	idx := configIndex{resources: map[string]exprSet{
		"aws_lambda_function.fn": {refs: map[string][]string{"role": {"aws_iam_role.app.arn", "aws_iam_role.app"}}},
		"aws_iam_role_policy.app_rds": {refs: map[string][]string{
			"role":   {"aws_iam_role.app.name", "aws_iam_role.app"},
			"policy": {"data.aws_iam_policy_document.connect.json", "data.aws_iam_policy_document.connect"},
		}},
		"aws_iam_role_policy_attachment.rds_full": {refs: map[string][]string{
			"role":       {"aws_iam_role.app.name", "aws_iam_role.app"},
			"policy_arn": {"arn:aws:iam::aws:policy/AmazonRDSFullAccess"},
		}},
	}}
	flow := &Flow{
		From: src.canonicalKey(), To: dest.canonicalKey(),
		AuthzScope: "resource", AuthzGrants: []string{"resource"},
		Causes: map[string]string{"authz_scope": "data.aws_iam_policy_document.connect"},
	}
	var warns []string
	attachDBControlPlane(flow, src, dest, resources, data, idx, []*Element{src, dest}, &warns)
	if flow.AuthzScope != "resource" || flow.Causes["authz_scope"] != "data.aws_iam_policy_document.connect" {
		t.Fatalf("attachDBControlPlane must not change FR-028 authz_scope")
	}
	if flow.AuthzDBControlScope != "account" {
		t.Fatalf("control scope=%q want account", flow.AuthzDBControlScope)
	}
	if len(flow.AuthzDBControlClasses) != 4 {
		t.Fatalf("control classes=%v want all four", flow.AuthzDBControlClasses)
	}
	if flow.Causes["authz_db_control_classes"] != "aws_iam_role_policy_attachment.rds_full" {
		t.Fatalf("control cause=%q", flow.Causes["authz_db_control_classes"])
	}
}

func iamPolicyDoc(addr string, stmts []iamStatement) planResource {
	var stmtVals []any
	for _, st := range stmts {
		effect := "Allow"
		if !st.allow {
			effect = "Deny"
		}
		acts := make([]any, len(st.actions))
		for i, a := range st.actions {
			acts[i] = a
		}
		s := map[string]any{
			"actions":   acts,
			"resources": st.resources,
			"effect":    effect,
		}
		if st.condition {
			s["condition"] = []any{map[string]any{"test": "Bool", "variable": "aws:SecureTransport", "values": []any{"true"}}}
		}
		stmtVals = append(stmtVals, s)
	}
	return planResource{
		address: addr,
		typ:     "aws_iam_policy_document",
		values: map[string]any{
			"statement": stmtVals,
			"json":      "{}",
		},
	}
}
