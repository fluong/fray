package client

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassifyDynamoDBARN(t *testing.T) {
	sessions := planResource{
		address: "aws_dynamodb_table.sessions", typ: "aws_dynamodb_table",
		values: map[string]any{"name": "sessions", "arn": "arn:aws:dynamodb:us-east-1:123:table/sessions"},
	}
	items := planResource{
		address: "aws_dynamodb_table.items", typ: "aws_dynamodb_table",
		values: map[string]any{"name": "items", "arn": "arn:aws:dynamodb:us-east-1:123:table/items"},
	}
	resources := []planResource{sessions, items}
	elements := []*Element{
		awsDynamoDBTableElement(sessions, false),
		awsDynamoDBTableElement(items, false),
	}
	cases := []struct {
		arn     string
		account bool
		want    string
	}{
		{"*", true, ""},
		{"arn:aws:dynamodb:us-east-1:123:table/sessions", false, "aws_dynamodb_table.sessions"},
		{"arn:aws:dynamodb:us-east-1:123:table/sessions/index/gsi", false, "aws_dynamodb_table.sessions"},
		{"arn:aws:dynamodb:us-east-1:123:table/sessions/stream/2020-01-01", false, "aws_dynamodb_table.sessions"},
		{"arn:aws:dynamodb:us-east-1:123:table/*", true, ""},
		{"arn:aws:dynamodb:*:*:table/sessions", true, ""},
		{"arn:aws:dynamodb:us-east-1:123:table/other", false, ""},
	}
	for _, tc := range cases {
		acc, el := classifyDynamoDBARN(tc.arn, resources, elements)
		if acc != tc.account {
			t.Fatalf("%q account=%v want %v", tc.arn, acc, tc.account)
		}
		got := ""
		if el != nil && len(el.Evidence.Addresses) > 0 {
			got = el.Evidence.Addresses[0]
		}
		if got != tc.want {
			t.Fatalf("%q el=%q want %q", tc.arn, got, tc.want)
		}
	}
}

func dynamoTestPolicyDoc(t *testing.T, address, policy string) planResource {
	t.Helper()
	doc, ok := syntheticDocFromPolicyJSON(address, policy)
	if !ok {
		t.Fatal("bad policy json")
	}
	return doc
}

func TestTablesFromDocsNamedSingleTableResourceScope(t *testing.T) {
	table := planResource{
		address: "aws_dynamodb_table.sessions", typ: "aws_dynamodb_table",
		values: map[string]any{"name": "sessions", "arn": "arn:aws:dynamodb:us-east-1:123:table/sessions"},
	}
	el := awsDynamoDBTableElement(table, false)
	policy := `{"Statement":[{"Effect":"Allow","Action":["dynamodb:GetItem"],"Resource":["arn:aws:dynamodb:us-east-1:123:table/sessions"]}]}`
	docs := []planResource{dynamoTestPolicyDoc(t, "aws_iam_role_policy.app", policy)}
	tables, grants, cause, _ := tablesFromDocs(docs, nil, []planResource{table}, nil, []*Element{el}, configIndex{})
	if len(tables) != 1 || effectiveAuthzScope(grants) != "resource" {
		t.Fatalf("tables=%d grants=%v", len(tables), grants)
	}
	if cause != "aws_iam_role_policy.app" {
		t.Fatalf("cause=%q", cause)
	}
}

func TestTablesFromDocsTwoNamedTablesTwoTargets(t *testing.T) {
	a := planResource{address: "aws_dynamodb_table.a", typ: "aws_dynamodb_table", values: map[string]any{
		"name": "a", "arn": "arn:aws:dynamodb:us-east-1:1:table/a",
	}}
	b := planResource{address: "aws_dynamodb_table.b", typ: "aws_dynamodb_table", values: map[string]any{
		"name": "b", "arn": "arn:aws:dynamodb:us-east-1:1:table/b",
	}}
	elements := []*Element{awsDynamoDBTableElement(a, false), awsDynamoDBTableElement(b, false)}
	policy := `{"Statement":[{"Effect":"Allow","Action":["dynamodb:*"],"Resource":["arn:aws:dynamodb:us-east-1:1:table/a","arn:aws:dynamodb:us-east-1:1:table/b"]}]}`
	docs := []planResource{dynamoTestPolicyDoc(t, "aws_iam_role_policy.p", policy)}
	tables, grants, _, _ := tablesFromDocs(docs, nil, []planResource{a, b}, nil, elements, configIndex{})
	if len(tables) != 2 || effectiveAuthzScope(grants) != "resource" {
		t.Fatalf("tables=%d grants=%v", len(tables), grants)
	}
}

func TestTablesFromDocsNamedPlusStarAccountOnEach(t *testing.T) {
	table := planResource{address: "aws_dynamodb_table.sessions", typ: "aws_dynamodb_table", values: map[string]any{
		"name": "sessions", "arn": "arn:aws:dynamodb:us-east-1:1:table/sessions",
	}}
	el := awsDynamoDBTableElement(table, false)
	policy := `{"Statement":[{"Effect":"Allow","Action":["dynamodb:GetItem"],"Resource":["arn:aws:dynamodb:us-east-1:1:table/sessions","*"]}]}`
	docs := []planResource{dynamoTestPolicyDoc(t, "aws_iam_role_policy.p", policy)}
	tables, grants, _, _ := tablesFromDocs(docs, nil, []planResource{table}, nil, []*Element{el}, configIndex{})
	if len(tables) != 1 || effectiveAuthzScope(grants) != "account" {
		t.Fatalf("tables=%d scope=%q grants=%v", len(tables), effectiveAuthzScope(grants), grants)
	}
}

func TestTablesFromDocsStarOnlyOneTableAccount(t *testing.T) {
	table := planResource{address: "aws_dynamodb_table.only", typ: "aws_dynamodb_table", values: map[string]any{"name": "only"}}
	el := awsDynamoDBTableElement(table, false)
	policy := `{"Statement":[{"Effect":"Allow","Action":["dynamodb:Scan"],"Resource":["*"]}]}`
	docs := []planResource{dynamoTestPolicyDoc(t, "aws_iam_role_policy.w", policy)}
	tables, grants, cause, _ := tablesFromDocs(docs, nil, []planResource{table}, nil, []*Element{el}, configIndex{})
	if len(tables) != 1 || effectiveAuthzScope(grants) != "account" {
		t.Fatalf("tables=%d grants=%v", len(tables), grants)
	}
	if cause != "aws_iam_role_policy.w" {
		t.Fatalf("cause=%q", cause)
	}
}

func dynamoDataDocPlanIndex(t *testing.T, docAddr string, statementExprs []map[string]any) configIndex {
	t.Helper()
	stmtExprs := make([]any, len(statementExprs))
	for i, se := range statementExprs {
		stmtExprs[i] = se
	}
	plan := map[string]any{
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": []any{
					map[string]any{
						"address": docAddr, "mode": "data", "type": "aws_iam_policy_document",
						"name":        strings.TrimPrefix(docAddr, "data.aws_iam_policy_document."),
						"expressions": map[string]any{"statement": stmtExprs},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := indexConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

func deferredDynamoDataDoc(address string, stmts []map[string]any) planResource {
	stmtAny := make([]any, len(stmts))
	for i, s := range stmts {
		stmtAny[i] = s
	}
	return planResource{
		address: address, typ: "aws_iam_policy_document",
		values: map[string]any{"statement": stmtAny},
	}
}

// (a) Unknown plan resources + config refs that do not name an in-plan table must
// not infer a table target (including the sole-table wildcard fallback).
func TestTablesFromDocsVarRefDoesNotGuessTable(t *testing.T) {
	table := planResource{
		address: "aws_dynamodb_table.sessions", typ: "aws_dynamodb_table",
		values: map[string]any{"name": "sessions", "arn": "arn:aws:dynamodb:us-east-1:1:table/sessions"},
	}
	el := awsDynamoDBTableElement(table, false)
	doc := deferredDynamoDataDoc("data.aws_iam_policy_document.app", []map[string]any{{
		"actions": []any{"dynamodb:GetItem"}, "resources": []any{nil},
	}})
	idx := dynamoDataDocPlanIndex(t, doc.address, []map[string]any{
		{"resources": map[string]any{"references": []any{"var.table_arn"}}},
	})
	tables, grants, _, _ := tablesFromDocs([]planResource{doc}, nil, []planResource{table}, nil, []*Element{el}, idx)
	if len(tables) != 0 || len(grants) != 0 {
		t.Fatalf("want no targets/grants, got tables=%d grants=%v", len(tables), grants)
	}
}

func TestTableFlowsForRoleVarRefDynamoScopeOmittedNotGuessed(t *testing.T) {
	table := planResource{
		address: "aws_dynamodb_table.sessions", typ: "aws_dynamodb_table",
		values: map[string]any{"name": "sessions", "arn": "arn:aws:dynamodb:us-east-1:1:table/sessions"},
	}
	el := awsDynamoDBTableElement(table, false)
	doc := deferredDynamoDataDoc("data.aws_iam_policy_document.app", []map[string]any{{
		"actions": []any{"dynamodb:GetItem"}, "resources": []any{nil},
	}})
	idx := dynamoDataDocPlanIndex(t, doc.address, []map[string]any{
		{"resources": map[string]any{"references": []any{"module.out.aws_dynamodb_table.x.arn", "module.out.aws_dynamodb_table.x"}}},
	})
	resources := []planResource{
		table,
		{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{"name": "task"}},
		{address: "aws_iam_role_policy.app", typ: "aws_iam_role_policy", values: map[string]any{"name": "app-dynamo"}},
		{address: "aws_iam_role_policy_attachment.extra", typ: "aws_iam_role_policy_attachment", values: map[string]any{
			"policy_arn": "arn:aws:iam::123456789012:policy/ExternalDDB",
		}},
	}
	// Merge attachment role ref into index via minimal plan patch.
	attachPlan := map[string]any{
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": []any{
					map[string]any{
						"address": "aws_iam_role_policy_attachment.extra", "type": "aws_iam_role_policy_attachment", "name": "extra",
						"expressions": map[string]any{
							"role": map[string]any{"references": []any{"aws_iam_role.task.id", "aws_iam_role.task"}},
						},
					},
					map[string]any{
						"address": "aws_iam_role_policy.app", "type": "aws_iam_role_policy", "name": "app",
						"expressions": map[string]any{
							"role":   map[string]any{"references": []any{"aws_iam_role.task.id", "aws_iam_role.task"}},
							"policy": map[string]any{"references": []any{"data.aws_iam_policy_document.app.json", "data.aws_iam_policy_document.app"}},
						},
					},
				},
			},
		},
	}
	raw, _ := json.Marshal(attachPlan)
	attachIdx, _ := indexConfig(raw)
	for k, v := range attachIdx.resources {
		idx.resources[k] = v
	}
	from := &Element{Kind: "container_service", Evidence: Evidence{Addresses: []string{"aws_ecs_service.app"}}}
	var warns []string
	flows := tableFlowsForRole(from, "", []string{"aws_iam_role.task"}, resources, []planResource{doc}, idx, []*Element{el}, &warns)
	for _, f := range flows {
		if f.AuthzScope != "" {
			t.Fatalf("must not guess authz_scope, got %q flow=%v", f.AuthzScope, f)
		}
	}
	if len(flows) != 0 {
		t.Fatalf("var/module-output refs must not produce DynamoDB flows, got %d", len(flows))
	}
	var omitWarn bool
	for _, w := range warns {
		if strings.Contains(w, "authz_scope omitted for aws_iam_role.task") {
			omitWarn = true
		}
	}
	if !omitWarn {
		t.Fatalf("want authz_scope omitted warning for role, got %v", warns)
	}
}

// (b) Constant "*" plus a second statement with unknown resources naming table X → account on X.
func TestTablesFromDocsStarPlusUnknownRefTableAccountScope(t *testing.T) {
	audit := planResource{
		address: "aws_dynamodb_table.audit", typ: "aws_dynamodb_table",
		values: map[string]any{"name": "audit", "arn": "arn:aws:dynamodb:us-east-1:1:table/audit"},
	}
	sessions := planResource{
		address: "aws_dynamodb_table.sessions", typ: "aws_dynamodb_table",
		values: map[string]any{"name": "sessions", "arn": "arn:aws:dynamodb:us-east-1:1:table/sessions"},
	}
	elements := []*Element{awsDynamoDBTableElement(audit, false), awsDynamoDBTableElement(sessions, false)}
	doc := deferredDynamoDataDoc("data.aws_iam_policy_document.audit_writer_ddb", []map[string]any{
		{"actions": []any{"dynamodb:*"}, "resources": []any{"*"}, "sid": "wide"},
		{"actions": []any{"dynamodb:*"}, "resources": []any{nil}, "sid": "audit"},
	})
	idx := dynamoDataDocPlanIndex(t, doc.address, []map[string]any{
		{"resources": map[string]any{"constant_value": []any{"*"}}},
		{"resources": map[string]any{"references": []any{"aws_dynamodb_table.audit.arn", "aws_dynamodb_table.audit"}}},
	})
	tables, grants, cause, _ := tablesFromDocs([]planResource{doc}, nil, []planResource{audit, sessions}, nil, elements, idx)
	if len(tables) != 1 || tables[0].Evidence.Addresses[0] != "aws_dynamodb_table.audit" {
		t.Fatalf("tables=%v", tables)
	}
	if effectiveAuthzScope(grants) != "account" {
		t.Fatalf("grants=%v", grants)
	}
	if cause != doc.address {
		t.Fatalf("cause=%q", cause)
	}
}

// (c) Unknown resources with configuration refs to table X only → resource scope on X.
func TestTablesFromDocsUnknownResourcesConfigTableRefResourceScope(t *testing.T) {
	table := planResource{
		address: "aws_dynamodb_table.sessions", typ: "aws_dynamodb_table",
		values: map[string]any{"name": "sessions", "arn": "arn:aws:dynamodb:us-east-1:1:table/sessions"},
	}
	el := awsDynamoDBTableElement(table, false)
	doc := deferredDynamoDataDoc("data.aws_iam_policy_document.app_dynamodb_sessions", []map[string]any{{
		"actions":   []any{"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"},
		"resources": []any{nil, nil},
		"sid":       "DynamoDBSessions",
	}})
	idx := dynamoDataDocPlanIndex(t, doc.address, []map[string]any{
		{"resources": map[string]any{"references": []any{
			"aws_dynamodb_table.sessions.arn", "aws_dynamodb_table.sessions",
			"aws_dynamodb_table.sessions.arn", "aws_dynamodb_table.sessions",
		}}},
	})
	tables, grants, cause, _ := tablesFromDocs([]planResource{doc}, nil, []planResource{table}, nil, []*Element{el}, idx)
	if len(tables) != 1 || effectiveAuthzScope(grants) != "resource" {
		t.Fatalf("tables=%d grants=%v", len(tables), grants)
	}
	if cause != doc.address {
		t.Fatalf("cause=%q", cause)
	}
}

func TestTablesFromDocsStarOnlyTwoTablesNoFlow(t *testing.T) {
	a := planResource{address: "aws_dynamodb_table.a", typ: "aws_dynamodb_table", values: map[string]any{"name": "a"}}
	b := planResource{address: "aws_dynamodb_table.b", typ: "aws_dynamodb_table", values: map[string]any{"name": "b"}}
	elements := []*Element{awsDynamoDBTableElement(a, false), awsDynamoDBTableElement(b, false)}
	policy := `{"Statement":[{"Effect":"Allow","Action":["dynamodb:Scan"],"Resource":["*"]}]}`
	docs := []planResource{dynamoTestPolicyDoc(t, "aws_iam_role_policy.w", policy)}
	tables, _, _, _ := tablesFromDocs(docs, nil, []planResource{a, b}, nil, elements, configIndex{})
	if len(tables) != 0 {
		t.Fatalf("want no tables, got %d", len(tables))
	}
}

func TestTablesFromDocsKnownWideFullAccess(t *testing.T) {
	table := planResource{address: "aws_dynamodb_table.sessions", typ: "aws_dynamodb_table", values: map[string]any{
		"name": "sessions", "arn": "arn:aws:dynamodb:us-east-1:1:table/sessions",
	}}
	el := awsDynamoDBTableElement(table, false)
	policy := `{"Statement":[{"Effect":"Allow","Action":["dynamodb:GetItem"],"Resource":["arn:aws:dynamodb:us-east-1:1:table/sessions"]}]}`
	resources := []planResource{
		table,
		{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{"name": "task"}},
		{address: "aws_iam_role_policy.task", typ: "aws_iam_role_policy", values: map[string]any{"policy": policy}},
		{address: "aws_iam_role_policy_attachment.ddb", typ: "aws_iam_role_policy_attachment", values: map[string]any{
			"policy_arn": "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess",
		}},
	}
	idx := configIndex{resources: map[string]exprSet{
		"aws_iam_role_policy.task": {refs: map[string][]string{
			"role": {"aws_iam_role.task.name", "aws_iam_role.task"},
		}},
		"aws_iam_role_policy_attachment.ddb": {refs: map[string][]string{
			"role": {"aws_iam_role.task.name", "aws_iam_role.task"},
		}},
	}}
	from := &Element{Kind: "container_service", Evidence: Evidence{Addresses: []string{"aws_ecs_service.app"}}}
	flows := tableFlowsForRole(from, "", []string{"aws_iam_role.task"}, resources, nil, idx, []*Element{el}, nil)
	if len(flows) != 1 || flows[0].AuthzScope != "account" {
		t.Fatalf("flows=%#v", flows)
	}
	if flows[0].Causes["authz_scope"] != "aws_iam_role_policy_attachment.ddb" {
		t.Fatalf("cause=%q", flows[0].Causes["authz_scope"])
	}
}

func TestTablesFromDocsKnownWideReadOnly(t *testing.T) {
	table := planResource{address: "aws_dynamodb_table.sessions", typ: "aws_dynamodb_table", values: map[string]any{
		"name": "sessions", "arn": "arn:aws:dynamodb:us-east-1:1:table/sessions",
	}}
	el := awsDynamoDBTableElement(table, false)
	policy := `{"Statement":[{"Effect":"Allow","Action":["dynamodb:GetItem"],"Resource":["arn:aws:dynamodb:us-east-1:1:table/sessions"]}]}`
	resources := []planResource{
		table,
		{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{"name": "task"}},
		{address: "aws_iam_role_policy.task", typ: "aws_iam_role_policy", values: map[string]any{"policy": policy}},
		{address: "aws_iam_role_policy_attachment.ro", typ: "aws_iam_role_policy_attachment", values: map[string]any{
			"policy_arn": "arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess",
		}},
	}
	idx := configIndex{resources: map[string]exprSet{
		"aws_iam_role_policy.task": {refs: map[string][]string{
			"role": {"aws_iam_role.task.name", "aws_iam_role.task"},
		}},
		"aws_iam_role_policy_attachment.ro": {refs: map[string][]string{
			"role": {"aws_iam_role.task.name", "aws_iam_role.task"},
		}},
	}}
	from := &Element{Kind: "serverless_function", Evidence: Evidence{Addresses: []string{"aws_lambda_function.fn"}}}
	flows := tableFlowsForRole(from, "", []string{"aws_iam_role.task"}, resources, nil, idx, []*Element{el}, nil)
	if len(flows) != 1 || flows[0].AuthzScope != "account" {
		t.Fatalf("flows=%#v", flows)
	}
}

func TestDynamoDBLambdaCallerFlow(t *testing.T) {
	plan := dynamoLambdaPlan(t)
	doc, warnings, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "",
		Source{Repo: "t/ddb-lambda", Commit: "abc", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "no mapping") {
			t.Fatalf("warning: %s", w)
		}
	}
	var fnFlow *Flow
	byID := map[string]Element{}
	for _, el := range doc.Elements {
		byID[el.ID] = el
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		from, to := byID[f.From], byID[f.To]
		if from.Kind == "serverless_function" && to.Kind == "nosql_db" {
			fnFlow = f
		}
	}
	if fnFlow == nil {
		t.Fatalf("want lambda→table flow, got %d flows", len(doc.Flows))
	}
	if fnFlow.AuthzScope != "resource" {
		t.Fatalf("scope=%q", fnFlow.AuthzScope)
	}
}

func TestDynamoDBVMCallerFlow(t *testing.T) {
	plan := dynamoVMPlan(t)
	doc, _, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "",
		Source{Repo: "t/ddb-vm", Commit: "abc", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var vmFlow *Flow
	byID := map[string]Element{}
	for _, el := range doc.Elements {
		byID[el.ID] = el
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		from, to := byID[f.From], byID[f.To]
		if from.Kind == "virtual_machine" && from.Evidence.Addresses[0] == "aws_instance.app" && to.Kind == "nosql_db" {
			vmFlow = f
		}
	}
	if vmFlow == nil {
		t.Fatal("want instance→table IAM flow")
	}
}

func TestDynamoDBTableDeletionProtectionAttrs(t *testing.T) {
	el := awsDynamoDBTableElement(planResource{
		address: "aws_dynamodb_table.a", typ: "aws_dynamodb_table",
		values: map[string]any{"name": "a", "deletion_protection_enabled": true},
	}, false)
	if el.Attributes["provider_deletion_protection"] != true {
		t.Fatalf("got %#v", el.Attributes)
	}
	el = awsDynamoDBTableElement(planResource{
		address: "aws_dynamodb_table.a", typ: "aws_dynamodb_table",
		values: map[string]any{"name": "a", "deletion_protection_enabled": false},
	}, false)
	if el.Attributes["provider_deletion_protection"] != false {
		t.Fatalf("got %#v", el.Attributes)
	}
	el = awsDynamoDBTableElement(planResource{
		address: "aws_dynamodb_table.a", typ: "aws_dynamodb_table",
		values:       map[string]any{"name": "a"},
		afterUnknown: map[string]any{"deletion_protection_enabled": true},
	}, false)
	if _, ok := el.Attributes["provider_deletion_protection"]; ok {
		t.Fatalf("want omitted when unknown, got %#v", el.Attributes)
	}
}

func TestDeferredDynamoDBPolicyDocumentPlan034(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "deferred-dynamodb-policy-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, warnings, err := Parse(raw, []byte("schema_version: fray-config/v1\n"), "",
		Source{Repo: "t/deferred-ddb", Commit: "plan034", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "no mapping") && strings.Contains(strings.ToLower(w), "dynamodb") {
			t.Fatalf("warning: %s", w)
		}
	}
	byID := map[string]Element{}
	addrByID := map[string]string{}
	for _, el := range doc.Elements {
		byID[el.ID] = el
		if len(el.Evidence.Addresses) == 1 {
			addrByID[el.ID] = el.Evidence.Addresses[0]
		}
	}
	type flowKey struct{ from, to string }
	got := map[flowKey]*Flow{}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		from := addrByID[f.From]
		to := addrByID[f.To]
		if byID[f.To].Kind != "nosql_db" {
			continue
		}
		got[flowKey{from, to}] = f
	}
	appSessions := flowKey{"aws_ecs_service.app", "aws_dynamodb_table.sessions"}
	if f := got[appSessions]; f == nil || f.AuthzScope != "resource" {
		t.Fatalf("app→sessions: flow=%v scope=%q", got[appSessions], "")
	}
	if got[appSessions].Causes["authz_scope"] != "data.aws_iam_policy_document.app_dynamodb_sessions" {
		t.Fatalf("app cause=%q", got[appSessions].Causes["authz_scope"])
	}
	lambdaAudit := flowKey{"aws_lambda_function.audit_writer", "aws_dynamodb_table.audit"}
	if f := got[lambdaAudit]; f == nil || f.AuthzScope != "account" {
		t.Fatalf("audit_writer→audit: flow=%v scope=%q", got[lambdaAudit], "")
	}
	if got[flowKey{"aws_lambda_function.audit_writer", "aws_dynamodb_table.sessions"}] != nil {
		t.Fatal("unexpected audit_writer→sessions flow")
	}
}

func TestDynamoDBCreateTableRealPlanShape(t *testing.T) {
	// Table being created: name known, arn/id unknown; IAM policy comes from a
	// data.aws_iam_policy_document whose config references aws_dynamodb_table.sessions.arn.
	literal := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:PutItem"],"Resource":["arn:aws:dynamodb:us-east-1:123456789012:table/sessions"]}]}`
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			map[string]any{
				"address": "aws_dynamodb_table.sessions", "mode": "managed", "type": "aws_dynamodb_table", "name": "sessions",
				"change": map[string]any{
					"actions":       []any{"create"},
					"after":         map[string]any{"name": "sessions", "hash_key": "id"},
					"after_unknown": map[string]any{"arn": true, "id": true},
				},
			},
			map[string]any{
				"address": "aws_lambda_function.worker", "mode": "managed", "type": "aws_lambda_function", "name": "worker",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"function_name": "worker"}},
			},
			map[string]any{
				"address": "aws_iam_role.worker", "mode": "managed", "type": "aws_iam_role", "name": "worker",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "worker"}},
			},
			map[string]any{
				"address": "aws_iam_role_policy.ddb", "mode": "managed", "type": "aws_iam_role_policy", "name": "ddb",
				"change": map[string]any{
					"actions":       []any{"create"},
					"after":         map[string]any{"name": "ddb"},
					"after_unknown": map[string]any{"policy": true, "role": true},
				},
			},
		},
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": []any{
					map[string]any{"address": "aws_iam_role_policy.ddb", "type": "aws_iam_role_policy", "name": "ddb", "expressions": map[string]any{
						"role": map[string]any{"references": []any{"aws_iam_role.worker.id", "aws_iam_role.worker"}},
						"policy": map[string]any{"references": []any{
							"data.aws_iam_policy_document.ddb.json",
							"data.aws_iam_policy_document.ddb",
						}},
					}},
					map[string]any{"address": "data.aws_iam_policy_document.ddb", "mode": "data", "type": "aws_iam_policy_document", "name": "ddb", "expressions": map[string]any{
						"statement": map[string]any{"references": []any{"aws_dynamodb_table.sessions.arn", "aws_dynamodb_table.sessions"}},
					}},
					map[string]any{"address": "aws_lambda_function.worker", "type": "aws_lambda_function", "name": "worker", "expressions": map[string]any{
						"role": map[string]any{"references": []any{"aws_iam_role.worker.arn", "aws_iam_role.worker"}},
					}},
				},
			},
		},
		"prior_state": map[string]any{
			"values": map[string]any{
				"root_module": map[string]any{
					"resources": []any{
						map[string]any{
							"address": "data.aws_iam_policy_document.ddb", "mode": "data", "type": "aws_iam_policy_document",
							"values": map[string]any{
								"json": literal,
								"statement": []any{map[string]any{
									"actions":   []any{"dynamodb:PutItem"},
									"effect":    "Allow",
									"resources": []any{"arn:aws:dynamodb:us-east-1:123456789012:table/sessions"},
								}},
							},
						},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	doc, warnings, err := Parse(raw, []byte("schema_version: fray-config/v1\n"), "",
		Source{Repo: "t/real", Commit: "abc", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "no mapping") && strings.Contains(w, "dynamodb") {
			t.Fatalf("warning: %s", w)
		}
	}
	var flow *Flow
	byID := map[string]Element{}
	for _, el := range doc.Elements {
		byID[el.ID] = el
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		to := byID[f.To]
		if to.Kind == "nosql_db" {
			flow = f
		}
	}
	if flow == nil {
		t.Fatalf("want table flow, elements=%d flows=%d warnings=%v", len(doc.Elements), len(doc.Flows), warnings)
	}
	if flow.AuthzScope != "resource" {
		t.Fatalf("scope=%q", flow.AuthzScope)
	}
	if flow.Causes["authz_scope"] != "data.aws_iam_policy_document.ddb" {
		t.Fatalf("cause=%q", flow.Causes["authz_scope"])
	}
}

func TestDynamoDBIAMGolden(t *testing.T) {
	plan := dynamoECSPlan(t)
	doc, warnings, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "",
		Source{Repo: "t/ddb-golden", Commit: "ddb0001", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.HasPrefix(w, "IAM flows omitted") || strings.Contains(w, "no mapping") {
			t.Fatalf("unexpected: %s", w)
		}
	}
	got, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "testdata", "golden", "dynamodb-iam.dfd.json")
	if os.Getenv("UPDATE") != "" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		_ = os.WriteFile("/tmp/dynamodb-iam.dfd.json", got, 0o644)
		t.Fatalf("missing golden (wrote /tmp): %v", err)
	}
	if !bytes.Equal(got, want) {
		_ = os.WriteFile("/tmp/dynamodb-iam.dfd.json", got, 0o644)
		t.Fatalf("golden drift; wrote /tmp/dynamodb-iam.dfd.json")
	}
}

func dynamoLambdaPlan(t *testing.T) string {
	t.Helper()
	policy := `{"Statement":[{"Effect":"Allow","Action":["dynamodb:GetItem"],"Resource":["arn:aws:dynamodb:us-east-1:123:table/events"]}]}`
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			map[string]any{
				"address": "aws_lambda_function.fn", "mode": "managed", "type": "aws_lambda_function", "name": "fn",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"function_name": "fn"}},
			},
			map[string]any{
				"address": "aws_iam_role.fn", "mode": "managed", "type": "aws_iam_role", "name": "fn",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "fn"}},
			},
			map[string]any{
				"address": "aws_iam_role_policy.fn", "mode": "managed", "type": "aws_iam_role_policy", "name": "fn",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"policy": policy}},
			},
			map[string]any{
				"address": "aws_dynamodb_table.events", "mode": "managed", "type": "aws_dynamodb_table", "name": "events",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"name": "events", "arn": "arn:aws:dynamodb:us-east-1:123:table/events",
				}},
			},
		},
		"configuration": map[string]any{"root_module": map[string]any{"resources": []any{
			map[string]any{"address": "aws_lambda_function.fn", "type": "aws_lambda_function", "name": "fn", "expressions": map[string]any{
				"role": map[string]any{"references": []any{"aws_iam_role.fn.arn", "aws_iam_role.fn"}},
			}},
			map[string]any{"address": "aws_iam_role_policy.fn", "type": "aws_iam_role_policy", "name": "fn", "expressions": map[string]any{
				"role": map[string]any{"references": []any{"aws_iam_role.fn.id", "aws_iam_role.fn"}},
			}},
		}}},
	}
	raw, _ := json.Marshal(plan)
	return string(raw)
}

func dynamoVMPlan(t *testing.T) string {
	t.Helper()
	policy := `{"Statement":[{"Effect":"Allow","Action":["dynamodb:Query"],"Resource":["arn:aws:dynamodb:us-east-1:123:table/cache"]}]}`
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			map[string]any{
				"address": "aws_instance.app", "mode": "managed", "type": "aws_instance", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"iam_instance_profile": "app"}},
			},
			map[string]any{
				"address": "aws_iam_instance_profile.app", "mode": "managed", "type": "aws_iam_instance_profile", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
			},
			map[string]any{
				"address": "aws_iam_role.app", "mode": "managed", "type": "aws_iam_role", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
			},
			map[string]any{
				"address": "aws_iam_role_policy.app", "mode": "managed", "type": "aws_iam_role_policy", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"policy": policy}},
			},
			map[string]any{
				"address": "aws_dynamodb_table.cache", "mode": "managed", "type": "aws_dynamodb_table", "name": "cache",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"name": "cache", "arn": "arn:aws:dynamodb:us-east-1:123:table/cache",
				}},
			},
		},
		"configuration": map[string]any{"root_module": map[string]any{"resources": []any{
			map[string]any{"address": "aws_iam_instance_profile.app", "type": "aws_iam_instance_profile", "name": "app", "expressions": map[string]any{
				"role": map[string]any{"references": []any{"aws_iam_role.app.arn", "aws_iam_role.app"}},
			}},
			map[string]any{"address": "aws_iam_role_policy.app", "type": "aws_iam_role_policy", "name": "app", "expressions": map[string]any{
				"role": map[string]any{"references": []any{"aws_iam_role.app.id", "aws_iam_role.app"}},
			}},
		}}},
	}
	raw, _ := json.Marshal(plan)
	return string(raw)
}

func dynamoECSPlan(t *testing.T) string {
	t.Helper()
	policy := `{"Statement":[{"Effect":"Allow","Action":["dynamodb:UpdateItem"],"Resource":["arn:aws:dynamodb:us-east-1:999:table/sessions"]}]}`
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			map[string]any{
				"address": "aws_ecs_service.app", "mode": "managed", "type": "aws_ecs_service", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
			},
			map[string]any{
				"address": "aws_ecs_task_definition.app", "mode": "managed", "type": "aws_ecs_task_definition", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"family": "app", "container_definitions": "[]",
				}},
			},
			map[string]any{
				"address": "aws_iam_role.task", "mode": "managed", "type": "aws_iam_role", "name": "task",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "task"}},
			},
			map[string]any{
				"address": "aws_iam_role_policy.task", "mode": "managed", "type": "aws_iam_role_policy", "name": "task",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"policy": policy}},
			},
			map[string]any{
				"address": "aws_dynamodb_table.sessions", "mode": "managed", "type": "aws_dynamodb_table", "name": "sessions",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"name": "sessions", "arn": "arn:aws:dynamodb:us-east-1:999:table/sessions",
					"deletion_protection_enabled": true,
				}},
			},
		},
		"configuration": map[string]any{"root_module": map[string]any{"resources": []any{
			map[string]any{"address": "aws_ecs_service.app", "type": "aws_ecs_service", "name": "app", "expressions": map[string]any{
				"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.app.arn", "aws_ecs_task_definition.app"}},
			}},
			map[string]any{"address": "aws_ecs_task_definition.app", "type": "aws_ecs_task_definition", "name": "app", "expressions": map[string]any{
				"task_role_arn": map[string]any{"references": []any{"aws_iam_role.task.arn", "aws_iam_role.task"}},
			}},
			map[string]any{"address": "aws_iam_role_policy.task", "type": "aws_iam_role_policy", "name": "task", "expressions": map[string]any{
				"role": map[string]any{"references": []any{"aws_iam_role.task.id", "aws_iam_role.task"}},
			}},
		}}},
	}
	raw, _ := json.Marshal(plan)
	return string(raw)
}

func TestDynamoDBUnmodelledCompanionTypesWarn(t *testing.T) {
	cases := []struct {
		typ     string
		address string
	}{
		{"aws_dynamodb_resource_policy", "aws_dynamodb_resource_policy.sessions"},
		{"aws_dynamodb_kinesis_streaming_destination", "aws_dynamodb_kinesis_streaming_destination.sessions"},
	}
	for _, tc := range cases {
		t.Run(tc.typ, func(t *testing.T) {
			plan := map[string]any{
				"format_version": "1.2",
				"resource_changes": []any{
					map[string]any{
						"address": tc.address, "mode": "managed", "type": tc.typ, "name": "sessions",
						"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{}},
					},
				},
			}
			raw, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			_, warnings, err := Parse(raw, []byte("schema_version: fray-config/v1\n"), "",
				Source{Repo: "t/ddb-warn", Commit: "abc", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			want := "no mapping for " + tc.address + "; skipped"
			var found bool
			for _, w := range warnings {
				if w == want {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("want warning %q, got %v", want, warnings)
			}
		})
	}
}
