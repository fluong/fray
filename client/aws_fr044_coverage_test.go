package client

import (
	"path/filepath"
	"testing"
)

func TestCoverageFR044FR045MessageQueues(t *testing.T) {
	modDir := filepath.Join("testdata", "fr044_hcl")
	doc, _ := parseCoveragePlanModule(t, "coverage-fr044-plan.json", modDir)

	falseVal := false
	trueVal := true

	assertRP := func(t *testing.T, addr string, world *bool, cross *bool, cause string) {
		t.Helper()
		el, ok := elementByAddress(doc, addr)
		if !ok {
			t.Fatalf("missing element %s", addr)
		}
		gotW, okW := el.Attributes["resource_policy_world_principal"].(bool)
		if world == nil {
			if okW {
				t.Fatalf("%s: world attr set=%v want omitted", addr, gotW)
			}
		} else if !okW || gotW != *world {
			t.Fatalf("%s: world=%v ok=%v want %v", addr, gotW, okW, *world)
		}
		gotC, okC := el.Attributes["resource_policy_cross_account"].(bool)
		if cross == nil {
			if okC {
				t.Fatalf("%s: cross attr set=%v want omitted", addr, gotC)
			}
		} else if !okC || gotC != *cross {
			t.Fatalf("%s: cross=%v ok=%v want %v", addr, gotC, okC, *cross)
		}
		if cause != "" {
			wCause := el.Causes["resource_policy_world_principal"]
			cCause := el.Causes["resource_policy_cross_account"]
			if wCause != cause && cCause != cause {
				t.Fatalf("%s: causes world=%q cross=%q want %q on set axis", addr, wCause, cCause, cause)
			}
		}
	}

	t.Run("Q_K_world", func(t *testing.T) {
		assertRP(t, "aws_sqs_queue.sqs_rp_world", &trueVal, &trueVal, "aws_sqs_queue_policy.sqs_rp_world")
	})
	t.Run("Q_L_foreign", func(t *testing.T) {
		assertRP(t, "aws_sqs_queue.sqs_rp_foreign", &falseVal, nil, "aws_sqs_queue_policy.sqs_rp_foreign")
	})
	t.Run("Q_L2_same", func(t *testing.T) {
		assertRP(t, "aws_sqs_queue.sqs_rp_same", &falseVal, &falseVal, "aws_sqs_queue_policy.sqs_rp_same")
	})
	t.Run("Q_M_org", func(t *testing.T) {
		assertRP(t, "aws_sqs_queue.sqs_rp_org", &falseVal, &falseVal, "aws_sqs_queue_policy.sqs_rp_org")
	})
	t.Run("Q_N_deny_cond", func(t *testing.T) {
		assertRP(t, "aws_sqs_queue.sqs_rp_deny_cond", nil, nil, "")
	})
	t.Run("Q_O_doc", func(t *testing.T) {
		assertRP(t, "aws_sqs_queue.sqs_rp_doc", &falseVal, &falseVal, "data.aws_iam_policy_document.sqs_rp_doc")
	})
	t.Run("Q_NONE", func(t *testing.T) {
		assertRP(t, "aws_sqs_queue.sqs_rp_none", &falseVal, &falseVal, "aws_sqs_queue.sqs_rp_none")
	})
	t.Run("T_K_world", func(t *testing.T) {
		assertRP(t, "aws_sns_topic.sns_rp_world", &trueVal, &trueVal, "aws_sns_topic_policy.sns_rp_world")
	})
	t.Run("T_DEFAULT", func(t *testing.T) {
		assertRP(t, "aws_sns_topic.sns_rp_default", &falseVal, &falseVal, "aws_sns_topic.sns_rp_default")
	})
	t.Run("T_OWNER", func(t *testing.T) {
		assertRP(t, "aws_sns_topic.sns_rp_owner", &falseVal, nil, "aws_sns_topic_policy.sns_rp_owner")
	})

	t.Run("F45_res_flows", func(t *testing.T) {
		none := flowLambdaToMessageQueue(doc, "aws_lambda_function.f45_res", "aws_sqs_queue.sqs_rp_none")
		if none == nil || none.AuthzScope != "resource" || none.Causes["authz_scope"] != "aws_iam_role_policy.f45_res" {
			t.Fatalf("sqs flow=%v", none)
		}
		topic := flowLambdaToMessageQueue(doc, "aws_lambda_function.f45_res", "aws_sns_topic.sns_rp_default")
		if topic == nil || topic.AuthzScope != "resource" || topic.Causes["authz_scope"] != "aws_iam_role_policy.f45_res" {
			t.Fatalf("sns flow=%v", topic)
		}
	})
	t.Run("F45_acc_all_sqs", func(t *testing.T) {
		want := []string{
			"aws_sqs_queue.sqs_rp_world",
			"aws_sqs_queue.sqs_rp_foreign",
			"aws_sqs_queue.sqs_rp_same",
			"aws_sqs_queue.sqs_rp_org",
			"aws_sqs_queue.sqs_rp_deny_cond",
			"aws_sqs_queue.sqs_rp_doc",
			"aws_sqs_queue.sqs_rp_none",
		}
		for _, q := range want {
			f := flowLambdaToMessageQueue(doc, "aws_lambda_function.f45_acc", q)
			if f == nil {
				t.Fatalf("missing flow to %s", q)
			}
			if f.AuthzScope != "account" || f.Causes["authz_scope"] != "aws_iam_role_policy.f45_acc" {
				t.Fatalf("%s: scope=%q cause=%q", q, f.AuthzScope, f.Causes["authz_scope"])
			}
		}
		if f := flowLambdaToMessageQueue(doc, "aws_lambda_function.f45_acc", "aws_sns_topic.sns_rp_default"); f != nil {
			t.Fatalf("sqs:* must not flow to sns: %v", f)
		}
	})
	t.Run("b71_one_still_resource", func(t *testing.T) {
		f := flowLambdaToBucket(doc, "aws_lambda_function.b71_reader", "aws_s3_bucket.b71_one")
		if f == nil || f.AuthzScope != "resource" {
			t.Fatalf("b71_one flow=%v", f)
		}
	})
}

func flowLambdaToMessageQueue(doc DFD, lambdaAddr, mqAddr string) *Flow {
	byID := map[string]Element{}
	for _, el := range doc.Elements {
		byID[el.ID] = el
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		from, ok1 := byID[f.From]
		to, ok2 := byID[f.To]
		if !ok1 || !ok2 {
			continue
		}
		if len(from.Evidence.Addresses) == 0 || from.Evidence.Addresses[0] != lambdaAddr {
			continue
		}
		if len(to.Evidence.Addresses) == 0 || to.Evidence.Addresses[0] != mqAddr {
			continue
		}
		return f
	}
	return nil
}
