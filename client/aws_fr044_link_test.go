package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFr044QueuePolicyLinkRefs(t *testing.T) {
	plan, err := os.ReadFile(filepath.Join("testdata", "coverage-fr044-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	resources, err := loadResources(plan)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := indexConfig(plan)
	if err != nil {
		t.Fatal(err)
	}
	modDir := filepath.Join("testdata", "fr044_hcl")
	idx.iamHCL, err = readRootIAMPolicyLiterals(modDir)
	if err != nil {
		t.Fatal(err)
	}
	refs := idx.attrRefs("aws_sqs_queue_policy.sqs_rp_world", "queue_url")
	if len(refs) == 0 {
		t.Fatal("no queue_url refs")
	}
	q, ok := resolveSingleByRef(refs, resources, nil, idx, sqsQueueRefOpts)
	if !ok {
		t.Fatalf("resolveSingleByRef failed refs=%v", refs)
	}
	if q.address != "aws_sqs_queue.sqs_rp_world" {
		t.Fatalf("got queue %s", q.address)
	}
	var rp planResource
	for _, r := range resources {
		if r.address == "aws_sqs_queue_policy.sqs_rp_world" {
			rp = r
			break
		}
	}
	docs, unk := resolvePolicyContent(rp, "policy", "", nil, resources, idx)
	if unk || len(docs) == 0 {
		t.Fatalf("policy unknown=%v docs=%d", unk, len(docs))
	}
	ctx := newAWSResourcePolicyContext(resources, nil, idx, plan)
	class := classifyResourcePolicyDocs(docs, ctx)
	if class.world != triTrue {
		t.Fatalf("world=%v cross=%v cause=%q", class.world, class.cross, class.cause)
	}
}

func TestFr044ParseSetsWorldOnQK(t *testing.T) {
	modDir := filepath.Join("testdata", "fr044_hcl")
	doc, warns := parseCoveragePlanModule(t, "coverage-fr044-plan.json", modDir)
	for _, w := range warns {
		t.Log("warn:", w)
	}
	el, ok := elementByAddress(doc, "aws_sqs_queue.sqs_rp_world")
	if !ok {
		t.Fatal("missing queue element")
	}
	w, okW := el.Attributes["resource_policy_world_principal"].(bool)
	if !okW || !w {
		t.Fatalf("attrs=%v causes=%v", el.Attributes, el.Causes)
	}
}
