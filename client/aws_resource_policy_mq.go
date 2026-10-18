package client

import "strings"

var (
	sqsQueueRefOpts = resolveSingleByRefOpts{
		ResourceType:     "aws_sqs_queue",
		SkipVarRef:       true,
		BareModule:       bareModuleSkipWithVar,
		EmptyNameManaged: emptyNameContinue,
	}
	snsTopicRefOpts = resolveSingleByRefOpts{
		ResourceType:     "aws_sns_topic",
		SkipVarRef:       true,
		BareModule:       bareModuleSkipWithVar,
		EmptyNameManaged: emptyNameContinue,
	}
)

func applySQSQueueResourcePolicies(resources, data []planResource, idx configIndex, plan []byte, byAddr map[string]*Element, warnings *[]string) {
	ctx := newAWSResourcePolicyContext(resources, data, idx, plan)
	linked := map[string][]resourcePolicyClass{}
	unlinkedPolicy := false
	for _, rp := range resources {
		if rp.typ != "aws_sqs_queue_policy" {
			continue
		}
		mod, _, _, _ := splitResourceAddress(rp.address)
		el, linkOK := queueElementForQueuePolicy(rp, mod, resources, data, idx, byAddr)
		if !linkOK || el == nil {
			unlinkedPolicy = true
			*warnings = append(*warnings, "unlinked resource policy "+rp.address+"; queue attributes omitted where policy presence is unknown")
			continue
		}
		key := el.canonicalKey()
		docs, unknown := resolvePolicyContent(rp, "policy", mod, data, resources, idx)
		cause := rp.address
		if len(docs) == 1 && docs[0].address != "" && docs[0].address != rp.address {
			cause = docs[0].address
		}
		var class resourcePolicyClass
		if unknown || len(docs) == 0 {
			class = resourcePolicyClass{world: triOmit, cross: triOmit, cause: cause}
			if unknown {
				*warnings = append(*warnings, "unreadable resource policy on "+rp.address+"; attributes omitted")
			}
		} else {
			class = classifyResourcePolicyDocs(docs, ctx)
			class.cause = cause
		}
		linked[key] = append(linked[key], class)
	}
	applyMessageQueueResourcePolicyAttrs(byAddr, linked, unlinkedPolicy, "aws_sqs_queue.")
}

func applySNSQueueResourcePolicies(resources, data []planResource, idx configIndex, plan []byte, byAddr map[string]*Element, warnings *[]string) {
	ctx := newAWSResourcePolicyContext(resources, data, idx, plan)
	linked := map[string][]resourcePolicyClass{}
	unlinkedPolicy := false
	for _, rp := range resources {
		if rp.typ != "aws_sns_topic_policy" {
			continue
		}
		mod, _, _, _ := splitResourceAddress(rp.address)
		el, linkOK := topicElementForTopicPolicy(rp, mod, resources, data, idx, byAddr)
		if !linkOK || el == nil {
			unlinkedPolicy = true
			*warnings = append(*warnings, "unlinked resource policy "+rp.address+"; topic attributes omitted where policy presence is unknown")
			continue
		}
		key := el.canonicalKey()
		docs, unknown := resolvePolicyContent(rp, "policy", mod, data, resources, idx)
		cause := rp.address
		if len(docs) == 1 && docs[0].address != "" && docs[0].address != rp.address {
			cause = docs[0].address
		}
		var class resourcePolicyClass
		if unknown || len(docs) == 0 {
			class = resourcePolicyClass{world: triOmit, cross: triOmit, cause: cause}
			if unknown {
				*warnings = append(*warnings, "unreadable resource policy on "+rp.address+"; attributes omitted")
			}
		} else {
			class = classifyResourcePolicyDocs(docs, ctx)
			class.cause = cause
		}
		linked[key] = append(linked[key], class)
	}
	applyMessageQueueResourcePolicyAttrs(byAddr, linked, unlinkedPolicy, "aws_sns_topic.")
}

func applyMessageQueueResourcePolicyAttrs(byAddr map[string]*Element, linked map[string][]resourcePolicyClass, unlinkedPolicy bool, addressPrefix string) {
	for _, el := range byAddr {
		if el == nil || el.Kind != "message_queue" {
			continue
		}
		if addressPrefix != "" {
			if len(el.Evidence.Addresses) != 1 || !strings.HasPrefix(el.Evidence.Addresses[0], addressPrefix) {
				continue
			}
		}
		key := el.canonicalKey()
		policies := linked[key]
		if len(policies) == 0 {
			if unlinkedPolicy {
				continue
			}
			mqCause := ""
			if len(el.Evidence.Addresses) > 0 {
				mqCause = el.Evidence.Addresses[0]
			}
			setResourcePolicyAttrs(el, false, false, mqCause)
			continue
		}
		world, cross, cause := mergeResourcePolicyClasses(policies)
		setResourcePolicyAttrsFromTri(el, world, cross, cause)
	}
}

func queueElementForQueuePolicy(rp planResource, module string, resources, data []planResource, idx configIndex, byAddr map[string]*Element) (*Element, bool) {
	if url, ok := rp.values["queue_url"].(string); ok && strings.TrimSpace(url) != "" && !attrAfterUnknown(rp, "queue_url") {
		for addr, el := range byAddr {
			if el == nil || el.Kind != "message_queue" {
				continue
			}
			if q, ok := planResourceByAddress(addr, resources); ok && q.typ == "aws_sqs_queue" {
				if id, ok := q.values["id"].(string); ok && id == url {
					return el, true
				}
				if urlVal, ok := q.values["url"].(string); ok && urlVal == url {
					return el, true
				}
			}
		}
	}
	refs := idx.attrRefs(rp.address, "queue_url")
	queue, ok := resolveSingleByRef(refs, resources, data, idx, sqsQueueRefOpts)
	if !ok {
		return nil, false
	}
	el := byAddr[queue.address]
	return el, el != nil
}

func topicElementForTopicPolicy(rp planResource, module string, resources, data []planResource, idx configIndex, byAddr map[string]*Element) (*Element, bool) {
	if arn, ok := rp.values["arn"].(string); ok && strings.TrimSpace(arn) != "" && !attrAfterUnknown(rp, "arn") {
		for addr, el := range byAddr {
			if el == nil || el.Kind != "message_queue" {
				continue
			}
			if topic, ok := planResourceByAddress(addr, resources); ok && topic.typ == "aws_sns_topic" {
				if topicARN, ok := topic.values["arn"].(string); ok && topicARN == arn {
					return el, true
				}
			}
		}
	}
	refs := idx.attrRefs(rp.address, "arn")
	topic, ok := resolveSingleByRef(refs, resources, data, idx, snsTopicRefOpts)
	if !ok {
		return nil, false
	}
	el := byAddr[topic.address]
	return el, el != nil
}
