package client

import (
	"encoding/json"
	"strings"
)

var (
	s3BucketRefOpts = resolveSingleByRefOpts{
		ResourceType:     "aws_s3_bucket",
		SkipVarRef:       true,
		BareModule:       bareModuleSkipWithVar,
		EmptyNameManaged: emptyNameContinue,
	}
	awsSecretRefOpts = resolveSingleByRefOpts{
		ResourceType:     "aws_secretsmanager_secret",
		SkipVarRef:       true,
		BareModule:       bareModuleSkipWithVar,
		EmptyNameManaged: emptyNameContinue,
	}
)

func applyS3BucketResourcePolicies(resources, data []planResource, idx configIndex, plan []byte, byAddr map[string]*Element, warnings *[]string) {
	ctx := newAWSResourcePolicyContext(resources, data, idx, plan)
	providerKeys := awsResourceProviderConfigKeys(plan)
	linked := map[string][]resourcePolicyClass{}
	unlinkedPolicy := false
	for _, rp := range resources {
		if rp.typ != "aws_s3_bucket_policy" {
			continue
		}
		mod, _, _, _ := splitResourceAddress(rp.address)
		el, bucket, linkOK := bucketElementForBucketPolicy(rp, mod, resources, data, idx, byAddr)
		if !linkOK || el == nil {
			unlinkedPolicy = true
			*warnings = append(*warnings, "unlinked resource policy "+rp.address+"; bucket attributes omitted where policy presence is unknown")
			continue
		}
		bucketKey := el.canonicalKey()
		docs, unknown := resolvePolicyContent(rp, "policy", mod, data, resources, idx)
		cause := rp.address
		if len(docs) == 1 && docs[0].address != "" && docs[0].address != rp.address {
			cause = docs[0].address
		}
		neutral := s3BucketPolicyNeutralization(bucket, resources, idx, providerKeys)
		var class resourcePolicyClass
		if unknown || len(docs) == 0 {
			class = resourcePolicyClass{world: triOmit, cross: triOmit, cause: cause}
			if unknown {
				*warnings = append(*warnings, "unreadable resource policy on "+rp.address+"; attributes omitted")
			}
		} else {
			opts := resourcePolicyDocOptions{}
			if neutral.blockAnyPrincipal {
				opts.neutralizeAnyPrincipalAllow = true
				opts.neutralizeCause = neutral.cause
			}
			class = classifyResourcePolicyDocsWithOptions(docs, ctx, opts)
			if class.cause == "" {
				class.cause = cause
			} else if opts.neutralizeCause != "" && class.world == triFalse && class.cross == triFalse {
				class.cause = opts.neutralizeCause
			}
		}
		linked[bucketKey] = append(linked[bucketKey], class)
	}
	for _, el := range byAddr {
		if el == nil || el.Kind != "object_storage" || el.Provider != "aws" {
			continue
		}
		key := el.canonicalKey()
		policies := linked[key]
		if len(policies) == 0 {
			if unlinkedPolicy {
				continue
			}
			bucketCause := ""
			if len(el.Evidence.Addresses) > 0 {
				bucketCause = el.Evidence.Addresses[0]
			}
			setResourcePolicyAttrs(el, false, false, bucketCause)
			continue
		}
		world, cross, cause := mergeResourcePolicyClasses(policies)
		setResourcePolicyAttrsFromTri(el, world, cross, cause)
	}
}

func applySecretsManagerResourcePolicies(resources, data []planResource, idx configIndex, plan []byte, byAddr map[string]*Element, warnings *[]string) {
	ctx := newAWSResourcePolicyContext(resources, data, idx, plan)
	linked := map[string][]resourcePolicyClass{}
	unlinkedPolicy := false
	for _, rp := range resources {
		if rp.typ != "aws_secretsmanager_secret_policy" {
			continue
		}
		mod, _, _, _ := splitResourceAddress(rp.address)
		el, linkOK := secretElementForSecretPolicy(rp, mod, resources, data, idx, byAddr)
		if !linkOK || el == nil {
			unlinkedPolicy = true
			*warnings = append(*warnings, "unlinked resource policy "+rp.address+"; secret attributes omitted where policy presence is unknown")
			continue
		}
		secretKey := el.canonicalKey()
		docs, unknown := resolvePolicyContent(rp, "policy", mod, data, resources, idx)
		cause := rp.address
		if len(docs) == 1 && docs[0].address != "" && docs[0].address != rp.address {
			cause = docs[0].address
		}
		blockPublic := secretPolicyBlockPublic(rp)
		var class resourcePolicyClass
		if unknown || len(docs) == 0 {
			class = resourcePolicyClass{world: triOmit, cross: triOmit, cause: cause}
			if unknown {
				*warnings = append(*warnings, "unreadable resource policy on "+rp.address+"; attributes omitted")
			}
		} else {
			opts := resourcePolicyDocOptions{}
			if blockPublic {
				opts.neutralizeAnyPrincipalAllow = true
				opts.neutralizeCause = rp.address
			}
			class = classifyResourcePolicyDocsWithOptions(docs, ctx, opts)
			if class.cause == "" {
				class.cause = cause
			} else if blockPublic && class.world == triFalse && class.cross == triFalse {
				if len(el.Evidence.Addresses) > 0 {
					class.cause = el.Evidence.Addresses[0]
				}
			}
		}
		linked[secretKey] = append(linked[secretKey], class)
	}
	for _, el := range byAddr {
		if el == nil || el.Kind != "secret_store" || el.Provider != "aws" {
			continue
		}
		key := el.canonicalKey()
		policies := linked[key]
		if len(policies) == 0 {
			if unlinkedPolicy {
				continue
			}
			secretCause := ""
			if len(el.Evidence.Addresses) > 0 {
				secretCause = el.Evidence.Addresses[0]
			}
			setResourcePolicyAttrs(el, false, false, secretCause)
			continue
		}
		world, cross, cause := mergeResourcePolicyClasses(policies)
		setResourcePolicyAttrsFromTri(el, world, cross, cause)
	}
}

func classifyResourcePolicyDocsWithOptions(docs []planResource, ctx awsResourcePolicyContext, opts resourcePolicyDocOptions) resourcePolicyClass {
	var parts []resourcePolicyClass
	for _, doc := range docs {
		parts = append(parts, classifyResourcePolicyDocWithOptions(doc, ctx, opts))
	}
	return mergeResourcePolicyClassesSlice(parts)
}

func bucketElementForBucketPolicy(rp planResource, module string, resources, data []planResource, idx configIndex, byAddr map[string]*Element) (*Element, planResource, bool) {
	if bucketID, ok := rp.values["bucket"].(string); ok && strings.TrimSpace(bucketID) != "" && !attrAfterUnknown(rp, "bucket") {
		for addr, el := range byAddr {
			if el == nil || el.Kind != "object_storage" {
				continue
			}
			if bucket, ok := planResourceByAddress(addr, resources); ok {
				if id, ok := bucket.values["id"].(string); ok && id == bucketID {
					return el, bucket, true
				}
			}
		}
	}
	refs := idx.attrRefs(rp.address, "bucket")
	bucket, ok := resolveSingleByRef(refs, resources, data, idx, s3BucketRefOpts)
	if !ok {
		return nil, planResource{}, false
	}
	el := byAddr[bucket.address]
	if el == nil {
		return nil, planResource{}, false
	}
	return el, bucket, true
}

func secretElementForSecretPolicy(rp planResource, module string, resources, data []planResource, idx configIndex, byAddr map[string]*Element) (*Element, bool) {
	if arn, ok := rp.values["secret_arn"].(string); ok && strings.TrimSpace(arn) != "" && !attrAfterUnknown(rp, "secret_arn") {
		for addr, el := range byAddr {
			if el == nil || el.Kind != "secret_store" {
				continue
			}
			if sec, ok := planResourceByAddress(addr, resources); ok {
				if secARN, ok := sec.values["arn"].(string); ok && secARN == arn {
					return el, true
				}
			}
		}
	}
	refs := idx.attrRefs(rp.address, "secret_arn")
	sec, ok := resolveSingleByRef(refs, resources, data, idx, awsSecretRefOpts)
	if !ok {
		return nil, false
	}
	el := byAddr[sec.address]
	return el, el != nil
}

type s3PolicyNeutralization struct {
	blockAnyPrincipal bool
	cause             string
}

func s3BucketPolicyNeutralization(bucket planResource, resources []planResource, idx configIndex, providerKeys map[string]string) s3PolicyNeutralization {
	if sib, ok := bucketPublicAccessBlockForBucket(bucket, resources, idx); ok {
		if restrictPublicBucketsKnown(sib) {
			return s3PolicyNeutralization{blockAnyPrincipal: true, cause: sib.address}
		}
	}
	pk := providerKeys[bucket.address]
	if pk == "" {
		return s3PolicyNeutralization{}
	}
	if ok, addr := accountBPARestrictsPublic(resources, providerKeys, pk); ok {
		return s3PolicyNeutralization{blockAnyPrincipal: true, cause: addr}
	}
	return s3PolicyNeutralization{}
}

func bucketPublicAccessBlockForBucket(bucket planResource, resources []planResource, idx configIndex) (planResource, bool) {
	_, _, name, ok := splitResourceAddress(bucket.address)
	if !ok {
		return planResource{}, false
	}
	mod, _, _, _ := splitResourceAddress(bucket.address)
	var hits []planResource
	for _, r := range resources {
		if r.typ != "aws_s3_bucket_public_access_block" {
			continue
		}
		if mod != "" && !sameModule(r.address, mod) {
			continue
		}
		if mod == "" {
			m, _, _, ok := splitResourceAddress(r.address)
			if ok && m != "" {
				continue
			}
		}
		for _, attr := range []string{"bucket", "bucket_id"} {
			for _, ref := range idx.attrRefs(r.address, attr) {
				if containsResource(ref, "aws_s3_bucket", name) {
					hits = append(hits, r)
				}
			}
		}
	}
	hits = uniqueResources(hits)
	if len(hits) == 1 {
		return hits[0], true
	}
	return planResource{}, false
}

func restrictPublicBucketsKnown(r planResource) bool {
	if attrUnknownMap(r.afterUnknown, "restrict_public_buckets") {
		return false
	}
	v, ok := r.values["restrict_public_buckets"].(bool)
	return ok && v
}

func accountBPARestrictsPublic(resources []planResource, providerKeys map[string]string, providerKey string) (bool, string) {
	for _, r := range resources {
		if r.typ != "aws_s3_account_public_access_block" {
			continue
		}
		if providerKeys[r.address] != providerKey {
			continue
		}
		if restrictPublicBucketsKnown(r) {
			return true, r.address
		}
	}
	return false, ""
}

func secretPolicyBlockPublic(rp planResource) bool {
	if attrUnknownMap(rp.afterUnknown, "block_public_policy") {
		return false
	}
	v, ok := rp.values["block_public_policy"].(bool)
	return ok && v
}

func awsResourceProviderConfigKeys(plan []byte) map[string]string {
	if len(plan) == 0 {
		return nil
	}
	var root struct {
		Configuration struct {
			RootModule map[string]any `json:"root_module"`
		} `json:"configuration"`
	}
	if err := json.Unmarshal(plan, &root); err != nil {
		return nil
	}
	out := map[string]string{}
	if root.Configuration.RootModule != nil {
		walkProviderConfigKeys(root.Configuration.RootModule, "", out)
	}
	return out
}

func walkProviderConfigKeys(mod map[string]any, prefix string, out map[string]string) {
	for _, raw := range asList(mod["resources"]) {
		r, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		addr, _ := r["address"].(string)
		full := addr
		if prefix != "" {
			full = prefix + "." + addr
		}
		if pk, ok := r["provider_config_key"].(string); ok && pk != "" {
			out[full] = pk
		}
	}
	calls, _ := mod["module_calls"].(map[string]any)
	for name, raw := range calls {
		call, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		full := "module." + name
		if prefix != "" {
			full = prefix + "." + full
		}
		if sub, ok := call["module"].(map[string]any); ok {
			walkProviderConfigKeys(sub, full, out)
		}
	}
}
