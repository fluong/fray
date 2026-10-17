package client

// buildAWS maps the aws-web-app shape: a load balancer, a container service,
// a relational database, object storage, and a secret store. Other AWS types
// are ignored by the caller. An empty result is not an error.
func buildAWS(plan []byte, resources []planResource, moduleDir string, lifecycle preventIndex, auditOwned bool) ([]*Element, []*Flow, []*Boundary, []string, error) {
	var lbs, services, dbs, buckets, tables, caches, secrets, restAPIs, httpAPIs, fnURLs, lambdas, instances, asgs, nodeGroups []planResource
	for _, r := range resources {
		switch r.typ {
		case "aws_lb":
			lbs = append(lbs, r)
		case "aws_ecs_service":
			services = append(services, r)
		case "aws_db_instance", "aws_rds_cluster":
			dbs = append(dbs, r)
		case "aws_s3_bucket":
			buckets = append(buckets, r)
		case "aws_dynamodb_table":
			tables = append(tables, r)
		case "aws_elasticache_replication_group", "aws_elasticache_cluster":
			caches = append(caches, r)
		case "aws_secretsmanager_secret":
			secrets = append(secrets, r)
		case "aws_api_gateway_rest_api":
			restAPIs = append(restAPIs, r)
		case "aws_apigatewayv2_api":
			httpAPIs = append(httpAPIs, r)
		case "aws_lambda_function_url":
			fnURLs = append(fnURLs, r)
		case "aws_lambda_function":
			lambdas = append(lambdas, r)
		case "aws_instance":
			instances = append(instances, r)
		case "aws_autoscaling_group":
			asgs = append(asgs, r)
		case "aws_eks_node_group":
			nodeGroups = append(nodeGroups, r)
		}
	}
	if len(lbs)+len(services)+len(dbs)+len(buckets)+len(tables)+len(caches)+len(secrets)+len(restAPIs)+len(httpAPIs)+len(fnURLs)+len(lambdas)+len(instances)+len(asgs)+len(nodeGroups) == 0 {
		return nil, nil, nil, nil, nil
	}
	idx, err := indexConfig(plan)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	idx.iamHCL, err = readRootIAMPolicyLiterals(moduleDir)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	data, err := loadDataResources(plan)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	containers, err := readRootContainers(moduleDir)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	rootTaskContainers, err := readRootTaskDefinitionContainers(moduleDir)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	var warnings []string
	var elements []*Element
	byAddr := map[string]*Element{}
	add := func(el *Element) {
		elements = append(elements, el)
		if len(el.Evidence.Addresses) == 1 {
			byAddr[el.Evidence.Addresses[0]] = el
		}
	}

	for _, r := range buckets {
		add(awsBucketElement(r, resources, idx, lifecycle.protected(r.address), auditOwned))
	}
	for _, r := range tables {
		add(awsDynamoDBTableElement(r, lifecycle.protected(r.address)))
	}
	applyDynamoDBResourcePolicies(resources, data, idx, plan, byAddr, &warnings)
	for _, el := range awsElastiCacheElements(resources, data, idx, &warnings) {
		add(el)
	}
	for _, r := range secrets {
		add(awsSecretElement(r, resources, idx, lifecycle.protected(r.address)))
	}
	for _, r := range dbs {
		add(awsDBElement(r, resources, data, idx, lifecycle.protected(r.address)))
	}
	for _, r := range lbs {
		add(awsLBElement(r, resources, data, idx))
	}
	for _, r := range services {
		add(awsServiceElement(r, resources, idx, containers, rootTaskContainers, &warnings))
	}
	for _, r := range instances {
		add(awsInstanceElement(r, resources, data, idx))
	}
	for _, r := range asgs {
		add(awsASGElement(r, resources, data, idx))
	}
	for _, r := range nodeGroups {
		add(awsEKSNodeGroupElement(r, resources, data, idx))
	}
	for _, r := range restAPIs {
		if restAPIInternetEntry(r, resources, idx) {
			add(awsAPIGatewayElement(r))
		}
	}
	for _, r := range httpAPIs {
		if httpAPIInternetEntry(r) {
			add(awsAPIGatewayElement(r))
		}
	}
	// Lambda function elements are created on demand for function URLs, API
	// integrations, and Bedrock invoke grants inside awsConnections.

	flows, bounds, extra, flowWarns := awsConnections(resources, data, idx, elements, byAddr, containers, rootTaskContainers)
	warnings = append(warnings, flowWarns...)
	elements = append(elements, extra...)
	return elements, flows, bounds, warnings, nil
}

func awsLBElement(r planResource, resources, data []planResource, idx configIndex) *Element {
	name, _ := r.values["name"].(string)
	attrs := map[string]any{}
	if public, ok := lbPublic(r, resources, data, idx); ok {
		attrs["public"] = public
	}
	return &Element{
		Name: DisplayName(r.address, name, "load_balancer"), Type: "process", Kind: "load_balancer", Provider: "aws",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
}

func awsServiceElement(r planResource, resources []planResource, idx configIndex, containers, rootTaskContainers map[string][]containerSpec, warnings *[]string) *Element {
	name, _ := r.values["name"].(string)
	attrs := map[string]any{}
	if n, ok, warn := serviceMax(r, resources, idx); warn != "" {
		*warnings = append(*warnings, warn)
	} else if ok {
		attrs["max_instances"] = n
	}
	mod, _, _, _ := splitResourceAddress(r.address)
	if task, ok := serviceTaskDefinition(r, resources, idx); ok {
		specs := resolveContainerSpecs(mod, task, containers, rootTaskContainers)
		if pinned, ok := imagePinned(specs); ok {
			attrs["image_pinned_by_digest"] = pinned
		}
	} else if len(taskDefinitionsInModule(resources, mod)) > 1 {
		*warnings = append(*warnings, "ambiguous task definition on "+r.address+"; image not read")
	}
	return &Element{
		Name: DisplayName(r.address, name, "container_service"), Type: "process", Kind: "container_service", Provider: "aws",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
}

func awsDBElement(r planResource, resources, data []planResource, idx configIndex, prevent bool) *Element {
	name, _ := r.values["identifier"].(string)
	if name == "" {
		name, _ = r.values["cluster_identifier"].(string)
	}
	if name == "" {
		name, _ = r.values["db_name"].(string)
	}
	attrs := map[string]any{}
	if v, ok := r.values["publicly_accessible"].(bool); ok {
		attrs["public"] = v
	}
	// Provider default for storage_encrypted is false; when Terraform omits the
	// argument the plan still writes false, so this is open (not unverified).
	if v, ok := r.values["storage_encrypted"].(bool); ok {
		attrs["encrypted_at_rest"] = v
	}
	// prevent_destroy wins. Otherwise record the plan bool, including false
	// (provider default when the argument is omitted).
	if prevent {
		attrs["deletion_protection"] = true
	} else if v, ok := r.values["deletion_protection"].(bool); ok {
		attrs["deletion_protection"] = v
	}
	// Provider console/API flag only (FR-038). Never from prevent_destroy.
	if !attrUnknownMap(r.afterUnknown, "deletion_protection") {
		if v, ok := r.values["deletion_protection"].(bool); ok {
			attrs["provider_deletion_protection"] = v
		}
	}
	if restricted, ok := dbNetworkRestricted(r, resources, data, idx); ok {
		attrs["network_restricted"] = restricted
	}
	if tls, ok := dbTLSEnforced(r, resources, idx); ok {
		attrs["tls_enforced"] = tls
	}
	return &Element{
		Name: DisplayName(r.address, name, "relational_db"), Type: "datastore", Kind: "relational_db", Provider: "aws",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
}

func awsBucketElement(r planResource, resources []planResource, idx configIndex, prevent, auditOwned bool) *Element {
	name, _ := r.values["bucket"].(string)
	if name == "" {
		name, _ = r.values["bucket_prefix"].(string)
	}
	attrs := map[string]any{}
	causes := map[string]string{}
	setObjectDeletion(attrs, r.values, prevent)
	if sib, ok := oneSibling(r, resources, "aws_s3_bucket_versioning", idx); ok {
		switch versioningStatus(sib.values) {
		case "Enabled":
			attrs["versioning"] = true
		case "Suspended", "Disabled":
			attrs["versioning"] = false
		}
	}
	if sib, ok := oneSibling(r, resources, "aws_s3_bucket_public_access_block", idx); ok {
		if blocked, known := publicAccessBlocked(sib.values); known {
			attrs["public_access_blocked"] = blocked
			if blocked {
				attrs["public"] = false
			}
		}
	}
	if sib, ok := oneSibling(r, resources, "aws_s3_bucket_ownership_controls", idx); ok {
		if ownership(sib.values) == "BucketOwnerEnforced" {
			attrs["acls_disabled"] = true
		} else if ownership(sib.values) != "" {
			attrs["acls_disabled"] = false
		}
	}
	if sib, ok := oneSibling(r, resources, "aws_s3_bucket_server_side_encryption_configuration", idx); ok {
		if encrypted(sib.values) {
			attrs["encrypted_at_rest"] = true
		}
	}
	if cmk, ok := customerManagedKey(r, resources, idx); ok {
		attrs["customer_managed_key"] = cmk
	}
	if locked, known := awsObjectLock(r, resources, idx); known {
		attrs["object_lock"] = locked
	} else if reason := awsObjectLockAbsentReason(r, resources, idx); reason != "" {
		causes["object_lock"] = reason
	}
	// Positive logging/trail evidence always emits true. Ownership only
	// decides missing evidence: owned → false; otherwise omit. WriteOnly /
	// read-only-false selectors stay unknown (!known) and are always omitted.
	if audit, known := bucketAudit(r, resources, idx); known {
		if ptr := auditLoggingPtr(audit, auditOwned); ptr != nil {
			attrs["audit_logging"] = *ptr
		}
	}
	el := &Element{
		Name: DisplayName(r.address, name, "object_storage"), Type: "datastore", Kind: "object_storage", Provider: "aws",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
	if len(causes) > 0 {
		el.Causes = causes
	}
	return el
}

func awsSecretElement(r planResource, resources []planResource, idx configIndex, prevent bool) *Element {
	name, _ := r.values["name"].(string)
	attrs := map[string]any{
		"audit_logging":       true,
		"rotation_configured": secretRotated(r, resources, idx),
	}
	if prevent {
		attrs["deletion_protection"] = true
	} else if n, ok := number(r.values["recovery_window_in_days"]); ok {
		attrs["deletion_protection"] = n > 0
	} else if _, present := r.values["recovery_window_in_days"]; !present {
		attrs["deletion_protection"] = true
	}
	return &Element{
		Name: DisplayName(r.address, name, "secret_store"), Type: "datastore", Kind: "secret_store", Provider: "aws",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
}

func awsConnections(resources, data []planResource, idx configIndex, elements []*Element, byAddr map[string]*Element, containers, rootTaskContainers map[string][]containerSpec) ([]*Flow, []*Boundary, []*Element, []string) {
	var warnings []string
	var flows []*Flow
	var extra []*Element
	var public *Element
	var inside []string
	seenInside := map[string]bool{}
	addInside := func(el *Element) {
		k := el.canonicalKey()
		if seenInside[k] {
			return
		}
		seenInside[k] = true
		inside = append(inside, k)
	}

	for _, lb := range resources {
		if lb.typ != "aws_lb" {
			continue
		}
		lbEl := byAddr[lb.address]
		if lbEl == nil || lbEl.Attributes["public"] != true {
			continue
		}
		if public == nil {
			// Closed class label for world exposure — not a harvested CIDR.
			// Kept as "0.0.0.0/0" so public_client identity matches prior plans.
			public = &Element{
				Name: "Public client", Type: "external_entity", Kind: "public_client",
				Provenance: "inferred",
				Evidence:   Evidence{Signals: []Signal{{Type: "network_ingress", Name: "0.0.0.0/0"}}},
			}
			extra = append(extra, public)
		}
		listener, transport, scope := publicListener(lb, resources, idx)
		flow := &Flow{
			From: public.canonicalKey(), To: lbEl.canonicalKey(),
			DataClass: "unknown", Transport: transport,
		}
		if scope != "" {
			flow.AuthzScope = scope
			flow.AuthzGrants = normalizeAuthzGrants(scope)
			if listener != "" {
				flow.Causes = map[string]string{"authz_scope": listener}
			}
		}
		flows = append(flows, flow)
		addInside(lbEl)

		for _, hit := range servicesFronted(lb, resources, elements, idx, &warnings) {
			flows = append(flows, &Flow{
				From: lbEl.canonicalKey(), To: hit.el.canonicalKey(),
				DataClass: "unknown", Transport: hit.transport,
			})
			addInside(hit.el)
		}
	}

	apiFlows, apiWarns := awsAPIEntries(resources, idx, byAddr, &public, &extra, addInside)
	flows = append(flows, apiFlows...)
	warnings = append(warnings, apiWarns...)

	for _, svc := range resources {
		if svc.typ != "aws_ecs_service" {
			continue
		}
		svcEl := byAddr[svc.address]
		if svcEl == nil {
			continue
		}
		mod, _, _, _ := splitResourceAddress(svc.address)
		task, ok := serviceTaskDefinition(svc, resources, idx)
		if !ok {
			// Unresolvable task_definition → omit this service's secret/S3 flows.
			continue
		}
		// Plan value known → plan wins. Else module-call HCL (module.*) or
		// root-resource HCL fallback when container_definitions is unknown.
		specs := resolveContainerSpecs(mod, task, containers, rootTaskContainers)
		flows = append(flows, secretFlowsFrom(svc, svcEl, mod, task.address, specs, resources, data, idx, elements, &warnings)...)
		flows = append(flows, bucketFlows(svc, svcEl, mod, task.address, resources, data, idx, elements, &warnings)...)
		flows = append(flows, tableFlows(svcEl, mod, task.address, resources, data, idx, elements, &warnings)...)
	}
	iamOmitWarned := map[string]bool{}
	flows = append(flows, dbFlows(resources, data, idx, elements, &warnings, iamOmitWarned)...)

	flows = append(flows, virtualMachineIAMFlows(resources, data, idx, elements, &warnings, iamOmitWarned)...)

	bedrockFlows, bedrockEl := bedrockConnections(resources, data, idx, elements, byAddr, &extra, &warnings, iamOmitWarned)
	flows = append(flows, bedrockFlows...)
	if bedrockEl != nil {
		extra = append(extra, bedrockEl)
	}
	flows = append(flows, dynamodbLambdaFlows(resources, data, idx, elements, byAddr, &extra, &warnings)...)
	flows = append(flows, lambdaS3Flows(resources, data, idx, elements, byAddr, &extra, &warnings)...)

	var bounds []*Boundary
	if public != nil && len(inside) > 0 {
		bounds = append(bounds, &Boundary{
			Kind:    "network",
			Inside:  inside,
			Outside: []string{public.canonicalKey()},
		})
	}
	return dedupeFlows(flows), bounds, extra, warnings
}

// resolveContainerSpecs prefers a known plan container_definitions value.
// When unknown/absent: module-call HCL for module addresses, or root-module
// aws_ecs_task_definition HCL for root tasks. Never invents from flat refs.
func resolveContainerSpecs(mod string, task planResource, containers, rootTaskContainers map[string][]containerSpec) []containerSpec {
	specs := containers[mod]
	if planned, ok := containersFromPlan(task); ok {
		return planned
	}
	taskMod, _, name, ok := splitResourceAddress(task.address)
	if ok && taskMod == "" {
		if hcl, ok := rootTaskContainers[name]; ok {
			return hcl
		}
	}
	return specs
}

func secretFlowsFrom(svc planResource, svcEl *Element, module, taskAddr string, specs []containerSpec, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string) []*Flow {
	seen := map[string]bool{}
	var flows []*Flow
	roleRefs := idx.attrRefs(taskAddr, "execution_role_arn")
	docs, unknownDocs, iamWarns := roleDocuments(module, roleRefs, resources, data, idx)
	*warnings = append(*warnings, iamWarns...)
	wideCause, wideSecrets := roleKnownWideGrant(module, roleRefs, resources, idx, iamServiceSecretsManager)
	taskMod, _, _, _ := splitResourceAddress(taskAddr)
	for _, spec := range specs {
		for _, ref := range spec.secrets {
			hits, ambiguous := secretElementsFromValueFrom(ref, taskMod, resources, elements)
			if ambiguous || len(hits) != 1 {
				*warnings = append(*warnings, "ambiguous secret for "+ref+" on "+svc.address)
				continue
			}
			sec := hits[0]
			if seen[sec.canonicalKey()] {
				continue
			}
			seen[sec.canonicalKey()] = true
			flow := &Flow{
				From: sec.canonicalKey(), To: svcEl.canonicalKey(),
				DataClass: "credentials", Transport: "local", SecretDelivery: "env",
				Causes: map[string]string{"secret_delivery": svc.address},
			}
			var scope, cause string
			var grants []string
			if !unknownDocs || wideSecrets {
				scope, grants, cause = awsSecretScope(sec, docs, idx.callRefs(module), resources, elements)
				if wideSecrets {
					scope, grants, cause = widenScopeWithKnownWide(scope, cause, wideCause)
				}
			}
			if scope != "" {
				flow.AuthzScope = scope
				flow.AuthzGrants = grants
				if cause != "" {
					flow.Causes["authz_scope"] = cause
				}
			} else if unknownDocs {
				if role := omittedScopeRole(module, roleRefs); role != "" {
					flow.Causes["authz_scope_omitted_for"] = role
				}
			}
			flows = append(flows, flow)
		}
	}
	return flows
}

func bucketFlows(svc planResource, svcEl *Element, module, taskAddr string, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string) []*Flow {
	if taskAddr == "" {
		return nil
	}
	return bucketFlowsForRole(svcEl, module, idx.attrRefs(taskAddr, "task_role_arn"), resources, data, idx, elements, warnings)
}

func dbFlows(resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string, iamOmitWarned map[string]bool) []*Flow {
	var flows []*Flow
	for _, sg := range resources {
		if sg.typ != "aws_security_group" {
			continue
		}
		peers := peerSecurityGroups(sg, resources, idx)
		if len(peers) == 0 {
			continue
		}
		dest := dbDestinations(sg, resources, data, elements, idx)
		if len(dest) == 0 {
			continue
		}
		// Several DBs behind one SG (module path may list every DB in the
		// module) cannot be told apart — keep the pre-plain-ALB drop.
		if len(dest) != 1 {
			*warnings = append(*warnings, "ambiguous database path through "+sg.address)
			continue
		}
		for _, src := range dbSources(sg, peers, resources, data, elements, idx, warnings) {
			flows = append(flows, dbNetworkFlowWithAuthz(src, dest[0], resources, data, idx, elements, warnings, iamOmitWarned))
		}
	}
	return flows
}

func dbNetworkFlowWithAuthz(src, dest *Element, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string, iamOmitWarned map[string]bool) *Flow {
	flow := &Flow{
		From: src.canonicalKey(), To: dest.canonicalKey(),
		DataClass: "unknown", Transport: "unknown",
	}
	scope, grants, cause, omittedRole := dbAuthzForFlow(src, dest, resources, data, idx, elements, warnings, iamOmitWarned)
	if scope != "" {
		flow.AuthzScope = scope
		flow.AuthzGrants = grants
		if cause != "" {
			flow.Causes = map[string]string{"authz_scope": cause}
		}
	} else if omittedRole != "" {
		flow.Causes = map[string]string{"authz_scope_omitted_for": omittedRole}
	}
	attachDBControlPlane(flow, src, dest, resources, data, idx, elements, warnings)
	return flow
}

// dbAuthzForFlow attaches IAM DB-access scope from the source compute role.
// SG topology is unchanged; password-only paths (no matching DB actions) omit
// authz_scope. Unknown identity-policy sources omit scope (same as secrets).
// EKS node groups do not get DB authz in R1.
func dbAuthzForFlow(src, dest *Element, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string, iamOmitWarned map[string]bool) (scope string, grants []string, cause, omittedRole string) {
	r, ok := planResourceByElement(src, resources)
	if !ok {
		return "", nil, "", ""
	}
	if r.typ == "aws_eks_node_group" {
		return "", nil, "", ""
	}
	mod, roleRefs, omit := iamRoleRefsForCompute(src, resources, data, idx)
	if omit != "" {
		warnIAMFlowsOmitted(warnings, r.address, omit, iamOmitWarned)
		return "", nil, "", ""
	}
	if len(roleRefs) == 0 {
		return "", nil, "", ""
	}
	docs, unknownDocs, iamWarns := roleDocuments(mod, roleRefs, resources, data, idx)
	if warnings != nil {
		*warnings = append(*warnings, iamWarns...)
	}
	wideCause, wideDB := roleKnownWideGrant(mod, roleRefs, resources, idx, iamServiceRDS)
	if !wideDB {
		wideCause, wideDB = roleKnownWideGrant(mod, roleRefs, resources, idx, iamServiceRDSDB)
	}
	if unknownDocs && !wideDB {
		return "", nil, "", omittedScopeRole(mod, roleRefs)
	}
	scope, grants, cause = awsDBScope(dest, docs, idx, resources, elements)
	if wideDB {
		scope, grants, cause = widenScopeWithKnownWide(scope, cause, wideCause)
	}
	return scope, grants, cause, ""
}

// awsObjectLock reports object_lock for an S3 bucket.
//
// Truth table:
//   - object_lock_enabled=false → false, known
//   - enabled=true + default_retention mode=COMPLIANCE → true, known
//   - enabled=true + default_retention mode=GOVERNANCE → absent
//     (s3:BypassGovernanceRetention can remove retention)
//   - enabled=true, no default_retention in this plan → absent
//   - lock configuration managed in another root → absent
func awsObjectLock(r planResource, resources []planResource, idx configIndex) (locked, known bool) {
	enabled, enabledSet := r.values["object_lock_enabled"].(bool)
	if enabledSet && !enabled {
		return false, true
	}
	sib, hasConfig := oneSibling(r, resources, "aws_s3_bucket_object_lock_configuration", idx)
	if hasConfig {
		mode, hasMode := retentionMode(sib.values)
		if hasMode && mode == "COMPLIANCE" {
			return true, true
		}
		// GOVERNANCE or retention not visible → absent.
		return false, false
	}
	return false, false
}

// awsObjectLockAbsentReason names why object_lock is omitted from attributes.
// Empty when the attribute is simply unknown for a boring reason.
func awsObjectLockAbsentReason(r planResource, resources []planResource, idx configIndex) string {
	sib, hasConfig := oneSibling(r, resources, "aws_s3_bucket_object_lock_configuration", idx)
	if !hasConfig {
		return ""
	}
	mode, hasMode := retentionMode(sib.values)
	if hasMode && mode == "GOVERNANCE" {
		return "s3:BypassGovernanceRetention"
	}
	return ""
}

func retentionMode(values map[string]any) (mode string, ok bool) {
	for _, rule := range asList(values["rule"]) {
		m, isMap := rule.(map[string]any)
		if !isMap {
			continue
		}
		for _, ret := range asList(m["default_retention"]) {
			rm, isMap := ret.(map[string]any)
			if !isMap {
				continue
			}
			mode, _ = rm["mode"].(string)
			if mode != "" {
				return mode, true
			}
		}
	}
	return "", false
}
