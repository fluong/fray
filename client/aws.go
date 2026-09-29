package client

// buildAWS maps the aws-web-app shape: a load balancer, a container service,
// a relational database, object storage, and a secret store. Other AWS types
// are ignored by the caller. An empty result is not an error.
func buildAWS(plan []byte, resources []planResource, moduleDir string, lifecycle preventIndex, auditOwned bool) ([]*Element, []*Flow, []*Boundary, []string, error) {
	var lbs, services, dbs, buckets, secrets []planResource
	for _, r := range resources {
		switch r.typ {
		case "aws_lb":
			lbs = append(lbs, r)
		case "aws_ecs_service":
			services = append(services, r)
		case "aws_db_instance":
			dbs = append(dbs, r)
		case "aws_s3_bucket":
			buckets = append(buckets, r)
		case "aws_secretsmanager_secret":
			secrets = append(secrets, r)
		}
	}
	if len(lbs)+len(services)+len(dbs)+len(buckets)+len(secrets) == 0 {
		return nil, nil, nil, nil, nil
	}
	idx, err := indexConfig(plan)
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
	for _, r := range secrets {
		add(awsSecretElement(r, resources, idx, lifecycle.protected(r.address)))
	}
	for _, r := range dbs {
		add(awsDBElement(r, lifecycle.protected(r.address)))
	}
	for _, r := range lbs {
		add(awsLBElement(r, resources, idx))
	}
	for _, r := range services {
		add(awsServiceElement(r, resources, idx, containers, &warnings))
	}

	flows, bounds, extra, flowWarns := awsConnections(resources, data, idx, elements, byAddr, containers)
	warnings = append(warnings, flowWarns...)
	elements = append(elements, extra...)
	return elements, flows, bounds, warnings, nil
}

func awsLBElement(r planResource, resources []planResource, idx configIndex) *Element {
	name, _ := r.values["name"].(string)
	attrs := map[string]any{}
	if public, ok := lbPublic(r, resources, idx); ok {
		attrs["public"] = public
	}
	return &Element{
		Name: DisplayName(r.address, name, "load_balancer"), Type: "process", Kind: "load_balancer", Provider: "aws",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
}

func awsServiceElement(r planResource, resources []planResource, idx configIndex, containers map[string][]containerSpec, warnings *[]string) *Element {
	name, _ := r.values["name"].(string)
	attrs := map[string]any{}
	if n, ok, warn := serviceMax(r, resources, idx); warn != "" {
		*warnings = append(*warnings, warn)
	} else if ok {
		attrs["max_instances"] = n
	}
	mod, _, _, _ := splitResourceAddress(r.address)
	tasks := underType(resources, mod, "aws_ecs_task_definition")
	if len(tasks) == 1 {
		specs := containers[mod]
		if planned, ok := containersFromPlan(tasks[0]); ok {
			specs = planned
		}
		if pinned, ok := imagePinned(specs); ok {
			attrs["image_pinned_by_digest"] = pinned
		}
	} else if len(tasks) > 1 {
		*warnings = append(*warnings, "ambiguous task definition on "+r.address+"; image not read")
	}
	return &Element{
		Name: DisplayName(r.address, name, "container_service"), Type: "process", Kind: "container_service", Provider: "aws",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
}

func awsDBElement(r planResource, prevent bool) *Element {
	name, _ := r.values["identifier"].(string)
	if name == "" {
		name, _ = r.values["db_name"].(string)
	}
	attrs := map[string]any{}
	if v, ok := r.values["publicly_accessible"].(bool); ok {
		attrs["public"] = v
	}
	if v, ok := r.values["storage_encrypted"].(bool); ok {
		attrs["encrypted_at_rest"] = v
	}
	setDeletionProtection(attrs, r.values, prevent)
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
	if locked, known := awsObjectLock(r, resources, idx); known {
		attrs["object_lock"] = locked
	} else if reason := awsObjectLockAbsentReason(r, resources, idx); reason != "" {
		causes["object_lock"] = reason
	}
	if auditOwned {
		attrs["audit_logging"] = bucketAudit(r, resources, idx)
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

func awsConnections(resources, data []planResource, idx configIndex, elements []*Element, byAddr map[string]*Element, containers map[string][]containerSpec) ([]*Flow, []*Boundary, []*Element, []string) {
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
		cidrs := lbWorldCIDRs(lb, resources, idx)
		if len(cidrs) == 0 {
			continue
		}
		if public == nil {
			var sigs []Signal
			for _, c := range cidrs {
				sigs = append(sigs, Signal{Type: "network_ingress", Name: c})
			}
			public = &Element{
				Name: "Public client", Type: "external_entity", Kind: "public_client",
				Provenance: "inferred",
				Evidence:   Evidence{Signals: sigs},
			}
			extra = append(extra, public)
		}
		listener, transport, anonymous := publicListener(lb, resources, idx)
		flow := &Flow{
			From: public.canonicalKey(), To: lbEl.canonicalKey(),
			DataClass: "unknown", Transport: transport,
		}
		if anonymous {
			flow.AuthzScope = "public"
			flow.AuthzGrants = normalizeAuthzGrants("public")
			if listener != "" {
				flow.Causes = map[string]string{"authz_scope": listener}
			}
		}
		flows = append(flows, flow)
		addInside(lbEl)

		for _, svc := range servicesFronted(lb, resources, elements, idx, &warnings) {
			flows = append(flows, &Flow{
				From: lbEl.canonicalKey(), To: svc.canonicalKey(),
				DataClass: "unknown", Transport: targetTransport(lb, resources, idx),
			})
			addInside(svc)
		}
	}

	for _, svc := range resources {
		if svc.typ != "aws_ecs_service" {
			continue
		}
		svcEl := byAddr[svc.address]
		if svcEl == nil {
			continue
		}
		mod, _, _, _ := splitResourceAddress(svc.address)
		tasks := underType(resources, mod, "aws_ecs_task_definition")
		if len(tasks) != 1 {
			continue
		}
		specs := containers[mod]
		if planned, ok := containersFromPlan(tasks[0]); ok {
			specs = planned
		}
		flows = append(flows, secretFlowsFrom(svc, svcEl, mod, specs, resources, data, idx, elements, &warnings)...)
		flows = append(flows, bucketFlows(svc, svcEl, mod, resources, data, idx, elements, &warnings)...)
	}
	flows = append(flows, dbFlows(resources, idx, elements, &warnings)...)

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

func secretFlowsFrom(svc planResource, svcEl *Element, module string, specs []containerSpec, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string) []*Flow {
	seen := map[string]bool{}
	var flows []*Flow
	docs := roleDocuments(module, idx.attrRefs(taskAddress(resources, module), "execution_role_arn"), resources, data, idx)
	for _, spec := range specs {
		for _, ref := range spec.secrets {
			hits, ambiguous := elementsFromRefs([]string{ref}, resources, elements, "aws_secretsmanager_secret")
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
			if scope, grants, cause := awsSecretScope(sec, docs, idx.callRefs(module), resources, elements); scope != "" {
				flow.AuthzScope = scope
				flow.AuthzGrants = grants
				if cause != "" {
					flow.Causes["authz_scope"] = cause
				}
			}
			flows = append(flows, flow)
		}
	}
	return flows
}

func bucketFlows(svc planResource, svcEl *Element, module string, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string) []*Flow {
	docs := roleDocuments(module, idx.attrRefs(taskAddress(resources, module), "task_role_arn"), resources, data, idx)
	hits, grants, actions, cause, ambiguous, actionWarn := bucketsFromDocs(docs, idx.callRefs(module), resources, elements)
	if ambiguous {
		*warnings = append(*warnings, "ambiguous bucket for "+svc.address)
		return nil
	}
	if len(hits) != 1 {
		return nil
	}
	scope := effectiveAuthzScope(grants)
	if scope == "" {
		return nil
	}
	if actionWarn != "" {
		*warnings = append(*warnings, actionWarn)
	}
	flow := &Flow{
		From: svcEl.canonicalKey(), To: hits[0].canonicalKey(),
		DataClass: "unknown", Transport: "tls",
		AuthzScope: scope, AuthzGrants: grants, AuthzActions: actions,
	}
	if cause != "" {
		flow.Causes = map[string]string{"authz_scope": cause}
	}
	return []*Flow{flow}
}

func dbFlows(resources []planResource, idx configIndex, elements []*Element, warnings *[]string) []*Flow {
	var flows []*Flow
	for _, sg := range resources {
		if sg.typ != "aws_security_group" {
			continue
		}
		if !ingressRefsSG(sg, idx) {
			continue
		}
		dest := elementsUsingSG(sg.address, "relational_db", elements, idx)
		if len(dest) == 0 {
			continue
		}
		sources := sourceServices(sg, resources, elements, idx)
		if len(dest) != 1 || len(sources) != 1 {
			*warnings = append(*warnings, "ambiguous database path through "+sg.address)
			continue
		}
		flows = append(flows, &Flow{
			From: sources[0].canonicalKey(), To: dest[0].canonicalKey(),
			DataClass: "unknown", Transport: "unknown",
		})
	}
	return flows
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
