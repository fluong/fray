package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Ignored resource types are read for attributes or dropped on purpose.
var ignoredTypes = map[string]bool{
	"google_project_service":                         true,
	"google_secret_manager_secret_version":           true,
	"google_service_account":                         true,
	"google_artifact_registry_repository":            true,
	"google_artifact_registry_repository_iam_member": true,
	"google_project_iam_audit_config":                true,
	"google_project_iam_member":                      true,
	"google_secret_manager_secret_iam_member":        true,
	"google_cloud_run_v2_service_iam_member":         true,
	"google_logging_project_sink":                    true,
	"google_logging_folder_sink":                     true,
	"google_logging_organization_sink":               true,
	// AWS types that are siblings or network plumbing, not elements.
	"aws_appautoscaling_policy":                          true,
	"aws_appautoscaling_target":                          true,
	"aws_cloudtrail":                                     true,
	"aws_cloudwatch_log_group":                           true,
	"aws_db_parameter_group":                             true,
	"aws_db_subnet_group":                                true,
	"aws_default_network_acl":                            true,
	"aws_default_route_table":                            true,
	"aws_default_security_group":                         true,
	"aws_ecs_cluster":                                    true,
	"aws_ecs_cluster_capacity_providers":                 true,
	"aws_ecs_task_definition":                            true,
	"aws_eip":                                            true,
	"aws_iam_policy":                                     true,
	"aws_iam_policy_document":                            true,
	"aws_iam_role":                                       true,
	"aws_iam_role_policy_attachment":                     true,
	"aws_internet_gateway":                               true,
	"aws_lb_listener":                                    true,
	"aws_lb_target_group":                                true,
	"aws_nat_gateway":                                    true,
	"aws_route":                                          true,
	"aws_route_table":                                    true,
	"aws_route_table_association":                        true,
	"aws_s3_bucket_logging":                              true,
	"aws_s3_bucket_ownership_controls":                   true,
	"aws_s3_bucket_public_access_block":                  true,
	"aws_s3_bucket_server_side_encryption_configuration": true,
	"aws_s3_bucket_versioning":                           true,
	"aws_secretsmanager_secret_rotation":                 true,
	"aws_secretsmanager_secret_version":                  true,
	"aws_security_group":                                 true,
	"aws_subnet":                                         true,
	"aws_vpc":                                            true,
	"aws_vpc_security_group_egress_rule":                 true,
	"aws_vpc_security_group_ingress_rule":                true,
	"random_id":                                          true,
	"random_password":                                    true,
	"time_sleep":                                         true,
}

var regionPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

type planResource struct {
	address string
	typ     string
	values  map[string]any
}

type frayConfig struct {
	SchemaVersion string          `yaml:"schema_version"`
	Redaction     string          `yaml:"redaction"` // "" = on (default); "off" = plaintext
	AuditConfig   string          `yaml:"audit_config"`
	Elements      []frayElement   `yaml:"elements"`
	Flows         []frayFlow      `yaml:"flows"`
	Boundaries    []frayBoundary  `yaml:"boundaries"`
	Annotations   frayAnnotations `yaml:"annotations"`
}

// RedactionOff reports whether fray.yaml sets redaction: off.
func (c frayConfig) RedactionOff() bool { return c.Redaction == "off" }

type frayElement struct {
	Key        string         `yaml:"key"`
	Name       string         `yaml:"name"`
	Type       string         `yaml:"type"`
	Kind       string         `yaml:"kind"`
	Provider   string         `yaml:"provider"`
	Purpose    string         `yaml:"purpose"`
	Attributes map[string]any `yaml:"attributes"`
}

type frayFlow struct {
	From           string   `yaml:"from"`
	To             string   `yaml:"to"`
	DataClass      string   `yaml:"data_class"`
	Transport      string   `yaml:"transport"`
	AuthzScope     string   `yaml:"authz_scope"`
	AuthzGrants    []string `yaml:"authz_grants"`
	SecretDelivery string   `yaml:"secret_delivery"`
}

type frayBoundary struct {
	Kind    string   `yaml:"kind"`
	Inside  []string `yaml:"inside"`
	Outside []string `yaml:"outside"`
}

type frayAnnotations struct {
	Elements []struct {
		Signal   string `yaml:"signal"`
		Address  string `yaml:"address"`
		Kind     string `yaml:"kind"`
		Provider string `yaml:"provider"`
		Purpose  string `yaml:"purpose"`
	} `yaml:"elements"`
	Flows []struct {
		From      string `yaml:"from"`
		To        string `yaml:"to"`
		DataClass string `yaml:"data_class"`
	} `yaml:"flows"`
}

// Parse builds a DFD from a terraform show -json plan and fray.yaml.
// declaredSource is the path recorded on declared elements. moduleDir is the
// Terraform root module; lifecycle.prevent_destroy is read from there because
// the plan JSON omits it. An empty moduleDir skips that read. Warnings are
// ambiguity: the parser emitted nothing for that decision.
func Parse(plan, config []byte, declaredSource string, src Source, moduleDir string) (DFD, []string, error) {
	resources, err := loadResources(plan)
	if err != nil {
		return DFD{}, nil, err
	}
	lifecycle, err := readPreventDestroy(moduleDir)
	if err != nil {
		return DFD{}, nil, err
	}
	cfg, err := loadConfig(config)
	if err != nil {
		return DFD{}, nil, err
	}
	var warnings []string
	elements := make([]*Element, 0)
	byAddress := map[string]*Element{}

	var (
		services   []planResource
		secrets    []planResource
		gcs        []planResource
		r2         []planResource
		invokers   []planResource
		secretIAM  []planResource
		projectIAM []planResource
		audits     []planResource
	)
	seenUnknown := map[string]bool{}
	for _, r := range resources {
		switch r.typ {
		case "google_cloud_run_v2_service":
			services = append(services, r)
		case "google_secret_manager_secret":
			secrets = append(secrets, r)
		case "google_storage_bucket":
			gcs = append(gcs, r)
		case "cloudflare_r2_bucket":
			r2 = append(r2, r)
		case "google_cloud_run_v2_service_iam_member":
			invokers = append(invokers, r)
		case "google_secret_manager_secret_iam_member":
			secretIAM = append(secretIAM, r)
		case "google_project_iam_member":
			projectIAM = append(projectIAM, r)
		case "google_project_iam_audit_config":
			audits = append(audits, r)
		case "aws_lb", "aws_ecs_service", "aws_db_instance", "aws_s3_bucket", "aws_secretsmanager_secret":
			// Mapped in buildAWS. Not warned as unknown.
		case "cloudflare_r2_managed_domain", "cloudflare_r2_custom_domain":
			// Read later to decide whether a bucket is public. Not an element.
		default:
			if ignoredTypes[r.typ] || seenUnknown[r.typ] {
				continue
			}
			seenUnknown[r.typ] = true
			warnings = append(warnings, "no mapping for "+r.address+"; skipped")
		}
	}

	secretAudit := auditDataRead(audits, "secretmanager.googleapis.com")
	var storageAudit *bool
	if cfg.AuditConfig == "owned_by_this_root" {
		v := auditDataRead(audits, "storage.googleapis.com")
		storageAudit = &v
	}

	add := func(el *Element) {
		elements = append(elements, el)
		if len(el.Evidence.Addresses) == 1 {
			byAddress[el.Evidence.Addresses[0]] = el
		}
	}

	for _, r := range services {
		el, warn := cloudRunElement(r, invokers, lifecycle.protected(r.address))
		warnings = append(warnings, warn...)
		add(el)
	}
	for _, r := range secrets {
		add(secretElement(r, secretAudit, lifecycle.protected(r.address)))
	}
	for _, r := range gcs {
		add(gcsElement(r, storageAudit, lifecycle.protected(r.address)))
	}
	for _, r := range r2 {
		add(r2Element(r, resources, lifecycle.protected(r.address)))
	}

	awsOwned := cfg.AuditConfig == "owned_by_this_root"
	awsEls, awsFlows, awsBounds, awsWarns, err := buildAWS(plan, resources, moduleDir, lifecycle, awsOwned)
	if err != nil {
		return DFD{}, nil, err
	}
	warnings = append(warnings, awsWarns...)
	for _, el := range awsEls {
		add(el)
	}

	db := databaseElement(secrets, services)
	if db != nil {
		elements = append(elements, db)
	}
	llm := vertexElement(projectIAM, services)
	if llm.warn != "" {
		warnings = append(warnings, llm.warn)
	}
	if llm.el != nil {
		elements = append(elements, llm.el)
	}
	caller := publicCaller(invokers)
	if caller != nil {
		elements = append(elements, caller)
	}

	for _, dec := range cfg.Elements {
		if dec.Purpose != "" && !ValidPurpose(dec.Purpose) {
			return DFD{}, warnings, fmt.Errorf("declared element %q purpose %q is not a dfd/v1 purpose", dec.Key, dec.Purpose)
		}
		el := &Element{
			Name: dec.Name, Type: dec.Type, Kind: dec.Kind, Provider: dec.Provider,
			Provenance: "declared",
			Evidence:   Evidence{Source: declaredSource, Key: dec.Key},
		}
		if dec.Purpose != "" {
			setPurpose(el, dec.Purpose, PurposeSourceDeclared, true)
		}
		if len(dec.Attributes) > 0 {
			el.Attributes = dec.Attributes
		}
		elements = append(elements, el)
		byAddress["declared:"+dec.Key] = el
	}

	idx, err := indexConfig(plan)
	if err != nil {
		return DFD{}, warnings, err
	}
	applyPurpose(elements, resources, idx)

	if err := applyElementAnnotations(elements, cfg); err != nil {
		return DFD{}, warnings, err
	}

	flows := mechanicalFlows(services, secrets, r2, invokers, secretIAM, projectIAM, elements, &warnings)
	flows = append(flows, awsFlows...)
	for _, f := range cfg.Flows {
		flow, err := declaredFlow(f, elements)
		if err != nil {
			return DFD{}, warnings, err
		}
		flows = append(flows, flow)
	}
	for _, f := range flows {
		f.identityClass = f.DataClass
	}
	if err := applyFlowAnnotations(flows, elements, cfg); err != nil {
		return DFD{}, warnings, err
	}

	boundaries := mechanicalBoundaries(flows, elements, &warnings)
	boundaries = append(boundaries, awsBounds...)
	for _, b := range cfg.Boundaries {
		bound, err := declaredBoundary(b, elements)
		if err != nil {
			return DFD{}, warnings, err
		}
		boundaries = append(boundaries, bound)
	}
	doc := DFD{
		SchemaVersion:   "dfd/v1",
		Source:          src,
		Elements:        deref(elements),
		TrustBoundaries: derefB(boundaries),
		Flows:           derefF(flows),
	}
	finalize(&doc)
	slices.Sort(warnings)
	return doc, warnings, nil
}

func loadResources(plan []byte) ([]planResource, error) {
	var root struct {
		ResourceChanges []struct {
			Address string `json:"address"`
			Mode    string `json:"mode"`
			Type    string `json:"type"`
			Change  struct {
				After map[string]any `json:"after"`
			} `json:"change"`
		} `json:"resource_changes"`
	}
	dec := json.NewDecoder(bytes.NewReader(plan))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}
	var out []planResource
	for _, r := range root.ResourceChanges {
		if r.Mode != "" && r.Mode != "managed" {
			continue
		}
		if r.Change.After == nil {
			continue
		}
		out = append(out, planResource{address: r.Address, typ: r.Type, values: r.Change.After})
	}
	return out, nil
}

func loadConfig(raw []byte) (frayConfig, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var cfg frayConfig
	if err := dec.Decode(&cfg); err != nil {
		return frayConfig{}, err
	}
	if cfg.SchemaVersion != "fray-config/v1" {
		return frayConfig{}, fmt.Errorf("fray.yaml schema_version %q", cfg.SchemaVersion)
	}
	if cfg.AuditConfig != "" && cfg.AuditConfig != "owned_by_this_root" {
		return frayConfig{}, fmt.Errorf("fray.yaml audit_config %q", cfg.AuditConfig)
	}
	if cfg.Redaction != "" && cfg.Redaction != "off" {
		return frayConfig{}, fmt.Errorf("fray.yaml redaction %q (want \"off\" or omit)", cfg.Redaction)
	}
	return cfg, nil
}

// RedactionDisabled reports whether fray.yaml sets redaction: off.
func RedactionDisabled(config []byte) (bool, error) {
	cfg, err := loadConfig(config)
	if err != nil {
		return false, err
	}
	return cfg.RedactionOff(), nil
}

func cloudRunElement(r planResource, invokers []planResource, prevent bool) (*Element, []string) {
	var warnings []string
	attrs := map[string]any{}
	name, _ := r.values["name"].(string)
	if loc, ok := r.values["location"].(string); ok && regionPattern.MatchString(loc) {
		attrs["region"] = loc
	}
	setDeletionProtection(attrs, r.values, prevent)
	templates := asList(r.values["template"])
	containers := []any{}
	if len(templates) == 1 {
		if m, ok := templates[0].(map[string]any); ok {
			containers = asList(m["containers"])
			scaling := asList(m["scaling"])
			if len(scaling) == 1 {
				if sm, ok := scaling[0].(map[string]any); ok {
					if n, ok := number(sm["max_instance_count"]); ok {
						attrs["max_instances"] = n
					}
				}
			}
		}
	} else if len(templates) > 1 {
		warnings = append(warnings, "ambiguous Cloud Run template on "+r.address)
	}
	if len(containers) == 1 {
		if c, ok := containers[0].(map[string]any); ok {
			if image, ok := c["image"].(string); ok {
				attrs["image_pinned_by_digest"] = strings.Contains(image, "@sha256:")
			}
		}
	} else if len(containers) > 1 {
		warnings = append(warnings, "ambiguous Cloud Run containers on "+r.address+"; image not read")
	}
	if publicInvoker(r, invokers) {
		attrs["public"] = true
	}
	return &Element{
		Name: DisplayName(r.address, name, "container_service"), Type: "process", Kind: "container_service", Provider: "gcp",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}, warnings
}

func secretElement(r planResource, audit, prevent bool) *Element {
	name, _ := r.values["secret_id"].(string)
	attrs := map[string]any{
		"audit_logging":       audit,
		"rotation_configured": rotationOn(r.values["rotation"]),
	}
	setDeletionProtection(attrs, r.values, prevent)
	return &Element{
		Name: DisplayName(r.address, name, "secret_store"), Type: "datastore", Kind: "secret_store", Provider: "gcp",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
}

func gcsElement(r planResource, audit *bool, prevent bool) *Element {
	name, _ := r.values["name"].(string)
	attrs := map[string]any{}
	if audit != nil {
		attrs["audit_logging"] = *audit
	}
	if r.values["uniform_bucket_level_access"] == true {
		attrs["acls_disabled"] = true
	}
	if r.values["public_access_prevention"] == "enforced" {
		attrs["public_access_blocked"] = true
		attrs["public"] = false
	}
	if versioningOn(r.values["versioning"]) {
		attrs["versioning"] = true
	}
	if locked, known := gcsRetentionLocked(r.values["retention_policy"]); known {
		attrs["object_lock"] = locked
	}
	setObjectDeletion(attrs, r.values, prevent)
	return &Element{
		Name: DisplayName(r.address, name, "object_storage"), Type: "datastore", Kind: "object_storage", Provider: "gcp",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
}

func r2Element(r planResource, resources []planResource, prevent bool) *Element {
	name, _ := r.values["name"].(string)
	attrs := map[string]any{
		"acls_disabled": true,
		"audit_logging": false,
		// object_lock omitted: Cloudflare R2 lock / retention is not parsed yet
		// (roadmap). Absent → FR-027 stays unverified rather than false-open.
	}
	causes := map[string]string{}
	if cause, public := r2PublicCause(name, resources); public {
		attrs["public"] = true
		attrs["public_access_blocked"] = false
		causes["public"] = cause
		causes["public_access_blocked"] = cause
	} else {
		attrs["public_access_blocked"] = true
		attrs["public"] = false
	}
	setObjectDeletion(attrs, r.values, prevent)
	return &Element{
		Name: DisplayName(r.address, name, "object_storage"), Type: "datastore", Kind: "object_storage", Provider: "cloudflare",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
		Causes:     causes,
	}
}

func setDeletionProtection(attrs, values map[string]any, prevent bool) {
	if prevent || values["deletion_protection"] == true {
		attrs["deletion_protection"] = true
	}
}

// setObjectDeletion is deletion_protection for buckets. prevent_destroy wins.
// force_destroy false, including the provider default when the argument is
// omitted, blocks deleting a non-empty bucket. force_destroy true does not.
func setObjectDeletion(attrs, values map[string]any, prevent bool) {
	if prevent {
		attrs["deletion_protection"] = true
		return
	}
	force, present := values["force_destroy"]
	if !present {
		attrs["deletion_protection"] = true
		return
	}
	on, ok := force.(bool)
	if !ok {
		return
	}
	attrs["deletion_protection"] = !on
}

func databaseElement(secrets, services []planResource) *Element {
	var sigs []Signal
	for _, s := range secrets {
		id, _ := s.values["secret_id"].(string)
		if strings.Contains(id, "database-url") {
			sigs = append(sigs, Signal{Type: "secret_name", Name: id})
		}
	}
	for _, svc := range services {
		for _, env := range serviceEnvs(svc) {
			if env.name == "DATABASE_URL" {
				sigs = append(sigs, Signal{Type: "env_var", Name: "DATABASE_URL"})
			}
		}
	}
	if len(sigs) == 0 {
		return nil
	}
	return &Element{
		Name: "Postgres", Type: "datastore", Kind: "relational_db",
		Provenance: "inferred",
		Evidence:   Evidence{Signals: sigs},
	}
}

func vertexElement(members, services []planResource) (out struct {
	el   *Element
	warn string
}) {
	var role bool
	for _, m := range members {
		if m.values["role"] == "roles/aiplatform.user" {
			role = true
		}
	}
	var regions []string
	for _, svc := range services {
		for _, env := range serviceEnvs(svc) {
			if env.name == "VERTEX_REGION" && env.value != "" {
				regions = append(regions, env.value)
			}
		}
	}
	if !role && len(regions) == 0 {
		return out
	}
	sigs := []Signal{}
	if role {
		sigs = append(sigs, Signal{Type: "iam_role", Name: "roles/aiplatform.user"})
	}
	if len(regions) > 0 {
		sigs = append(sigs, Signal{Type: "env_var", Name: "VERTEX_REGION"})
	}
	el := &Element{
		Name: "Vertex", Type: "external_entity", Kind: "llm_api", Provider: "gcp",
		Provenance: "inferred",
		Evidence:   Evidence{Signals: sigs},
	}
	if len(regions) == 1 && regionPattern.MatchString(regions[0]) {
		el.Attributes = map[string]any{"region": regions[0]}
	} else if len(regions) > 1 {
		out.warn = "ambiguous VERTEX_REGION values; region not set"
	}
	out.el = el
	return out
}

func publicCaller(invokers []planResource) *Element {
	for _, m := range invokers {
		if m.values["member"] == "allUsers" && m.values["role"] == "roles/run.invoker" {
			return &Element{
				Name: "Public client", Type: "external_entity", Kind: "public_client",
				Provenance: "inferred",
				Evidence:   Evidence{Signals: []Signal{{Type: "iam_member", Name: "allUsers"}}},
			}
		}
	}
	return nil
}

type envRef struct {
	name   string
	value  string
	secret string
}

func serviceEnvs(r planResource) []envRef {
	var out []envRef
	for _, t := range asList(r.values["template"]) {
		tm, ok := t.(map[string]any)
		if !ok {
			continue
		}
		for _, c := range asList(tm["containers"]) {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			for _, e := range asList(cm["env"]) {
				em, ok := e.(map[string]any)
				if !ok {
					continue
				}
				name, _ := em["name"].(string)
				value, _ := em["value"].(string)
				out = append(out, envRef{name: name, value: value, secret: secretRef(em)})
			}
		}
	}
	return out
}

func secretRef(env map[string]any) string {
	for _, vs := range asList(env["value_source"]) {
		vm, ok := vs.(map[string]any)
		if !ok {
			continue
		}
		for _, skr := range asList(vm["secret_key_ref"]) {
			sm, ok := skr.(map[string]any)
			if !ok {
				continue
			}
			if s, ok := sm["secret"].(string); ok {
				return s
			}
		}
	}
	return ""
}

func mechanicalFlows(services, secrets, r2buckets, invokers, secretIAM, projectIAM []planResource, elements []*Element, warnings *[]string) []*Flow {
	var flows []*Flow
	secretByID := map[string]*Element{}
	for _, s := range secrets {
		id, _ := s.values["secret_id"].(string)
		for _, el := range elements {
			if len(el.Evidence.Addresses) == 1 && el.Evidence.Addresses[0] == s.address {
				secretByID[id] = el
			}
		}
	}
	var caller *Element
	var db *Element
	var llm *Element
	for _, el := range elements {
		if el.Provenance != "inferred" {
			continue
		}
		for _, sig := range el.Evidence.Signals {
			switch sig.Type + ":" + sig.Name {
			case "iam_member:allUsers":
				caller = el
			case "env_var:DATABASE_URL":
				db = el
			case "iam_role:roles/aiplatform.user":
				llm = el
			}
		}
	}

	var r2el *Element
	if len(r2buckets) == 1 {
		for _, el := range elements {
			if len(el.Evidence.Addresses) == 1 && el.Evidence.Addresses[0] == r2buckets[0].address {
				r2el = el
			}
		}
	}

	for _, svc := range services {
		svcEl := findAddress(elements, svc.address)
		if svcEl == nil {
			continue
		}
		sa, _ := serviceAccount(svc)
		for _, env := range serviceEnvs(svc) {
			if env.secret == "" {
				continue
			}
			sec := secretByID[env.secret]
			if sec == nil {
				*warnings = append(*warnings, "env "+env.name+" references secret "+env.secret+" with no element")
				continue
			}
			flow := &Flow{
				From: secTemp(sec), To: secTemp(svcEl),
				DataClass: "credentials", Transport: "local", SecretDelivery: "env",
				Causes: map[string]string{"secret_delivery": svc.address},
			}
			if scope, grants, cause := secretScope(env.secret, sa, secretIAM, projectIAM); scope != "" {
				flow.AuthzScope = scope
				flow.AuthzGrants = grants
				if cause != "" {
					flow.Causes["authz_scope"] = cause
				}
			}
			flows = append(flows, flow)
		}
		if db != nil && hasEnv(svc, "DATABASE_URL") {
			flows = append(flows, &Flow{
				From: secTemp(svcEl), To: secTemp(db),
				DataClass: "unknown", Transport: "tls",
			})
		}
		r2envs := 0
		for _, env := range serviceEnvs(svc) {
			if strings.HasPrefix(env.name, "R2_") && env.secret != "" {
				r2envs++
			}
		}
		if r2envs > 0 {
			if len(r2buckets) != 1 {
				names := make([]string, len(r2buckets))
				for i, b := range r2buckets {
					names[i] = b.address
				}
				slices.Sort(names)
				*warnings = append(*warnings, "ambiguous R2 bucket for R2 key envs on "+svc.address+"; candidates: "+strings.Join(names, ", "))
			} else if r2el != nil {
				flows = append(flows, &Flow{
					From: secTemp(svcEl), To: secTemp(r2el),
					DataClass: "unknown", Transport: "tls",
					// R2 access-key envs imply a bucket-scoped write capability.
					AuthzScope:  "resource",
					AuthzGrants: normalizeAuthzGrants("resource"),
				})
			}
		}
		if llm != nil && hasEnv(svc, "VERTEX_REGION") && saMatches(projectIAM, "roles/aiplatform.user", sa) {
			flows = append(flows, &Flow{
				From: secTemp(svcEl), To: secTemp(llm),
				DataClass: "unknown", Transport: "tls", AuthzScope: "project",
				AuthzGrants: normalizeAuthzGrants("project"),
				Causes:      map[string]string{"authz_scope": projectRole(projectIAM, "roles/aiplatform.user", sa)},
			})
		}
		if caller != nil && publicInvoker(svc, invokers) {
			flows = append(flows, &Flow{
				From: secTemp(caller), To: secTemp(svcEl),
				DataClass: "unknown", Transport: "tls", AuthzScope: "public",
				AuthzGrants: normalizeAuthzGrants("public"),
				Causes:      map[string]string{"authz_scope": publicInvokerAddress(svc, invokers)},
			})
		}
	}
	return flows
}

// secTemp stores the element pointer's address string in From/To until ids exist.
// The pointer identity is kept in a side channel via the element name? No.
// From/To will be filled with a placeholder key we can resolve: use a stable
// token stored on the element before ids exist.
//
// We use the canonical key, which is unique, and replace it with the id in assign.
// Flow.From holding the canonical key works if we translate after assignIDs.
// Doing it here is messy. Instead keep *Element on an internal flow.

func secTemp(el *Element) string {
	return el.canonicalKey()
}

func declaredFlow(f frayFlow, elements []*Element) (*Flow, error) {
	from, err := resolve(f.From, elements)
	if err != nil {
		return nil, err
	}
	to, err := resolve(f.To, elements)
	if err != nil {
		return nil, err
	}
	return &Flow{
		From: from.canonicalKey(), To: to.canonicalKey(),
		DataClass: f.DataClass, Transport: f.Transport,
		AuthzScope: f.AuthzScope, AuthzGrants: normalizeAuthzGrants(f.AuthzGrants...),
		SecretDelivery: f.SecretDelivery,
		Boundaries:     []string{},
	}, nil
}

func applyElementAnnotations(elements []*Element, cfg frayConfig) error {
	for _, ann := range cfg.Annotations.Elements {
		if ann.Purpose != "" && !ValidPurpose(ann.Purpose) {
			return fmt.Errorf("annotation purpose %q is not a dfd/v1 purpose", ann.Purpose)
		}
		var hits []*Element
		switch {
		case ann.Address != "":
			el, err := resolve(ann.Address, elements)
			if err != nil {
				return err
			}
			hits = []*Element{el}
		case ann.Signal != "":
			var err error
			hits, err = matchSignal(ann.Signal, elements)
			if err != nil {
				return err
			}
			if len(hits) != 1 {
				return fmt.Errorf("annotation %s matched %d elements", ann.Signal, len(hits))
			}
		default:
			return fmt.Errorf("element annotation needs address or signal")
		}
		if ann.Kind != "" {
			hits[0].Kind = ann.Kind
		}
		if ann.Provider != "" {
			hits[0].Provider = ann.Provider
		}
		if ann.Purpose != "" {
			setPurpose(hits[0], ann.Purpose, PurposeSourceDeclared, true)
		}
	}
	return nil
}

func applyFlowAnnotations(flows []*Flow, elements []*Element, cfg frayConfig) error {
	for _, ann := range cfg.Annotations.Flows {
		from, err := resolve(ann.From, elements)
		if err != nil {
			return err
		}
		to, err := resolve(ann.To, elements)
		if err != nil {
			return err
		}
		fk, tk := from.canonicalKey(), to.canonicalKey()
		n := 0
		for _, f := range flows {
			if f.From == fk && f.To == tk {
				f.DataClass = ann.DataClass
				n++
			}
		}
		if n == 0 {
			return fmt.Errorf("flow annotation %s -> %s matched no parser flow; declare a new flow under flows instead", ann.From, ann.To)
		}
		if n != 1 {
			return fmt.Errorf("flow annotation %s -> %s matched %d flows", ann.From, ann.To, n)
		}
	}
	return nil
}

func mechanicalBoundaries(flows []*Flow, elements []*Element, warnings *[]string) []*Boundary {
	type key struct{ kind, inside, outside string }
	seen := map[key]*Boundary{}
	var out []*Boundary
	byKey := map[string]*Element{}
	for _, el := range elements {
		byKey[el.canonicalKey()] = el
	}
	for _, f := range flows {
		from, to := byKey[f.From], byKey[f.To]
		if from == nil || to == nil {
			continue
		}
		kind, inside, outside, ok := boundaryEnds(from, to, warnings)
		if !ok {
			continue
		}
		k := key{kind, inside.canonicalKey(), outside.canonicalKey()}
		if _, exists := seen[k]; exists {
			continue
		}
		b := &Boundary{Kind: kind, Inside: []string{inside.canonicalKey()}, Outside: []string{outside.canonicalKey()}}
		seen[k] = b
		out = append(out, b)
	}
	return out
}

func boundaryEnds(from, to *Element, warnings *[]string) (string, *Element, *Element, bool) {
	if proc, other, ok := processExternal(from, to); ok {
		kind := "provider"
		if other.Kind == "public_client" || other.Kind == "ci_runner" {
			kind = "network"
		}
		return kind, proc, other, true
	}
	if from.Provider != "" && to.Provider != "" && from.Provider != to.Provider {
		switch {
		case from.Kind == "container_service":
			return "provider", from, to, true
		case to.Kind == "container_service":
			return "provider", to, from, true
		default:
			*warnings = append(*warnings, "ambiguous provider-boundary side between "+from.Name+" and "+to.Name)
		}
	}
	return "", nil, nil, false
}

func processExternal(a, b *Element) (*Element, *Element, bool) {
	if a.Kind == "container_service" && b.Type == "external_entity" {
		return a, b, true
	}
	if b.Kind == "container_service" && a.Type == "external_entity" {
		return b, a, true
	}
	return nil, nil, false
}

func declaredBoundary(b frayBoundary, elements []*Element) (*Boundary, error) {
	inside, err := resolveAll(b.Inside, elements)
	if err != nil {
		return nil, err
	}
	outside, err := resolveAll(b.Outside, elements)
	if err != nil {
		return nil, err
	}
	inKeys := make([]string, len(inside))
	outKeys := make([]string, len(outside))
	for i, el := range inside {
		inKeys[i] = el.canonicalKey()
	}
	for i, el := range outside {
		outKeys[i] = el.canonicalKey()
	}
	return &Boundary{Kind: b.Kind, Inside: inKeys, Outside: outKeys}, nil
}

func deref(els []*Element) []Element {
	out := make([]Element, len(els))
	for i, el := range els {
		out[i] = *el
	}
	return out
}

func derefB(bs []*Boundary) []Boundary {
	out := make([]Boundary, len(bs))
	for i, b := range bs {
		out[i] = *b
	}
	return out
}

func derefF(fs []*Flow) []Flow {
	out := make([]Flow, len(fs))
	for i, f := range fs {
		if f.Boundaries == nil {
			f.Boundaries = []string{}
		}
		out[i] = *f
	}
	return out
}

func asList(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case map[string]any:
		return []any{t}
	default:
		return nil
	}
}

func number(v any) (int, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	case float64:
		return int(n), n == float64(int(n))
	default:
		return 0, false
	}
}

func rotationOn(v any) bool {
	switch t := v.(type) {
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		return false
	}
}

func versioningOn(v any) bool {
	for _, item := range asList(v) {
		m, ok := item.(map[string]any)
		if ok && m["enabled"] == true {
			return true
		}
	}
	return false
}

// gcsRetentionLocked reads retention_policy.is_locked.
//
// Truth table:
//   - is_locked=true → object_lock=true, known
//   - is_locked=false (unlocked retention) → attribute absent
//   - no retention_policy → object_lock=false, known
func gcsRetentionLocked(v any) (locked, known bool) {
	items := asList(v)
	if len(items) == 0 {
		if m, ok := v.(map[string]any); ok {
			items = []any{m}
		}
	}
	if len(items) == 0 {
		// No retention policy block → not locked, known false.
		return false, true
	}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		b, ok := m["is_locked"].(bool)
		if !ok {
			// Policy present without is_locked → absent.
			return false, false
		}
		if b {
			return true, true
		}
		// Unlocked retention is bypassable → absent.
		return false, false
	}
	return false, false
}

func auditDataRead(audits []planResource, service string) bool {
	for _, a := range audits {
		if a.values["service"] != service {
			continue
		}
		for _, c := range asList(a.values["audit_log_config"]) {
			m, ok := c.(map[string]any)
			if ok && m["log_type"] == "DATA_READ" {
				return true
			}
		}
	}
	return false
}

// r2PublicCause reports the enabled r2.dev or custom-domain resource for this
// bucket. A disabled domain is not public. Other R2 resources, such as CORS,
// do not make the bucket public.
func r2PublicCause(bucketName string, resources []planResource) (cause string, public bool) {
	if bucketName == "" {
		return "", false
	}
	for _, r := range resources {
		if r.typ != "cloudflare_r2_managed_domain" && r.typ != "cloudflare_r2_custom_domain" {
			continue
		}
		if r.values["enabled"] != true {
			continue
		}
		name, _ := r.values["bucket_name"].(string)
		if name == bucketName {
			return r.address, true
		}
	}
	return "", false
}

func findAddress(elements []*Element, address string) *Element {
	for _, el := range elements {
		if slices.Contains(el.Evidence.Addresses, address) {
			return el
		}
	}
	return nil
}

func hasEnv(r planResource, name string) bool {
	for _, env := range serviceEnvs(r) {
		if env.name == name {
			return true
		}
	}
	return false
}

func serviceAccount(r planResource) (string, bool) {
	for _, t := range asList(r.values["template"]) {
		m, ok := t.(map[string]any)
		if !ok {
			continue
		}
		if s, ok := m["service_account"].(string); ok && s != "" {
			return s, true
		}
	}
	return "", false
}

func publicInvoker(svc planResource, invokers []planResource) bool {
	return publicInvokerAddress(svc, invokers) != ""
}

func publicInvokerAddress(svc planResource, invokers []planResource) string {
	name, _ := svc.values["name"].(string)
	for _, m := range invokers {
		if m.values["member"] != "allUsers" || m.values["role"] != "roles/run.invoker" {
			continue
		}
		target, _ := m.values["name"].(string)
		if target == name || strings.HasSuffix(target, "/services/"+name) {
			return m.address
		}
	}
	return ""
}

func memberIs(member any, sa string) bool {
	s, _ := member.(string)
	return sa != "" && (s == sa || s == "serviceAccount:"+sa)
}

func secretMatch(got, secretID string) bool {
	return got == secretID || strings.HasSuffix(got, "/secrets/"+secretID)
}

// secretScope is the broadest grant that applies, plus every contributing
// grant. A project-level secretAccessor covers every secret in the project,
// including secrets that also have a per-secret binding.
func secretScope(secretID, sa string, secretIAM, projectIAM []planResource) (scope string, grants []string, cause string) {
	var scopes []string
	resourceCause, projectCause := "", ""
	for _, m := range secretIAM {
		sid, _ := m.values["secret_id"].(string)
		if secretMatch(sid, secretID) && memberIs(m.values["member"], sa) {
			scopes = append(scopes, "resource")
			resourceCause = m.address
		}
	}
	for _, m := range projectIAM {
		if m.values["role"] == "roles/secretmanager.secretAccessor" && memberIs(m.values["member"], sa) {
			scopes = append(scopes, "project")
			projectCause = m.address
		}
	}
	grants = normalizeAuthzGrants(scopes...)
	scope = effectiveAuthzScope(grants)
	switch scope {
	case "project":
		cause = projectCause
	case "resource":
		cause = resourceCause
	}
	return scope, grants, cause
}

func projectRole(members []planResource, role, sa string) string {
	for _, m := range members {
		if m.values["role"] == role && memberIs(m.values["member"], sa) {
			return m.address
		}
	}
	return ""
}

func saMatches(members []planResource, role, sa string) bool {
	for _, m := range members {
		if m.values["role"] == role && memberIs(m.values["member"], sa) {
			return true
		}
	}
	return false
}

func resolve(addr string, elements []*Element) (*Element, error) {
	if strings.HasPrefix(addr, "signal:") {
		hits, err := matchSignal(addr, elements)
		if err != nil {
			return nil, err
		}
		if len(hits) != 1 {
			return nil, fmt.Errorf("address %s matched %d elements", addr, len(hits))
		}
		return hits[0], nil
	}
	if strings.HasPrefix(addr, "declared:") {
		key := strings.TrimPrefix(addr, "declared:")
		for _, el := range elements {
			if el.Provenance == "declared" && el.Evidence.Key == key {
				return el, nil
			}
		}
		return nil, fmt.Errorf("unknown declared element %s", addr)
	}
	for _, el := range elements {
		if slices.Contains(el.Evidence.Addresses, addr) {
			return el, nil
		}
	}
	return nil, fmt.Errorf("unknown address %s", addr)
}

func resolveAll(addrs []string, elements []*Element) ([]*Element, error) {
	out := make([]*Element, len(addrs))
	for i, addr := range addrs {
		el, err := resolve(addr, elements)
		if err != nil {
			return nil, err
		}
		out[i] = el
	}
	return out, nil
}

func matchSignal(addr string, elements []*Element) ([]*Element, error) {
	rest := strings.TrimPrefix(addr, "signal:")
	typ, name, ok := strings.Cut(rest, ":")
	if !ok || typ == "" || name == "" {
		return nil, fmt.Errorf("signal %s", addr)
	}
	var hits []*Element
	for _, el := range elements {
		for _, s := range el.Evidence.Signals {
			if s.Type == typ && s.Name == name {
				hits = append(hits, el)
				break
			}
		}
	}
	return hits, nil
}
