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
	"google_folder_iam_audit_config":                 true,
	"google_organization_iam_audit_config":           true,
	"google_project_iam_member":                      true,
	"google_project_iam_binding":                     true,
	"google_project_iam_policy":                      true,
	"google_secret_manager_secret_iam_member":        true,
	"google_cloud_run_v2_service_iam_member":         true,
	"google_logging_project_sink":                    true,
	"google_logging_folder_sink":                     true,
	"google_logging_organization_sink":               true,
	"cloudflare_api_token":                           true,
	"cloudflare_account_token":                       true,
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
	"aws_eip_association":                                true,
	"aws_eks_cluster":                                    true,
	"aws_network_interface":                              true,
	"aws_iam_instance_profile":                           true,
	"aws_iam_policy":                                     true,
	"aws_iam_policy_attachment":                          true,
	"aws_iam_policy_document":                            true,
	"aws_iam_role":                                       true,
	"aws_iam_role_policies_exclusive":                    true,
	"aws_iam_role_policy":                                true,
	"aws_iam_role_policy_attachment":                     true,
	"aws_iam_role_policy_attachments_exclusive":          true,
	"aws_internet_gateway":                               true,
	"aws_launch_configuration":                           true,
	"aws_launch_template":                                true,
	"aws_lb_listener":                                    true,
	"aws_lb_target_group":                                true,
	"aws_nat_gateway":                                    true,
	"aws_route":                                          true,
	"aws_route_table":                                    true,
	"aws_route_table_association":                        true,
	"aws_kms_alias":                                      true,
	"aws_kms_key":                                        true,
	"aws_s3_bucket_logging":                              true,
	"aws_s3_bucket_ownership_controls":                   true,
	"aws_s3_bucket_public_access_block":                  true,
	"aws_s3_bucket_server_side_encryption_configuration": true,
	"aws_s3_bucket_versioning":                           true,
	"google_kms_crypto_key":                              true,
	"aws_secretsmanager_secret_rotation":                 true,
	"aws_secretsmanager_secret_version":                  true,
	"aws_ec2_managed_prefix_list":                        true,
	"aws_security_group":                                 true,
	"aws_security_group_rule":                            true,
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
	address      string
	typ          string
	values       map[string]any
	afterUnknown map[string]any // change.after_unknown; attribute → true when unknown after apply
	actions      []string       // change.actions; e.g. ["create"], ["update"], ["no-op"]
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
	Flows []frayFlowAnnotation `yaml:"flows"`
}

type frayFlowAnnotation struct {
	From       string `yaml:"from"`
	To         string `yaml:"to"`
	DataClass  string `yaml:"data_class"`
	AuthzScope string `yaml:"authz_scope"`
	Reason     string `yaml:"reason"`
}

// Parse builds a DFD from a terraform show -json plan and fray.yaml.
// declaredSource is the path recorded on declared elements. moduleDir is the
// Terraform root module; lifecycle.prevent_destroy is read from there because
// the plan JSON omits it. An empty moduleDir skips that read. Warnings are
// ambiguity: the parser emitted nothing for that decision.
func Parse(plan, config []byte, declaredSource string, src Source, moduleDir string) (DFD, []string, error) {
	// Defense in depth: blank Terraform-marked sensitive values before any
	// attribute or name is read into the DFD (Action and CLI share this path).
	stripped, _, err := StripSensitive(plan)
	if err != nil {
		return DFD{}, nil, fmt.Errorf("strip sensitive plan values: %w", err)
	}
	plan = stripped

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
		cloudSQL   []planResource
		invokers   []planResource
		secretIAM  []planResource
		projectIAM []planResource
		audits     []planResource
	)
	seenUnknown := map[string]bool{}
	for _, r := range resources {
		switch r.typ {
		case "google_cloud_run_v2_service", "google_cloud_run_service":
			services = append(services, r)
		case "google_secret_manager_secret":
			secrets = append(secrets, r)
		case "google_storage_bucket":
			gcs = append(gcs, r)
		case "cloudflare_r2_bucket":
			r2 = append(r2, r)
		case "google_sql_database_instance":
			cloudSQL = append(cloudSQL, r)
		case "google_cloud_run_v2_service_iam_member":
			invokers = append(invokers, r)
		case "google_secret_manager_secret_iam_member":
			secretIAM = append(secretIAM, r)
		case "google_project_iam_member", "google_project_iam_binding", "google_project_iam_policy":
			projectIAM = append(projectIAM, r)
		case "google_project_iam_audit_config",
			"google_folder_iam_audit_config",
			"google_organization_iam_audit_config":
			audits = append(audits, r)
		case "aws_lb", "aws_ecs_service", "aws_db_instance", "aws_rds_cluster", "aws_s3_bucket", "aws_secretsmanager_secret",
			"aws_api_gateway_rest_api", "aws_apigatewayv2_api", "aws_lambda_function", "aws_lambda_function_url",
			"aws_instance", "aws_autoscaling_group", "aws_eks_node_group":
			// Mapped in buildAWS. Not warned as unknown.
		case "cloudflare_r2_managed_domain", "cloudflare_r2_custom_domain":
			// Read later to decide whether a bucket is public. Not an element.
		case "cloudflare_r2_bucket_lock":
			// Read later for object_lock. Not an element.
		case "cloudflare_api_token", "cloudflare_account_token":
			// Policies feed R2 service→bucket authz_scope. Not an element.
		default:
			if ignoredTypes[r.typ] || seenUnknown[r.typ] {
				continue
			}
			seenUnknown[r.typ] = true
			warnings = append(warnings, "no mapping for "+r.address+"; skipped")
		}
	}

	// Positive DATA_READ coverage always emits true. Ownership only decides
	// missing evidence: owned_by_this_root → false; otherwise omit (unverified).
	owned := cfg.AuditConfig == "owned_by_this_root"
	secretAudit := auditLoggingPtr(auditDataRead(audits, "secretmanager.googleapis.com"), owned)
	storageAudit := auditLoggingPtr(auditDataRead(audits, "storage.googleapis.com"), owned)

	idx, err := indexConfig(plan)
	if err != nil {
		return DFD{}, warnings, err
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
		add(gcsElement(r, storageAudit, lifecycle.protected(r.address), idx))
	}
	for _, r := range r2 {
		add(r2Element(r, resources, idx, lifecycle.protected(r.address)))
	}
	for _, r := range cloudSQL {
		add(cloudSQLElement(r, lifecycle.protected(r.address)))
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

	attachedSQL := map[string]*Element{}
	attachedPostgres := map[string]*Element{}
	for _, svc := range services {
		inst := resolveExclusiveCloudSQL(svc, cloudSQL)
		if inst == nil {
			continue
		}
		el := findAddress(elements, inst.address)
		if el == nil {
			continue
		}
		attachedSQL[svc.address] = el
		if cloudSQLIsPostgres(*inst) {
			attachedPostgres[svc.address] = el
		}
	}

	// When every DATABASE_URL service attaches to exactly one Postgres Cloud SQL
	// instance, drop the inferred database — flows use the iac element instead.
	if db := databaseElement(secrets, services); db != nil && !suppressInferredDatabase(services, attachedPostgres) {
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

	applyPurpose(elements, resources, idx)

	if err := applyElementAnnotations(elements, cfg); err != nil {
		return DFD{}, warnings, err
	}

	flows := mechanicalFlows(services, secrets, r2, invokers, secretIAM, projectIAM, resources, elements, attachedSQL, idx, &warnings)
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
	if err := applyFlowAnnotations(flows, elements, cfg, declaredSource, &warnings); err != nil {
		return DFD{}, warnings, err
	}
	reconcileOmittedScopeWarnings(flows, &warnings)

	boundaries := mechanicalBoundaries(flows, elements, &warnings)
	boundaries = append(boundaries, awsBounds...)
	for _, b := range cfg.Boundaries {
		bound, err := declaredBoundary(b, elements)
		if err != nil {
			return DFD{}, warnings, err
		}
		boundaries = append(boundaries, bound)
	}
	sanitizeAttributes(elements)

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
				Actions      []string       `json:"actions"`
				After        map[string]any `json:"after"`
				AfterUnknown map[string]any `json:"after_unknown"`
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
		out = append(out, planResource{
			address:      r.Address,
			typ:          r.Type,
			values:       r.Change.After,
			afterUnknown: r.Change.AfterUnknown,
			actions:      r.Change.Actions,
		})
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
	if r.typ == "google_cloud_run_service" {
		return cloudRunV1Element(r, invokers, prevent)
	}
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

// cloudRunV1Element maps google_cloud_run_service. Attribute coverage is
// thinner than v2; Cloud SQL attachment uses the revision annotation.
func cloudRunV1Element(r planResource, invokers []planResource, prevent bool) (*Element, []string) {
	attrs := map[string]any{}
	name, _ := r.values["name"].(string)
	if loc, ok := r.values["location"].(string); ok && regionPattern.MatchString(loc) {
		attrs["region"] = loc
	}
	setDeletionProtection(attrs, r.values, prevent)
	if publicInvoker(r, invokers) {
		attrs["public"] = true
	}
	return &Element{
		Name: DisplayName(r.address, name, "container_service"), Type: "process", Kind: "container_service", Provider: "gcp",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}, nil
}

// suppressInferredDatabase is true when at least one service has DATABASE_URL
// and every such service attaches to exactly one Postgres Cloud SQL instance.
func suppressInferredDatabase(services []planResource, attachedPostgres map[string]*Element) bool {
	any := false
	for _, svc := range services {
		if !hasEnv(svc, "DATABASE_URL") {
			continue
		}
		any = true
		if attachedPostgres[svc.address] == nil {
			return false
		}
	}
	return any
}

func secretElement(r planResource, audit *bool, prevent bool) *Element {
	name, _ := r.values["secret_id"].(string)
	attrs := map[string]any{
		"rotation_configured": rotationOn(r.values["rotation"]),
	}
	if audit != nil {
		attrs["audit_logging"] = *audit
	}
	setDeletionProtection(attrs, r.values, prevent)
	return &Element{
		Name: DisplayName(r.address, name, "secret_store"), Type: "datastore", Kind: "secret_store", Provider: "gcp",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
}

func gcsElement(r planResource, audit *bool, prevent bool, idx configIndex) *Element {
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
	if cmk, ok := gcsCustomerManagedKey(r, idx); ok {
		attrs["customer_managed_key"] = cmk
	}
	return &Element{
		Name: DisplayName(r.address, name, "object_storage"), Type: "datastore", Kind: "object_storage", Provider: "gcp",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
}

func r2Element(r planResource, resources []planResource, idx configIndex, prevent bool) *Element {
	name, _ := r.values["name"].(string)
	attrs := map[string]any{
		"acls_disabled": true,
		// R2 Data Access Logs are enabled per bucket in the dashboard and have
		// no Terraform resource in the Cloudflare v5 provider, so the plan
		// cannot show them — omit (FR-023 unverified) rather than false.
		"encrypted_at_rest": true, // R2 always encrypts objects at rest
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
	if locked, known, cause := r2ObjectLock(r, resources, idx); known {
		attrs["object_lock"] = locked
		if cause != "" {
			causes["object_lock"] = cause
		}
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

// r2ObjectLock reports whole-bucket retention from matching
// cloudflare_r2_bucket_lock resources.
//
//	true  — enabled rule, prefix absent/"", Indefinite or Age with max_age_seconds>0
//	false — matching lock with rules empty/absent
//	absent — no matching lock, prefix-only, disabled-only, Date-only, Age<=0, unresolved ref
func r2ObjectLock(bucket planResource, resources []planResource, idx configIndex) (locked, known bool, cause string) {
	var matched []planResource
	for _, r := range resources {
		if r.typ != "cloudflare_r2_bucket_lock" {
			continue
		}
		if r2LockMatchesBucket(r, bucket, idx) {
			matched = append(matched, r)
		}
	}
	if len(matched) == 0 {
		return false, false, ""
	}
	emptyRulesOnly := true
	for _, lock := range matched {
		rules := asList(lock.values["rules"])
		if len(rules) > 0 {
			emptyRulesOnly = false
		}
		for _, rule := range rules {
			rm, ok := rule.(map[string]any)
			if !ok {
				continue
			}
			if r2WholeBucketRetention(rm) {
				return true, true, lock.address
			}
		}
	}
	if emptyRulesOnly {
		return false, true, matched[0].address
	}
	return false, false, ""
}

func r2Jurisdiction(v any) string {
	s, _ := v.(string)
	if s == "" {
		return "default"
	}
	return s
}

func r2LockMatchesBucket(lock, bucket planResource, idx configIndex) bool {
	lockAcct, _ := lock.values["account_id"].(string)
	buckAcct, _ := bucket.values["account_id"].(string)
	if lockAcct != buckAcct {
		return false
	}
	if r2Jurisdiction(lock.values["jurisdiction"]) != r2Jurisdiction(bucket.values["jurisdiction"]) {
		return false
	}
	lockName, _ := lock.values["bucket_name"].(string)
	buckName, _ := bucket.values["name"].(string)
	if lockName != "" && buckName != "" && lockName == buckName {
		return true
	}
	_, _, bName, ok := splitResourceAddress(bucket.address)
	if !ok {
		return false
	}
	refs := idx.attrRefs(lock.address, "bucket_name")
	if len(refs) == 0 {
		return false
	}
	for _, ref := range refs {
		if containsResource(ref, "cloudflare_r2_bucket", bName) {
			return true
		}
	}
	return false
}

func r2WholeBucketRetention(rule map[string]any) bool {
	if rule["enabled"] != true {
		return false
	}
	if prefix, ok := rule["prefix"].(string); ok && prefix != "" {
		return false
	}
	var cond map[string]any
	switch c := rule["condition"].(type) {
	case map[string]any:
		cond = c
	case []any:
		if len(c) > 0 {
			cond, _ = c[0].(map[string]any)
		}
	}
	if cond == nil {
		return false
	}
	switch typ, _ := cond["type"].(string); typ {
	case "Indefinite":
		return true
	case "Age":
		n, ok := number(cond["max_age_seconds"])
		return ok && n > 0
	default:
		return false
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
},
) {
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

// serviceVolumeSecrets returns Secret Manager secret ids from
// template.volumes[].secret that at least one container mounts. Declared but
// unmounted volumes are ignored (no delivery).
func serviceVolumeSecrets(r planResource) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range asList(r.values["template"]) {
		tm, ok := t.(map[string]any)
		if !ok {
			continue
		}
		mounted := map[string]bool{}
		for _, c := range asList(tm["containers"]) {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			for _, vm := range asList(cm["volume_mounts"]) {
				m, ok := vm.(map[string]any)
				if !ok {
					continue
				}
				if name, _ := m["name"].(string); name != "" {
					mounted[name] = true
				}
			}
		}
		for _, v := range asList(tm["volumes"]) {
			vm, ok := v.(map[string]any)
			if !ok {
				continue
			}
			volName, _ := vm["name"].(string)
			if volName == "" || !mounted[volName] {
				continue
			}
			for _, s := range asList(vm["secret"]) {
				sm, ok := s.(map[string]any)
				if !ok {
					continue
				}
				id, _ := sm["secret"].(string)
				if id == "" || seen[id] {
					continue
				}
				seen[id] = true
				out = append(out, id)
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

func mechanicalFlows(services, secrets, r2buckets, invokers, secretIAM, projectIAM, allResources []planResource, elements []*Element, attachedSQL map[string]*Element, idx configIndex, warnings *[]string) []*Flow {
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
		// Per (service, secret): volume only when every delivery of that secret
		// to this service is a mounted volume. Env anywhere → env (FR-003 open).
		type secretDelivery struct {
			el     *Element
			id     string
			hasEnv bool
			hasVol bool
		}
		bySecret := map[string]*secretDelivery{} // secret element canonical key
		resolveSecret := func(id, warnPrefix string) (*Element, string) {
			sec := secretByID[id]
			if sec == nil {
				for sid, el := range secretByID {
					if secretMatch(id, sid) {
						return el, sid
					}
				}
				*warnings = append(*warnings, warnPrefix+id+" on "+svc.address+" with no element")
				return nil, ""
			}
			return sec, id
		}
		for _, env := range serviceEnvs(svc) {
			if env.secret == "" {
				continue
			}
			sec, id := resolveSecret(env.secret, "env "+env.name+" references secret ")
			if sec == nil {
				continue
			}
			d := bySecret[sec.canonicalKey()]
			if d == nil {
				d = &secretDelivery{el: sec, id: id}
				bySecret[sec.canonicalKey()] = d
			}
			d.hasEnv = true
		}
		for _, id := range serviceVolumeSecrets(svc) {
			sec, sid := resolveSecret(id, "volume secret ")
			if sec == nil {
				continue
			}
			d := bySecret[sec.canonicalKey()]
			if d == nil {
				d = &secretDelivery{el: sec, id: sid}
				bySecret[sec.canonicalKey()] = d
			}
			d.hasVol = true
		}
		for _, d := range bySecret {
			delivery := "volume"
			if d.hasEnv {
				delivery = "env"
			} else if !d.hasVol {
				continue
			}
			flow := &Flow{
				From: secTemp(d.el), To: secTemp(svcEl),
				DataClass: "credentials", Transport: "local", SecretDelivery: delivery,
				Causes: map[string]string{"secret_delivery": svc.address},
			}
			if scope, grants, cause := secretScope(d.id, sa, secretIAM, projectIAM); scope != "" {
				flow.AuthzScope = scope
				flow.AuthzGrants = grants
				if cause != "" {
					flow.Causes["authz_scope"] = cause
				}
			}
			flows = append(flows, flow)
		}
		// Cloud SQL connector/proxy attachment wins over inferred DATABASE_URL.
		if sqlEl := attachedSQL[svc.address]; sqlEl != nil {
			flow := &Flow{
				From: secTemp(svcEl), To: secTemp(sqlEl),
				DataClass: "unknown", Transport: "tls",
			}
			if sqlRes, ok := planResourceByElement(sqlEl, allResources); ok {
				if scope, grants, cause := cloudSQLScope(sa, sqlRes, projectIAM, idx); scope != "" {
					flow.AuthzScope = scope
					flow.AuthzGrants = grants
					if cause != "" {
						flow.Causes = map[string]string{"authz_scope": cause}
					}
				}
			}
			flows = append(flows, flow)
		} else if db != nil && hasEnv(svc, "DATABASE_URL") {
			// Inferred DATABASE_URL Postgres: omit authz_scope (no IAM signal).
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
				flow := &Flow{
					From: secTemp(svcEl), To: secTemp(r2el),
					DataClass: "unknown", Transport: "tls",
				}
				if scope, grants, cause, ok := r2TokenAuthz(allResources); ok {
					flow.AuthzScope = scope
					flow.AuthzGrants = grants
					if cause != "" {
						flow.Causes = map[string]string{"authz_scope": cause}
					}
				} else {
					*warnings = append(*warnings, "R2 key envs on "+svc.address+" but no cloudflare_api_token in plan; authz_scope omitted")
				}
				flows = append(flows, flow)
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

func applyFlowAnnotations(flows []*Flow, elements []*Element, cfg frayConfig, declaredSource string, warnings *[]string) error {
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
		if ann.AuthzScope != "" {
			if err := fillAuthzScope(flows, ann, fk, tk, declaredSource, warnings); err != nil {
				return err
			}
			continue
		}
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

// fillAuthzScope sets authz_scope only when the parser omitted it. data_class,
// when set, selects the parser flow and must already equal that flow's class.
// A derived scope, or a match count other than one, is skipped with a warning.
func fillAuthzScope(flows []*Flow, ann frayFlowAnnotation, fromKey, toKey, declaredSource string, warnings *[]string) error {
	switch ann.AuthzScope {
	case "resource", "project", "account", "organization":
	default:
		return fmt.Errorf("fray.yaml annotation authz_scope %q on %s -> %s", ann.AuthzScope, ann.From, ann.To)
	}
	if len(strings.TrimSpace(ann.Reason)) < 10 {
		return fmt.Errorf("fray.yaml annotation authz_scope on %s -> %s requires reason of at least 10 characters", ann.From, ann.To)
	}
	var hits []*Flow
	for _, f := range flows {
		if f.From != fromKey || f.To != toKey {
			continue
		}
		if ann.DataClass != "" && f.DataClass != ann.DataClass {
			continue
		}
		hits = append(hits, f)
	}
	if len(hits) != 1 {
		*warnings = append(*warnings, scopeAnnotationIgnored(ann, len(hits)))
		return nil
	}
	f := hits[0]
	if f.AuthzScope != "" {
		*warnings = append(*warnings, fmt.Sprintf("fray.yaml annotation ignored: %s -> %s already has derived authz_scope %s; remove the annotation, or use .fray/waivers.yml to accept a wider grant", ann.From, ann.To, f.AuthzScope))
		return nil
	}
	f.AuthzScope = ann.AuthzScope
	f.AuthzGrants = normalizeAuthzGrants(ann.AuthzScope)
	if f.Causes == nil {
		f.Causes = map[string]string{}
	}
	f.Causes["authz_scope"] = ReportConfigPath(declaredSource) + "#" + ann.From + " -> " + ann.To + " " + f.DataClass
	return nil
}

const (
	omittedScopeWarnPrefix  = "authz_scope omitted for "
	omittedScopeDeclareHint = "; declare it with fray.yaml annotations.flows authz_scope"
)

// reconcileOmittedScopeWarnings drops an "authz_scope omitted for <role>"
// warning when every flow stamped with that role was filled from fray.yaml.
// If any of that role's flows are still unfilled, the warning stays and names
// the annotation that would fill it.
func reconcileOmittedScopeWarnings(flows []*Flow, warnings *[]string) {
	if warnings == nil || len(*warnings) == 0 {
		return
	}
	var kept []string
	for _, w := range *warnings {
		if !strings.HasPrefix(w, omittedScopeWarnPrefix) {
			kept = append(kept, w)
			continue
		}
		rest := strings.TrimPrefix(w, omittedScopeWarnPrefix)
		role, _, _ := strings.Cut(rest, ": ")
		var mine []*Flow
		for _, f := range flows {
			if f.Causes["authz_scope_omitted_for"] == role {
				mine = append(mine, f)
			}
		}
		if len(mine) == 0 {
			kept = append(kept, w)
			continue
		}
		allFilled := true
		for _, f := range mine {
			if f.AuthzScope == "" {
				allFilled = false
				break
			}
		}
		if allFilled {
			continue
		}
		if !strings.Contains(w, omittedScopeDeclareHint) {
			w += omittedScopeDeclareHint
		}
		kept = append(kept, w)
	}
	*warnings = kept
}

func scopeAnnotationIgnored(ann frayFlowAnnotation, n int) string {
	label := ann.From + " -> " + ann.To
	if ann.DataClass != "" {
		label += " " + ann.DataClass
	}
	if n == 0 {
		return fmt.Sprintf("fray.yaml annotation ignored: %s matched no parser flow; set data_class to disambiguate, or declare a new flow under flows", label)
	}
	return fmt.Sprintf("fray.yaml annotation ignored: %s matched %d flows; set data_class to disambiguate, or declare a new flow under flows", label, n)
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

// auditDataRead reports whether a GCP IAM audit config covers DATA_READ for
// service. A config matches when its service equals the target or
// "allServices". Project, folder, and organization audit configs are all
// considered. exempted_members do not negate coverage.
func auditDataRead(audits []planResource, service string) bool {
	for _, a := range audits {
		svc, _ := a.values["service"].(string)
		if svc != service && svc != "allServices" {
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

// auditLoggingPtr returns attributes.audit_logging when it should be set.
// covered (positive evidence in the plan) → true regardless of ownership.
// Not covered + owned_by_this_root → false. Not covered + not owned → nil (omit).
func auditLoggingPtr(covered, owned bool) *bool {
	if covered {
		t := true
		return &t
	}
	if owned {
		f := false
		return &f
	}
	return nil
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

var cloudSQLIAMRoles = map[string]bool{
	"roles/cloudsql.client":       true,
	"roles/cloudsql.instanceUser": true,
	"roles/cloudsql.admin":        true,
}

// cloudSQLScope classifies project IAM grants for Cloud Run → Cloud SQL.
// Unconditional binding → project; IAM Condition on this instance → resource;
// other/unparseable conditions or different instance → omit that binding.
func cloudSQLScope(sa string, sqlRes planResource, projectIAM []planResource, idx configIndex) (scope string, grants []string, cause string) {
	if sa == "" {
		return "", nil, ""
	}
	instName, _ := sqlRes.values["name"].(string)
	var scopes []string
	resourceCause, projectCause := "", ""
	for _, m := range expandProjectIAM(projectIAM) {
		role, _ := m.values["role"].(string)
		if !cloudSQLIAMRoles[role] {
			continue
		}
		if !projectIAMMemberMatches(m, sa) {
			continue
		}
		if !iamConditionBlockPresent(m, idx) {
			// Truly unconditional: no condition in after, config, or after_unknown.
			scopes = append(scopes, "project")
			projectCause = m.address
			continue
		}
		// Condition block exists. Prefer config refs to this instance when the
		// expression is unknown; otherwise parse the expression or omit.
		if condRefsThisInstance(m, sqlRes, idx) {
			scopes = append(scopes, "resource")
			resourceCause = m.address
			continue
		}
		expr := iamConditionExpression(m)
		if expr == "" {
			continue // condition present but unreadable → omit
		}
		match, ok := cloudSQLConditionMatches(expr, instName, sqlRes)
		if !ok {
			continue // unparseable
		}
		if match {
			scopes = append(scopes, "resource")
			resourceCause = m.address
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

// expandProjectIAM flattens google_project_iam_policy policy_data into
// synthetic member-shaped resources; member/binding pass through.
func expandProjectIAM(in []planResource) []planResource {
	var out []planResource
	for _, m := range in {
		switch m.typ {
		case "google_project_iam_policy":
			out = append(out, projectIAMFromPolicyData(m)...)
		default:
			out = append(out, m)
		}
	}
	return out
}

func projectIAMFromPolicyData(pol planResource) []planResource {
	raw, _ := pol.values["policy_data"].(string)
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var doc struct {
		Bindings []struct {
			Role      string         `json:"role"`
			Members   []string       `json:"members"`
			Condition map[string]any `json:"condition"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil
	}
	var out []planResource
	for i, b := range doc.Bindings {
		vals := map[string]any{"role": b.Role, "members": anyStrings(b.Members)}
		if len(b.Condition) > 0 {
			vals["condition"] = b.Condition
		}
		out = append(out, planResource{
			address: fmt.Sprintf("%s#binding[%d]", pol.address, i),
			typ:     "google_project_iam_binding",
			values:  vals,
		})
	}
	return out
}

func anyStrings(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func projectIAMMemberMatches(m planResource, sa string) bool {
	if memberIs(m.values["member"], sa) {
		return true
	}
	for _, mem := range asList(m.values["members"]) {
		if memberIs(mem, sa) {
			return true
		}
	}
	return false
}

func iamConditionExpression(m planResource) string {
	switch c := m.values["condition"].(type) {
	case map[string]any:
		s, _ := c["expression"].(string)
		return strings.TrimSpace(s)
	case []any:
		if len(c) == 0 {
			return ""
		}
		if cm, ok := c[0].(map[string]any); ok {
			s, _ := cm["expression"].(string)
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// iamConditionBlockPresent reports a condition block in after values, config
// expressions/refs, or after_unknown — including empty expression / unknown.
// An empty condition list or absent condition is not present.
func iamConditionBlockPresent(m planResource, idx configIndex) bool {
	if attrUnknownMap(m.afterUnknown, "condition") {
		return true
	}
	switch c := m.values["condition"].(type) {
	case map[string]any:
		if len(c) > 0 {
			return true
		}
	case []any:
		if len(c) > 0 {
			return true
		}
	}
	if hasConfigAttr(idx, m.address, "condition") {
		return true
	}
	key, ok := resourceKey(m.address)
	if !ok {
		return false
	}
	set := idx.resources[key]
	for attr := range set.raw {
		if attr == "condition" || strings.HasPrefix(attr, "condition.") {
			return true
		}
	}
	for attr := range set.refs {
		if attr == "condition" || strings.HasPrefix(attr, "condition.") {
			return true
		}
	}
	return false
}

var (
	cloudSQLCondNameRe = regexp.MustCompile(`resource\.name\s*==\s*"projects/[^"]+/instances/([^"]+)"`)
	cloudSQLCondTypeRe = regexp.MustCompile(`resource\.type\s*==\s*"sqladmin\.googleapis\.com/Instance"`)
	cloudSQLCondSvcRe  = regexp.MustCompile(`resource\.service\s*==\s*"sqladmin\.googleapis\.com"`)
)

// cloudSQLConditionMatches reports whether expr scopes to this instance.
// ok=false means unparseable (omit). ok=true && match=false means another instance.
func cloudSQLConditionMatches(expr, instName string, sqlRes planResource) (match, ok bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return false, false
	}
	// Split on && and require every clause to be known.
	parts := strings.Split(expr, "&&")
	var named string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return false, false
		}
		if m := cloudSQLCondNameRe.FindStringSubmatch(p); m != nil {
			named = m[1]
			continue
		}
		if cloudSQLCondTypeRe.MatchString(p) || cloudSQLCondSvcRe.MatchString(p) {
			continue
		}
		return false, false // unknown clause
	}
	if named == "" {
		return false, false
	}
	if instName != "" && named == instName {
		return true, true
	}
	// Literal name may equal a referenced instance when values.name is set.
	if v, ok := sqlRes.values["name"].(string); ok && v == named {
		return true, true
	}
	return false, true
}

func condRefsThisInstance(m, sqlRes planResource, idx configIndex) bool {
	_, typ, name, ok := splitResourceAddress(sqlRes.address)
	if !ok || typ != "google_sql_database_instance" {
		return false
	}
	for _, attr := range []string{"condition", "condition.expression"} {
		for _, ref := range idx.attrRefs(m.address, attr) {
			if containsResource(ref, typ, name) && (strings.Contains(ref, ".name") || strings.HasSuffix(ref, typ+"."+name)) {
				return true
			}
		}
	}
	// Nested under condition map — also check all attrs that mention condition.
	key, ok := resourceKey(m.address)
	if !ok {
		return false
	}
	for attr, refs := range idx.resources[key].refs {
		if !strings.Contains(attr, "condition") {
			continue
		}
		for _, ref := range refs {
			if containsResource(ref, typ, name) {
				return true
			}
		}
	}
	return false
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
