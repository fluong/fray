package client

import (
	"strings"
)

// cloudSQLElement maps google_sql_database_instance → relational_db (provider gcp).
//
// encrypted_at_rest is always true: Google encrypts Cloud SQL data at rest by
// default; CMEK via encryption_key_name is optional and does not change that.
func cloudSQLElement(r planResource, prevent bool) *Element {
	name, _ := r.values["name"].(string)
	attrs := map[string]any{
		"encrypted_at_rest": true,
	}
	if public, ok := cloudSQLPublic(r); ok {
		attrs["public"] = public
	}
	if restricted, ok := cloudSQLNetworkRestricted(r); ok {
		attrs["network_restricted"] = restricted
	}
	if tls, ok := cloudSQLTLSEnforced(r); ok {
		attrs["tls_enforced"] = tls
	}
	if dp, ok := cloudSQLDeletionProtection(r, prevent); ok {
		attrs["deletion_protection"] = dp
	}
	return &Element{
		Name: DisplayName(r.address, name, "relational_db"), Type: "datastore", Kind: "relational_db", Provider: "gcp",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
}

func cloudSQLPublic(r planResource) (public bool, known bool) {
	ip := cloudSQLIPConfig(r)
	if ip == nil {
		if cloudSQLIPConfigUnknown(r, "ipv4_enabled") {
			return false, false
		}
		return false, false
	}
	if cloudSQLIPConfigUnknown(r, "ipv4_enabled") {
		return false, false
	}
	v, ok := ip["ipv4_enabled"].(bool)
	if !ok {
		return false, false
	}
	return v, true
}

// cloudSQLNetworkRestricted is set only when ipv4_enabled is known true.
// No authorized_networks → true (connectors/IAM only). Any world CIDR → false.
// All narrower/private → true. Any unknown value → omit.
func cloudSQLNetworkRestricted(r planResource) (restricted bool, known bool) {
	ip := cloudSQLIPConfig(r)
	if ip == nil {
		return false, false
	}
	if cloudSQLIPConfigUnknown(r, "ipv4_enabled") {
		return false, false
	}
	ipv4, ok := ip["ipv4_enabled"].(bool)
	if !ok || !ipv4 {
		return false, false
	}
	if cloudSQLIPConfigUnknown(r, "authorized_networks") {
		return false, false
	}
	networks := asList(ip["authorized_networks"])
	if len(networks) == 0 {
		return true, true
	}
	sawWorld := false
	for _, n := range networks {
		nm, ok := n.(map[string]any)
		if !ok {
			return false, false
		}
		val, ok := nm["value"].(string)
		if !ok {
			return false, false
		}
		switch classifyCIDR(val) {
		case netSrcWorld:
			sawWorld = true
		case netSrcUnknown:
			return false, false
		}
	}
	return !sawWorld, true
}

func cloudSQLTLSEnforced(r planResource) (enforced bool, known bool) {
	ip := cloudSQLIPConfig(r)
	if ip == nil {
		return false, false
	}
	sslUnknown := cloudSQLIPConfigUnknown(r, "ssl_mode")
	reqUnknown := cloudSQLIPConfigUnknown(r, "require_ssl")
	sslMode, hasSSL := ip["ssl_mode"].(string)
	if sslUnknown {
		hasSSL = false
		sslMode = ""
	}
	if hasSSL && sslMode != "" {
		switch sslMode {
		case "ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED":
			return true, true
		case "ALLOW_UNENCRYPTED_AND_ENCRYPTED":
			return false, true
		default:
			return false, false
		}
	}
	if reqUnknown {
		return false, false
	}
	if req, ok := ip["require_ssl"].(bool); ok {
		if req {
			return true, true
		}
		// require_ssl=false alone is not a documented default we assume; omit
		// unless ssl_mode also spoke (handled above).
		return false, false
	}
	return false, false
}

// cloudSQLDeletionProtection: true if Terraform deletion_protection,
// settings.deletion_protection_enabled, or lifecycle.prevent_destroy is true;
// false when every present flag is false and prevent_destroy is absent;
// omit when any relevant value is unknown and none is true.
func cloudSQLDeletionProtection(r planResource, prevent bool) (protected bool, known bool) {
	if prevent {
		return true, true
	}
	var sawFalse bool
	unknown := false

	if attrUnknownMap(r.afterUnknown, "deletion_protection") {
		unknown = true
	} else if v, ok := r.values["deletion_protection"].(bool); ok {
		if v {
			return true, true
		}
		sawFalse = true
	}

	settings := cloudSQLSettings(r)
	if settings != nil {
		if cloudSQLSettingsUnknown(r, "deletion_protection_enabled") {
			unknown = true
		} else if v, ok := settings["deletion_protection_enabled"].(bool); ok {
			if v {
				return true, true
			}
			sawFalse = true
		}
	} else if cloudSQLSettingsUnknown(r, "deletion_protection_enabled") {
		unknown = true
	}

	if unknown {
		return false, false
	}
	if sawFalse {
		return false, true
	}
	// Nothing present → treat as unprotected only when Terraform wrote false
	// defaults; with no evidence, omit.
	return false, false
}

func cloudSQLSettings(r planResource) map[string]any {
	for _, s := range asList(r.values["settings"]) {
		if m, ok := s.(map[string]any); ok {
			return m
		}
	}
	return nil
}

func cloudSQLIPConfig(r planResource) map[string]any {
	settings := cloudSQLSettings(r)
	if settings == nil {
		return nil
	}
	for _, ip := range asList(settings["ip_configuration"]) {
		if m, ok := ip.(map[string]any); ok {
			return m
		}
	}
	return nil
}

func cloudSQLSettingsUnknown(r planResource, attr string) bool {
	u := r.afterUnknown["settings"]
	switch t := u.(type) {
	case bool:
		return t
	case []any:
		for _, item := range t {
			m, ok := item.(map[string]any)
			if !ok {
				if b, isBool := item.(bool); isBool && b {
					return true
				}
				continue
			}
			if attrUnknownMap(m, attr) {
				return true
			}
		}
	case map[string]any:
		return attrUnknownMap(t, attr)
	}
	return false
}

func cloudSQLIPConfigUnknown(r planResource, attr string) bool {
	u := r.afterUnknown["settings"]
	switch t := u.(type) {
	case bool:
		return t
	case []any:
		for _, item := range t {
			sm, ok := item.(map[string]any)
			if !ok {
				if b, isBool := item.(bool); isBool && b {
					return true
				}
				continue
			}
			ipU, ok := sm["ip_configuration"]
			if !ok {
				continue
			}
			switch ip := ipU.(type) {
			case bool:
				if ip {
					return true
				}
			case []any:
				for _, ipItem := range ip {
					im, ok := ipItem.(map[string]any)
					if !ok {
						if b, isBool := ipItem.(bool); isBool && b {
							return true
						}
						continue
					}
					if attrUnknownMap(im, attr) {
						return true
					}
				}
			case map[string]any:
				if attrUnknownMap(ip, attr) {
					return true
				}
			}
		}
	case map[string]any:
		return cloudSQLIPConfigUnknown(planResource{afterUnknown: map[string]any{"settings": []any{t}}}, attr)
	}
	return false
}

func cloudSQLConnectionName(r planResource) string {
	if s, ok := r.values["connection_name"].(string); ok && s != "" {
		return s
	}
	project, _ := r.values["project"].(string)
	region, _ := r.values["region"].(string)
	name, _ := r.values["name"].(string)
	if project != "" && region != "" && name != "" {
		return project + ":" + region + ":" + name
	}
	return ""
}

func cloudSQLIsPostgres(r planResource) bool {
	v, _ := r.values["database_version"].(string)
	return strings.HasPrefix(v, "POSTGRES")
}

// cloudSQLAttachments returns connection names declared on a Cloud Run service
// (v2 cloud_sql_instance volumes or v1 run.googleapis.com/cloudsql-instances).
func cloudSQLAttachments(svc planResource) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	switch svc.typ {
	case "google_cloud_run_v2_service":
		for _, t := range asList(svc.values["template"]) {
			tm, ok := t.(map[string]any)
			if !ok {
				continue
			}
			for _, v := range asList(tm["volumes"]) {
				vm, ok := v.(map[string]any)
				if !ok {
					continue
				}
				for _, csi := range asList(vm["cloud_sql_instance"]) {
					cm, ok := csi.(map[string]any)
					if !ok {
						continue
					}
					for _, inst := range asList(cm["instances"]) {
						if s, ok := inst.(string); ok {
							add(s)
						}
					}
				}
			}
		}
	case "google_cloud_run_service":
		for _, ann := range cloudRunV1Annotations(svc) {
			if v := ann["run.googleapis.com/cloudsql-instances"]; v != "" {
				for _, part := range strings.Split(v, ",") {
					add(part)
				}
			}
		}
	}
	return out
}

func cloudRunV1Annotations(svc planResource) []map[string]string {
	var out []map[string]string
	collect := func(meta any) {
		for _, m := range asList(meta) {
			mm, ok := m.(map[string]any)
			if !ok {
				continue
			}
			raw, ok := mm["annotations"].(map[string]any)
			if !ok {
				continue
			}
			ann := map[string]string{}
			for k, v := range raw {
				if s, ok := v.(string); ok {
					ann[k] = s
				}
			}
			if len(ann) > 0 {
				out = append(out, ann)
			}
		}
	}
	collect(svc.values["metadata"])
	for _, t := range asList(svc.values["template"]) {
		tm, ok := t.(map[string]any)
		if !ok {
			continue
		}
		collect(tm["metadata"])
	}
	return out
}

// resolveExclusiveCloudSQL returns the single plan instance named by the
// service's Cloud SQL attachments, or nil when zero or multiple match.
func resolveExclusiveCloudSQL(svc planResource, instances []planResource) *planResource {
	conns := cloudSQLAttachments(svc)
	if len(conns) == 0 {
		return nil
	}
	var matched []planResource
	seen := map[string]bool{}
	for _, c := range conns {
		for _, inst := range instances {
			if !cloudSQLMatchesConnection(inst, c) {
				continue
			}
			if seen[inst.address] {
				continue
			}
			seen[inst.address] = true
			matched = append(matched, inst)
		}
	}
	if len(matched) != 1 {
		return nil
	}
	return &matched[0]
}

func cloudSQLMatchesConnection(r planResource, conn string) bool {
	conn = strings.TrimSpace(conn)
	if conn == "" {
		return false
	}
	if cn := cloudSQLConnectionName(r); cn != "" && cn == conn {
		return true
	}
	name, _ := r.values["name"].(string)
	return name != "" && name == conn
}
