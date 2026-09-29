package client

import "strings"

// Purpose values are the closed dfd/v1 enum. Only these may appear on the wire.
var Purposes = []string{
	"audit_archive",
	"customer_uploads",
	"backups",
	"static_assets",
	"logs",
	"secrets",
	"app_data",
	"internal_api",
	"public_api",
	"other",
}

// PurposeSource values record how purpose was set (evidence.purpose_source).
const (
	PurposeSourceType     = "type"
	PurposeSourceRelation = "relation"
	PurposeSourceDeclared = "declared"
)

// ValidPurpose reports whether p is a dfd/v1 purpose enum value.
func ValidPurpose(p string) bool {
	for _, v := range Purposes {
		if p == v {
			return true
		}
	}
	return false
}

func validPurposeSource(s string) bool {
	switch s {
	case PurposeSourceType, PurposeSourceRelation, PurposeSourceDeclared:
		return true
	default:
		return false
	}
}

// setPurpose sets purpose and its evidence provenance when unset, or when
// force is true (declared annotations overwrite). Relation may upgrade logs →
// audit_archive when a CloudTrail target is also an access-log target.
func setPurpose(el *Element, purpose, source string, force bool) {
	if purpose == "" || !ValidPurpose(purpose) || !validPurposeSource(source) {
		return
	}
	if el.Purpose != "" && !force {
		// CloudTrail audit_archive wins over a prior logs relation.
		if el.Purpose == "logs" && purpose == "audit_archive" && source == PurposeSourceRelation {
			el.Purpose = purpose
			el.Evidence.PurposeSource = source
		}
		return
	}
	el.Purpose = purpose
	el.Evidence.PurposeSource = source
}

// applyPurposeFromType sets purpose from resource kind (secret managers only).
func applyPurposeFromType(elements []*Element) {
	for _, el := range elements {
		if el.Purpose != "" {
			continue
		}
		if el.Kind == "secret_store" {
			setPurpose(el, "secrets", PurposeSourceType, false)
		}
	}
}

// applyPurposeFromRelations sets purpose from plan relationships:
// CloudTrail s3_bucket_name → audit_archive; S3 server-access-logging
// target_bucket → logs; GCS logging sink destination → logs.
func applyPurposeFromRelations(elements []*Element, resources []planResource, idx configIndex) {
	byAddr := map[string]*Element{}
	byBucketName := map[string]*Element{}
	for _, el := range elements {
		for _, a := range el.Evidence.Addresses {
			byAddr[a] = el
		}
	}
	// Index object_storage elements by plan bucket/name values for string refs.
	for _, r := range resources {
		el, ok := byAddr[r.address]
		if !ok || el.Kind != "object_storage" {
			continue
		}
		for _, key := range []string{"bucket", "bucket_prefix", "name"} {
			if n, _ := r.values[key].(string); n != "" {
				byBucketName[n] = el
			}
		}
	}

	resolveBucket := func(refs []string, name string) *Element {
		for _, ref := range refs {
			for addr, el := range byAddr {
				if el.Kind != "object_storage" {
					continue
				}
				if containsResource(ref, "aws_s3_bucket", localTypeName(addr)) ||
					containsResource(ref, "google_storage_bucket", localTypeName(addr)) {
					return el
				}
			}
		}
		if name != "" {
			return byBucketName[name]
		}
		return nil
	}

	for _, r := range resources {
		switch r.typ {
		case "aws_cloudtrail":
			name, _ := r.values["s3_bucket_name"].(string)
			el := resolveBucket(idx.attrRefs(r.address, "s3_bucket_name"), name)
			if el != nil {
				setPurpose(el, "audit_archive", PurposeSourceRelation, false)
			}
		case "aws_s3_bucket_logging":
			name, _ := r.values["target_bucket"].(string)
			el := resolveBucket(idx.attrRefs(r.address, "target_bucket"), name)
			if el != nil {
				setPurpose(el, "logs", PurposeSourceRelation, false)
			}
		case "google_logging_project_sink", "google_logging_folder_sink", "google_logging_organization_sink":
			dest, _ := r.values["destination"].(string)
			if el := gcsSinkDestination(dest, byAddr, byBucketName); el != nil {
				setPurpose(el, "logs", PurposeSourceRelation, false)
			}
		}
	}
}

func gcsSinkDestination(dest string, byAddr, byBucketName map[string]*Element) *Element {
	// storage.googleapis.com/bucket-name or …/projects/_/buckets/name
	const prefix = "storage.googleapis.com/"
	if !strings.HasPrefix(dest, prefix) {
		return nil
	}
	rest := strings.TrimPrefix(dest, prefix)
	name := rest
	const bucketsPrefix = "projects/_/buckets/"
	if strings.HasPrefix(rest, bucketsPrefix) {
		name = strings.TrimPrefix(rest, bucketsPrefix)
	}
	if name == "" {
		return nil
	}
	if el := byBucketName[name]; el != nil {
		return el
	}
	for addr, el := range byAddr {
		if el.Kind == "object_storage" && localTypeName(addr) == name {
			return el
		}
	}
	return nil
}

// applyPurpose runs type then relation inference. Call before annotations so
// declared purpose can overwrite with PurposeSourceDeclared.
func applyPurpose(elements []*Element, resources []planResource, idx configIndex) {
	applyPurposeFromType(elements)
	applyPurposeFromRelations(elements, resources, idx)
}
