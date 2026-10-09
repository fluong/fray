package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
)

// MaxPlanFileBytes is the hard cap for an external plan-file (32 MiB).
const MaxPlanFileBytes = 32 << 20

// ErrPlanNotJSON is returned for binary or non-JSON plan-file bodies.
var ErrPlanNotJSON = fmt.Errorf("plan-file must be terraform show -json output (JSON), not a binary plan. Run: terraform show -json tfplan > plan.json. See https://github.com/fluong/fray#troubleshooting.")

// ErrPlanNotTerraformJSON is returned when format_version is missing or not a string.
var ErrPlanNotTerraformJSON = fmt.Errorf("not a Terraform JSON plan")

// ErrPlanLooksLikeState is returned for terraform state JSON passed as a plan-file.
var ErrPlanLooksLikeState = fmt.Errorf("plan-file looks like a Terraform state file, not a plan. Run: terraform show -json tfplan > plan.json. See https://github.com/fluong/fray#troubleshooting.")

// ErrPlanNoResources is returned when the plan has no managed resource_changes.
var ErrPlanNoResources = fmt.Errorf("plan contains no resources")

// ErrPlanTooLarge is returned when the plan-file exceeds MaxPlanFileBytes.
var ErrPlanTooLarge = fmt.Errorf("plan-file exceeds the 32 MiB size limit. See https://github.com/fluong/fray#troubleshooting.")

// ErrPlanEmptyDFD is returned when an external plan parses to zero DFD elements.
var ErrPlanEmptyDFD = fmt.Errorf("plan contains no resources Fray can analyse")

// LoadPlanFile reads and validates an external terraform show -json plan.
// Size is checked via Stat before a full read (LimitReader as a second guard).
func LoadPlanFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > MaxPlanFileBytes {
		return nil, ErrPlanTooLarge
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxPlanFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxPlanFileBytes {
		return nil, ErrPlanTooLarge
	}
	if err := ValidatePlanJSON(data); err != nil {
		return nil, err
	}
	return data, nil
}

// ValidatePlanJSON checks that data is a Terraform plan JSON (Design §2 /
// option 1): format_version string, not state-shaped, and at least one
// managed resource_changes entry.
func ValidatePlanJSON(data []byte) error {
	trimmed := bytes.TrimLeftFunc(data, unicode.IsSpace)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(data) {
		return ErrPlanNotJSON
	}
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return ErrPlanNotJSON
	}
	if _, ok := root["format_version"].(string); !ok {
		return ErrPlanNotTerraformJSON
	}
	_, hasPV := root["planned_values"]
	_, hasRC := root["resource_changes"]
	_, hasValues := root["values"]
	if hasValues && !hasPV && !hasRC {
		return ErrPlanLooksLikeState
	}
	if countManagedResourceChanges(root["resource_changes"]) < 1 {
		return ErrPlanNoResources
	}
	return nil
}

func countManagedResourceChanges(v any) int {
	list, ok := v.([]any)
	if !ok {
		return 0
	}
	n := 0
	for _, raw := range list {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if m["mode"] == "managed" {
			n++
		}
	}
	return n
}

// CountUnmatchedPlanAddresses returns how many managed plan addresses are
// missing from the checked-out HCL index (resource block or root module call).
// Indexes ([0], ["x"]) are stripped. Used for the plan-file mismatch warning.
func CountUnmatchedPlanAddresses(plan []byte, sourceDir string) (int, error) {
	idx, err := ResourceLocations(sourceDir)
	if err != nil {
		return 0, err
	}
	var root struct {
		ResourceChanges []struct {
			Address string `json:"address"`
			Mode    string `json:"mode"`
		} `json:"resource_changes"`
	}
	if err := json.Unmarshal(plan, &root); err != nil {
		return 0, err
	}
	unmatched := 0
	for _, rc := range root.ResourceChanges {
		if rc.Mode != "" && rc.Mode != "managed" {
			continue
		}
		if rc.Address == "" {
			continue
		}
		if planAddressInSource(idx, rc.Address) {
			continue
		}
		unmatched++
	}
	return unmatched, nil
}

func planAddressInSource(idx map[string]SourceLocation, address string) bool {
	if _, ok := LookupCauseLocation(idx, address, ""); ok {
		return true
	}
	if call, ok := rootModuleCall(address); ok {
		if _, ok := idx[call]; ok {
			return true
		}
	}
	moduleAddr, typ, name, ok := splitResourceAddress(address)
	if !ok {
		return false
	}
	key := resourceAddress(moduleAddr, typ, name)
	loc, ok := idx[key]
	return ok && !strings.Contains(loc.Path, ".terraform/modules/")
}

// PlanMismatchWarning formats the Action ::warning:: body for plan/source skew.
func PlanMismatchWarning(n int) string {
	return fmt.Sprintf("plan-file may not match this commit's working-directory (%d resource address(es) not found in checked-out HCL)", n)
}
