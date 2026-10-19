package validate

import (
	"encoding/json"
	"fmt"
)

// CheckDetectionRevisions enforces strictly increasing revision numbers when
// detection_revisions is present. JSON Schema validates each entry (revision >= 2);
// ordering is checked here for rule authors and CI fixtures.
func CheckDetectionRevisions(raw []byte) error {
	var doc struct {
		DetectionRevisions []struct {
			Revision int `json:"revision"`
		} `json:"detection_revisions"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	if len(doc.DetectionRevisions) == 0 {
		return nil
	}
	prev := 1
	for i, dr := range doc.DetectionRevisions {
		if dr.Revision <= prev {
			return fmt.Errorf("detection_revisions[%d]: revision must be > %d (got %d)", i, prev, dr.Revision)
		}
		prev = dr.Revision
	}
	return nil
}
