package main

import (
	"fmt"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
	"github.com/fluong/fray/render"
)

// resolveAccepted is kept for tests of the legacy address→id path shape.
// Production scan path uses resolveWaivers.
func resolveAccepted(doc client.DFD, entries []mitigationEntry) ([]apiv1.Accepted, error) {
	out := make([]apiv1.Accepted, 0, len(entries))
	for _, e := range entries {
		id := render.ResolveAddress(doc, e.Address)
		if id == "" {
			return nil, fmt.Errorf("%s: address %q not found", e.RuleID, e.Address)
		}
		status := e.Status
		if status == "" {
			status = "accepted"
		}
		out = append(out, apiv1.Accepted{RuleID: e.RuleID, TargetID: id, Status: status})
	}
	return out, nil
}

func toRenderEntries(entries []mitigationEntry) []render.MitigationEntry {
	out := make([]render.MitigationEntry, len(entries))
	for i, e := range entries {
		out[i] = render.MitigationEntry{
			RuleID: e.RuleID, Address: e.Address, Status: e.Status,
			Reason: e.Reason, Revisit: e.Revisit,
		}
	}
	return out
}
