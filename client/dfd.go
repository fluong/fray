package client

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
)

// DFD is a dfd/v1 document. Fields are allow-listed. Marshal emits them in
// this struct order, with map keys sorted, so two parses of the same plan match.
type DFD struct {
	SchemaVersion   string     `json:"schema_version"`
	Redaction       *Redaction `json:"redaction,omitempty"`
	Source          Source     `json:"source"`
	Elements        []Element  `json:"elements"`
	TrustBoundaries []Boundary `json:"trust_boundaries"`
	Flows           []Flow     `json:"flows"`
}

// Redaction records the HMAC scheme applied before the DFD left CI.
type Redaction struct {
	Scheme         string `json:"scheme"`
	KeyFingerprint string `json:"key_fingerprint"`
}

type Source struct {
	Repo     string `json:"repo"`
	Commit   string `json:"commit"`
	Tool     string `json:"iac_tool"`
	Fidelity string `json:"fidelity"`
}

type Element struct {
	ID         string         `json:"id"`
	Name       string         `json:"name,omitempty"`
	Type       string         `json:"type"`
	Kind       string         `json:"kind"`
	Provenance string         `json:"provenance"`
	Evidence   Evidence       `json:"evidence"`
	Provider   string         `json:"provider,omitempty"`
	Purpose    string         `json:"purpose,omitempty"` // closed enum; never a free-text name
	Attributes map[string]any `json:"attributes,omitempty"`
	// Causes maps an attribute name to the resource address that set it.
	// It is local report data and is not part of the DFD.
	Causes map[string]string `json:"-"`
}

type Evidence struct {
	Addresses []string `json:"addresses,omitempty"`
	Signals   []Signal `json:"signals,omitempty"`
	Source    string   `json:"source,omitempty"`
	Key       string   `json:"key,omitempty"`
}

type Signal struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type Boundary struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind"`
	Inside  []string `json:"inside"`
	Outside []string `json:"outside"`
}

type Flow struct {
	ID             string   `json:"id"`
	From           string   `json:"from"`
	To             string   `json:"to"`
	DataClass      string   `json:"data_class"`
	Transport      string   `json:"transport"`
	Boundaries     []string `json:"boundaries"`
	AuthzScope     string   `json:"authz_scope,omitempty"`
	AuthzGrants    []string `json:"authz_grants,omitempty"`
	// AuthzActions lists S3 write/policy actions granted on this flow when known
	// (closed enum including DeleteObject, PutObject, BypassGovernanceRetention, …).
	AuthzActions   []string `json:"authz_actions,omitempty"`
	SecretDelivery string   `json:"secret_delivery,omitempty"`
	// Causes maps a flow field to the resource address that set it.
	Causes map[string]string `json:"-"`
	// identityClass is the data_class used for the flow id. It is set when
	// the flow is created and never changed by annotations. An empty value
	// means DataClass is the identity, which is the declared-flow case.
	identityClass string
}

func (e Element) canonicalKey() string {
	switch e.Provenance {
	case "iac":
		addrs := slices.Clone(e.Evidence.Addresses)
		slices.Sort(addrs)
		return strings.Join(addrs, "\n")
	case "declared":
		return "declared:" + e.Evidence.Key
	case "inferred":
		return "inferred:" + strings.Join(signalKeys(e.Evidence.Signals), "\n")
	default:
		return ""
	}
}

func signalKeys(sigs []Signal) []string {
	out := make([]string, len(sigs))
	for i, s := range sigs {
		out[i] = s.Type + ":" + s.Name
	}
	slices.Sort(out)
	return out
}

// finalize assigns ids with plain SHA-256. Until here, flow and boundary
// references hold each element's canonical key, not its id.
func finalize(doc *DFD) {
	finalizeWith(doc, digest)
}

// finalizeHMAC assigns ids with HMAC-SHA256 under key (redacted DFDs).
func finalizeHMAC(doc *DFD, key []byte) {
	finalizeWith(doc, func(prefix, k string) string {
		return hmacDigest(key, prefix, k)
	})
}

func finalizeWith(doc *DFD, idFn func(prefix, key string) string) {
	keyToID := map[string]string{}
	for i := range doc.Elements {
		el := &doc.Elements[i]
		el.Evidence.Signals = dedupeSignals(el.Evidence.Signals)
		el.ID = idFn("e", el.canonicalKey())
		keyToID[el.canonicalKey()] = el.ID
	}
	for i := range doc.TrustBoundaries {
		b := &doc.TrustBoundaries[i]
		b.Inside = translate(b.Inside, keyToID)
		b.Outside = translate(b.Outside, keyToID)
		slices.Sort(b.Inside)
		slices.Sort(b.Outside)
		b.ID = idFn("b", b.Kind+"\n"+strings.Join(b.Inside, ",")+"\n"+strings.Join(b.Outside, ","))
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		f.From = keyToID[f.From]
		f.To = keyToID[f.To]
		f.Boundaries = nil
		for _, b := range doc.TrustBoundaries {
			in := toSet(b.Inside)
			out := toSet(b.Outside)
			if (in[f.From] && out[f.To]) || (out[f.From] && in[f.To]) {
				f.Boundaries = append(f.Boundaries, b.ID)
			}
		}
		if f.Boundaries == nil {
			f.Boundaries = []string{}
		}
		slices.Sort(f.Boundaries)
		class := f.DataClass
		if f.identityClass != "" {
			class = f.identityClass
		}
		f.ID = idFn("f", f.From+"\n"+f.To+"\n"+class)
	}
	slices.SortFunc(doc.Elements, func(a, b Element) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(doc.TrustBoundaries, func(a, b Boundary) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(doc.Flows, func(a, b Flow) int { return strings.Compare(a.ID, b.ID) })
}

func dedupeSignals(sigs []Signal) []Signal {
	seen := map[string]bool{}
	var out []Signal
	for _, s := range sigs {
		k := s.Type + ":" + s.Name
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b Signal) int {
		return strings.Compare(a.Type+":"+a.Name, b.Type+":"+b.Name)
	})
	return out
}

func translate(keys []string, keyToID map[string]string) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = keyToID[k]
	}
	return out
}

func toSet(ids []string) map[string]bool {
	out := map[string]bool{}
	for _, id := range ids {
		out[id] = true
	}
	return out
}

func digest(prefix, key string) string {
	sum := sha256.Sum256([]byte(key))
	return prefix + hex.EncodeToString(sum[:])[:16]
}

func hmacDigest(key []byte, prefix, msg string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(msg))
	sum := mac.Sum(nil)
	return prefix + hex.EncodeToString(sum)[:16]
}

func Marshal(doc DFD) ([]byte, error) {
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}
