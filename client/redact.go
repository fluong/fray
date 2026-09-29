package client

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
)

const (
	redactionScheme     = "hmac-sha256-v1"
	fingerprintMessage  = "fray-key-fingerprint"
	setupKeyCommand     = "openssl rand -hex 32 | gh secret set FRAY_REDACTION_KEY"
	fieldName           = "name"
	fieldAddress        = "address"
	fieldSignalName     = "signal.name"
	fieldEvidenceSource = "evidence.source"
	fieldEvidenceKey    = "evidence.key"
	fieldSourceRepo     = "source.repo"
)

// IDMap maps redacted wire ids back to local plaintext ids (and the reverse).
type IDMap struct {
	ToPlain    map[string]string // redacted id → plaintext id
	ToRedacted map[string]string // plaintext id → redacted id
	// Plaintext holds every identifying string that must not appear in the
	// outbound payload (names, addresses, signal names, repo).
	Plaintext []string
	FieldsHashed int
}

// ParseRedactionKey decodes FRAY_REDACTION_KEY (64 hex chars → 32 bytes).
func ParseRedactionKey(hexKey string) ([]byte, error) {
	hexKey = strings.TrimSpace(hexKey)
	if hexKey == "" {
		return nil, fmt.Errorf("FRAY_REDACTION_KEY is required (redaction is on by default).\nSet a 32-byte hex key:\n  %s", setupKeyCommand)
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("FRAY_REDACTION_KEY must be 64 hex characters (32 bytes).\nGenerate one:\n  %s", setupKeyCommand)
	}
	return key, nil
}

// LoadRedactionKey reads FRAY_REDACTION_KEY from the environment.
func LoadRedactionKey() ([]byte, error) {
	return ParseRedactionKey(os.Getenv("FRAY_REDACTION_KEY"))
}

// KeyFingerprint is the first 16 hex chars of HMAC(key, "fray-key-fingerprint").
func KeyFingerprint(key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(fingerprintMessage))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// HashField is HMAC-SHA256(key, field || 0x00 || value), hex-encoded.
func HashField(key []byte, field, value string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(field))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// Redact replaces identifying fields with HMAC digests, re-derives ids under
// the same key, and returns a map for local de-redaction. The input doc is not
// modified. subtype and provider_subtype are never emitted (Go types omit them).
func Redact(doc DFD, key []byte) (DFD, IDMap, error) {
	plain := collectPlaintext(doc)
	out := cloneDFD(doc)

	hashed := 0
	out.Source.Repo = HashField(key, fieldSourceRepo, out.Source.Repo)
	hashed++

	for i := range out.Elements {
		el := &out.Elements[i]
		el.Name = ""
		for j, addr := range el.Evidence.Addresses {
			el.Evidence.Addresses[j] = HashField(key, fieldAddress, addr)
			hashed++
		}
		for j := range el.Evidence.Signals {
			el.Evidence.Signals[j].Name = HashField(key, fieldSignalName, el.Evidence.Signals[j].Name)
			hashed++
		}
		if el.Evidence.Source != "" {
			el.Evidence.Source = HashField(key, fieldEvidenceSource, el.Evidence.Source)
			hashed++
		}
		if el.Evidence.Key != "" {
			el.Evidence.Key = HashField(key, fieldEvidenceKey, el.Evidence.Key)
			hashed++
		}
	}

	// Restore pre-finalize refs using NEW canonical keys (over hashed evidence).
	idToNewKey := map[string]string{}
	for i := range out.Elements {
		el := &out.Elements[i]
		idToNewKey[el.ID] = el.canonicalKey()
		el.ID = ""
	}
	for i := range out.TrustBoundaries {
		b := &out.TrustBoundaries[i]
		b.Inside = translate(b.Inside, idToNewKey)
		b.Outside = translate(b.Outside, idToNewKey)
		b.ID = ""
	}
	for i := range out.Flows {
		f := &out.Flows[i]
		f.From = idToNewKey[f.From]
		f.To = idToNewKey[f.To]
		f.ID = ""
		f.Boundaries = nil
	}

	finalizeHMAC(&out, key)
	out.Redaction = &Redaction{
		Scheme:         redactionScheme,
		KeyFingerprint: KeyFingerprint(key),
	}

	m := IDMap{
		ToPlain:      map[string]string{},
		ToRedacted:   map[string]string{},
		Plaintext:    plain.values(),
		FieldsHashed: hashed,
	}
	// Match plaintext → redacted without mutating the caller's doc.
	for _, el := range doc.Elements {
		addrs := make([]string, len(el.Evidence.Addresses))
		for j, addr := range el.Evidence.Addresses {
			addrs[j] = HashField(key, fieldAddress, addr)
		}
		sigs := make([]Signal, len(el.Evidence.Signals))
		for j, sig := range el.Evidence.Signals {
			sigs[j] = Signal{Type: sig.Type, Name: HashField(key, fieldSignalName, sig.Name)}
		}
		src, keyEv := el.Evidence.Source, el.Evidence.Key
		if src != "" {
			src = HashField(key, fieldEvidenceSource, src)
		}
		if keyEv != "" {
			keyEv = HashField(key, fieldEvidenceKey, keyEv)
		}
		hashedEl := Element{
			Provenance: el.Provenance,
			Evidence: Evidence{
				Addresses:     addrs,
				Signals:       sigs,
				Source:        src,
				Key:           keyEv,
				PurposeSource: el.Evidence.PurposeSource,
			},
		}
		rid := hmacDigest(key, "e", hashedEl.canonicalKey())
		m.ToPlain[rid] = el.ID
		m.ToRedacted[el.ID] = rid
	}
	for _, f := range doc.Flows {
		// Find matching redacted flow by remapped endpoints + identity class.
		fromR, okFrom := m.ToRedacted[f.From]
		toR, okTo := m.ToRedacted[f.To]
		if !okFrom || !okTo {
			continue
		}
		class := f.DataClass
		if f.identityClass != "" {
			class = f.identityClass
		}
		rid := hmacDigest(key, "f", fromR+"\n"+toR+"\n"+class)
		m.ToPlain[rid] = f.ID
		m.ToRedacted[f.ID] = rid
	}
	for _, b := range doc.TrustBoundaries {
		inside := make([]string, len(b.Inside))
		outside := make([]string, len(b.Outside))
		ok := true
		for i, id := range b.Inside {
			rid, found := m.ToRedacted[id]
			if !found {
				ok = false
				break
			}
			inside[i] = rid
		}
		if !ok {
			continue
		}
		for i, id := range b.Outside {
			rid, found := m.ToRedacted[id]
			if !found {
				ok = false
				break
			}
			outside[i] = rid
		}
		if !ok {
			continue
		}
		insideSorted := slices.Clone(inside)
		outsideSorted := slices.Clone(outside)
		slices.Sort(insideSorted)
		slices.Sort(outsideSorted)
		rid := hmacDigest(key, "b", b.Kind+"\n"+strings.Join(insideSorted, ",")+"\n"+strings.Join(outsideSorted, ","))
		m.ToPlain[rid] = b.ID
		m.ToRedacted[b.ID] = rid
	}

	return out, m, nil
}

type plainIndex struct {
	set map[string]struct{}
}

func (p plainIndex) values() []string {
	out := make([]string, 0, len(p.set))
	for v := range p.set {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func collectPlaintext(doc DFD) plainIndex {
	p := plainIndex{set: map[string]struct{}{}}
	add := func(v string) {
		if v != "" {
			p.set[v] = struct{}{}
		}
	}
	add(doc.Source.Repo)
	if owner, name, ok := strings.Cut(doc.Source.Repo, "/"); ok {
		add(owner)
		add(name)
	}
	for _, el := range doc.Elements {
		add(el.Name)
		for _, addr := range el.Evidence.Addresses {
			add(addr)
		}
		for _, sig := range el.Evidence.Signals {
			add(sig.Name)
		}
		add(el.Evidence.Source)
		add(el.Evidence.Key)
	}
	return p
}

// AssertNoPlaintext walks the JSON payload and fails if any string value equals
// a plaintext identifier. The error names the JSON pointer, never the value.
func AssertNoPlaintext(payload []byte, plaintext []string) error {
	if len(plaintext) == 0 {
		return nil
	}
	forbid := map[string]struct{}{}
	for _, v := range plaintext {
		forbid[v] = struct{}{}
	}
	var root any
	if err := json.Unmarshal(payload, &root); err != nil {
		return fmt.Errorf("payload guard: invalid json: %w", err)
	}
	var hit string
	var walk func(any, string)
	walk = func(n any, ptr string) {
		if hit != "" {
			return
		}
		switch t := n.(type) {
		case string:
			if _, ok := forbid[t]; ok {
				hit = ptr
			}
		case map[string]any:
			for k, child := range t {
				childPtr := ptr + "/" + escapePointer(k)
				walk(child, childPtr)
			}
		case []any:
			for i, child := range t {
				walk(child, fmt.Sprintf("%s/%d", ptr, i))
			}
		}
	}
	walk(root, "")
	if hit != "" {
		if hit == "" {
			hit = "/"
		}
		return fmt.Errorf("redaction guard: plaintext identifier found at %s (value omitted)", hit)
	}
	return nil
}

func escapePointer(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	s = strings.ReplaceAll(s, "/", "~1")
	return s
}

func cloneDFD(doc DFD) DFD {
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	var out DFD
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	// Preserve identityClass (unexported) from flows by index matching.
	// Marshal drops it; re-copy from source by matching from/to/data_class
	// before ids change — still available on input.
	for i := range out.Flows {
		if i < len(doc.Flows) {
			out.Flows[i].identityClass = doc.Flows[i].identityClass
			out.Flows[i].Causes = doc.Flows[i].Causes
		}
	}
	for i := range out.Elements {
		if i < len(doc.Elements) {
			out.Elements[i].Causes = doc.Elements[i].Causes
		}
	}
	return out
}

// RemapID returns the plaintext id for a redacted id, or the input if unknown.
func (m IDMap) RemapID(redacted string) string {
	if plain, ok := m.ToPlain[redacted]; ok {
		return plain
	}
	return redacted
}

// RemapAccepted rewrites accepted mitigation target ids to redacted wire ids.
func (m IDMap) RemapAcceptedTarget(plainID string) string {
	if rid, ok := m.ToRedacted[plainID]; ok {
		return rid
	}
	return plainID
}
