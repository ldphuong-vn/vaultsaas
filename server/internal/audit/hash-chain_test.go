package audit

import (
	"fmt"
	"testing"
	"time"
)

func makeEntry(userID, action, resourceType, resourceID, eventType, status string) Entry {
	return Entry{
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		EventType:    eventType,
		Status:       status,
	}
}

func TestComputeHash(t *testing.T) {
	e := makeEntry("u1", "create", "secret", "s1", "action", "success")
	h1 := ComputeHash(e, "")
	h2 := ComputeHash(e, "")
	if h1 != h2 {
		t.Error("same input should produce same hash")
	}
	// Different prevHash produces different hash
	h3 := ComputeHash(e, "prevhash")
	if h1 == h3 {
		t.Error("different prevHash should produce different hash")
	}
}

func TestComputeHash_DifferentFields(t *testing.T) {
	e1 := makeEntry("u1", "create", "secret", "s1", "action", "success")
	e2 := makeEntry("u2", "create", "secret", "s1", "action", "success")
	h1 := ComputeHash(e1, "")
	h2 := ComputeHash(e2, "")
	if h1 == h2 {
		t.Error("different userID should produce different hash")
	}
}

func TestComputeHash_NonEmpty(t *testing.T) {
	e := makeEntry("u1", "delete", "secret", "s1", "action", "success")
	h := ComputeHash(e, "")
	if h == "" {
		t.Error("hash should not be empty")
	}
	if len(h) != 64 {
		t.Errorf("SHA-256 hex should be 64 chars, got %d", len(h))
	}
}

func TestVerifyChain(t *testing.T) {
	entries := make([]Entry, 3)
	prevHash := ""
	for i := range entries {
		entries[i] = makeEntry("u1", "create", "secret", "s1", "action", "success")
		hash := ComputeHash(entries[i], prevHash)
		entries[i].HashPrev = hash
		prevHash = hash
	}

	ok, failIdx := VerifyChain(entries)
	if !ok {
		t.Errorf("valid chain should verify, failed at %d", failIdx)
	}
	if failIdx != -1 {
		t.Errorf("failIdx should be -1 for valid chain, got %d", failIdx)
	}
}

func TestVerifyChain_TamperDetected(t *testing.T) {
	entries := make([]Entry, 3)
	prevHash := ""
	for i := range entries {
		entries[i] = makeEntry("u1", "create", "secret", "s1", "action", "success")
		hash := ComputeHash(entries[i], prevHash)
		entries[i].HashPrev = hash
		prevHash = hash
	}
	// Tamper middle entry
	entries[1].Action = "tampered_action"
	ok, failIdx := VerifyChain(entries)
	if ok {
		t.Error("tampered chain should not verify")
	}
	if failIdx != 1 {
		t.Errorf("failIdx=%d, want 1", failIdx)
	}
}

func TestVerifyChain_Empty(t *testing.T) {
	ok, failIdx := VerifyChain([]Entry{})
	if !ok {
		t.Error("empty chain should be valid")
	}
	if failIdx != -1 {
		t.Errorf("failIdx=%d, want -1", failIdx)
	}
}

func TestVerifyChain_SingleEntry(t *testing.T) {
	e := makeEntry("u1", "create", "secret", "s1", "action", "success")
	hash := ComputeHash(e, "")
	e.HashPrev = hash
	ok, failIdx := VerifyChain([]Entry{e})
	if !ok {
		t.Errorf("single valid entry should verify, failIdx=%d", failIdx)
	}
}

func makeFullEntry() Entry {
	return Entry{
		EventTime:    time.Date(2026, 8, 31, 12, 0, 0, 123456000, time.UTC),
		UserID:       "u1",
		Action:       "proxy_request",
		ResourceType: "gateway",
		ResourceID:   "r1",
		EventType:    "action",
		Status:       "success",
		IPAddress:    "10.0.0.1",
		UserAgent:    "valt-cli/0.1",
		RegionCode:   "VN",
		Metadata:     `{"host":"db.internal"}`,
	}
}

// Regression for bug 1: every persisted field must participate in the hash.
// Before 000042, ip/user_agent/region/metadata/event_time could be edited in
// the database without breaking the chain.
func TestComputeHash_CoversAllFields(t *testing.T) {
	base := ComputeHash(makeFullEntry(), "")

	mutations := map[string]func(*Entry){
		"ip_address":  func(e *Entry) { e.IPAddress = "10.0.0.999" },
		"user_agent":  func(e *Entry) { e.UserAgent = "evil/1.0" },
		"region_code": func(e *Entry) { e.RegionCode = "US" },
		"metadata":    func(e *Entry) { e.Metadata = `{"host":"evil"}` },
		"event_time":  func(e *Entry) { e.EventTime = e.EventTime.Add(time.Hour) },
		"status":      func(e *Entry) { e.Status = "failure" },
	}
	for field, mutate := range mutations {
		e := makeFullEntry()
		mutate(&e)
		if h := ComputeHash(e, ""); h == base {
			t.Errorf("hash must change when %s changes", field)
		}
	}
}

func TestVerifyChain_DetectsFieldTampering(t *testing.T) {
	build := func() []Entry {
		entries := make([]Entry, 3)
		prev := ""
		for i := range entries {
			e := makeFullEntry()
			e.Action = fmt.Sprintf("action-%d", i)
			h := ComputeHash(e, prev)
			e.HashPrev = h
			prev = h
			entries[i] = e
		}
		return entries
	}

	for field, mutate := range map[string]func(*Entry){
		"ip_address": func(e *Entry) { e.IPAddress = "203.0.113.9" },
		"metadata":   func(e *Entry) { e.Metadata = `{"host":"attacker"}` },
		"event_time": func(e *Entry) { e.EventTime = e.EventTime.Add(24 * time.Hour) },
	} {
		entries := build()
		mutate(&entries[1])
		if ok, idx := VerifyChain(entries); ok || idx != 1 {
			t.Errorf("chain must break at tampered entry (field=%s), got ok=%v idx=%d", field, ok, idx)
		}
	}
}

// Rows written before the 000042 upgrade were hashed with the v1 algorithm and
// must remain verifiable.
func TestVerifyChain_AcceptsLegacyV1Chain(t *testing.T) {
	entries := make([]Entry, 3)
	prev := ""
	for i := range entries {
		e := makeFullEntry()
		e.HashPrev = computeHashV1(e, prev)
		prev = e.HashPrev
		entries[i] = e
	}
	if ok, idx := VerifyChain(entries); !ok {
		t.Errorf("legacy v1 chain should verify, broke at %d", idx)
	}
}

func TestCanonicalIP(t *testing.T) {
	cases := map[string]string{
		"10.0.0.1":              "10.0.0.1/32",
		"10.0.0.1, 192.168.1.1": "10.0.0.1/32", // XFF list: first entry
		"  10.0.0.7  ":          "10.0.0.7/32",
		"2001:db8::1":           "2001:db8::1/128",
		"::ffff:10.0.0.9":       "10.0.0.9/32", // IPv4-mapped
		"junk":                  "",
		"not-an-ip, 10.0.0.1":   "", // junk first entry is dropped
		"":                      "",
		"0.0.0.0":               "", // unspecified
	}
	for in, want := range cases {
		if got := canonicalIP(in); got != want {
			t.Errorf("canonicalIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeCSVCell(t *testing.T) {
	cases := map[string]string{
		"":            "",
		"normal":      "normal",
		"=1+1":        "'=1+1",
		"+SUM(A1)":    "'+SUM(A1)",
		"-2":          "'-2",
		"@cmd":        "'@cmd",
		"\tTabbed":    "'\tTabbed",
		"\rCR":        "'\rCR",
		"safe-ish -1": "safe-ish -1", // dash not first char
	}
	for in, want := range cases {
		if got := sanitizeCSVCell(in); got != want {
			t.Errorf("sanitizeCSVCell(%q) = %q, want %q", in, got, want)
		}
	}
}
