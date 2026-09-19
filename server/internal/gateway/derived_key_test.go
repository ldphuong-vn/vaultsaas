package gateway

import (
	"net/http/httptest"
	"testing"
)

func TestDerivedKeyFromAuthorization(t *testing.T) {
	cases := []struct {
		name    string
		header  string
		wantKey string
	}{
		{"bearer derived key", "Bearer valt_dk_abc123", "valt_dk_abc123"},
		{"bare derived key", "valt_dk_abc123", "valt_dk_abc123"},
		{"bearer with extra spaces", "Bearer   valt_dk_abc123  ", "valt_dk_abc123"},
		{"real api key ignored", "Bearer sk-real-upstream-key", ""},
		{"agent token ignored", "Bearer valt_agt_token", ""},
		{"empty", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://api.example.com/v1/models", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			if got := derivedKeyFromAuthorization(r); got != tc.wantKey {
				t.Fatalf("derivedKeyFromAuthorization = %q, want %q", got, tc.wantKey)
			}
		})
	}
}

func TestBearerTokenFrom(t *testing.T) {
	if got := bearerTokenFrom("Bearer tok1"); got != "tok1" {
		t.Fatalf("bearerTokenFrom simple = %q", got)
	}
	if got := bearerTokenFrom("bearer tok2"); got != "tok2" {
		t.Fatalf("bearerTokenFrom lowercase scheme = %q", got)
	}
	if got := bearerTokenFrom("Basic abc"); got != "" {
		t.Fatalf("non-bearer scheme must be rejected, got %q", got)
	}
	if got := bearerTokenFrom("Bearer"); got != "" {
		t.Fatalf("missing token must be rejected, got %q", got)
	}
}
