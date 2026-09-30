package home

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/server/templates"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/web"
)

func TestHomeUsesThemeWithoutSessions(t *testing.T) {
	static, theme, robots, pages, err := templates.LoadWebConfig(templates.Config{
		WebFS: web.FS(), Issuer: "Federate", IssuerURL: "https://login.federate.to/dex", Theme: "federate",
	})
	if err != nil {
		t.Fatal(err)
	}
	if static == nil || theme == nil || robots == nil {
		t.Fatal("web assets were not loaded")
	}
	issuer, err := url.Parse("https://login.federate.to/dex")
	if err != nil {
		t.Fatal(err)
	}
	h := Handler{IssuerURL: oauth2.IssuerURL{URL: *issuer}, Templates: pages, Logger: slog.Default()}
	response := httptest.NewRecorder()
	h.handle(response, httptest.NewRequest(http.MethodGet, "https://login.federate.to/dex", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("home returned %d", response.Code)
	}
	page := response.Body.String()
	for _, expected := range []string{"Federate", "by Cyberdione Labs", "Not signed in", "theme/styles.css", "static/legal/terms.html", "static/legal/privacy.html", "Cyberdione Labs Corporation. All rights reserved.", "/dex/.well-known/openid-configuration"} {
		if !strings.Contains(page, expected) {
			t.Errorf("home missing %q", expected)
		}
	}
	if strings.Contains(page, "Dex IdP") {
		t.Error("home fell back to the unbranded inline page")
	}
}

func TestSessionExpiry(t *testing.T) {
	absolute := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		session  storage.AuthSession
		want     time.Time
		wantIdle bool
	}{
		{
			name:     "idle first",
			session:  storage.AuthSession{AbsoluteExpiry: absolute, IdleExpiry: absolute.Add(-time.Hour)},
			want:     absolute.Add(-time.Hour),
			wantIdle: true,
		},
		{
			name:     "absolute first",
			session:  storage.AuthSession{AbsoluteExpiry: absolute, IdleExpiry: absolute.Add(time.Hour)},
			want:     absolute,
			wantIdle: false,
		},
		{
			// Equal deadlines are the absolute one: it cannot move, so it is the
			// honest label of the two.
			name:     "equal",
			session:  storage.AuthSession{AbsoluteExpiry: absolute, IdleExpiry: absolute},
			want:     absolute,
			wantIdle: false,
		},
		{
			name:     "only idle set",
			session:  storage.AuthSession{IdleExpiry: absolute},
			want:     absolute,
			wantIdle: true,
		},
		{
			name:     "only absolute set",
			session:  storage.AuthSession{AbsoluteExpiry: absolute},
			want:     absolute,
			wantIdle: false,
		},
		{
			name:    "neither set",
			session: storage.AuthSession{},
			want:    time.Time{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, idle := sessionExpiry(&tc.session)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantIdle, idle)
		})
	}
}

func TestTimeFields(t *testing.T) {
	iso, text := timeFields(time.Date(2026, 7, 28, 9, 5, 0, 0, time.UTC))
	// The attribute has to parse as a date/time for <time> to mean anything.
	assert.Equal(t, "2026-07-28T09:05:00Z", iso)
	assert.Equal(t, "28 Jul 2026, 09:05 UTC", text)

	// A different zone is still reported as the same instant in UTC.
	tokyo, err := time.LoadLocation("Asia/Tokyo")
	assert.NoError(t, err)
	iso, text = timeFields(time.Date(2026, 7, 28, 18, 5, 0, 0, tokyo))
	assert.Equal(t, "2026-07-28T09:05:00Z", iso)
	assert.Equal(t, "28 Jul 2026, 09:05 UTC", text)

	iso, text = timeFields(time.Time{})
	assert.Empty(t, iso)
	assert.Empty(t, text)
}
