package device

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/storage/memory"
)

func TestGetDeviceVerificationURI(t *testing.T) {
	u, err := url.Parse("https://dex.example.com/non-root-path")
	require.NoError(t, err)

	h := &Handler{IssuerURL: oauth2.IssuerURL{URL: *u}}
	require.Equal(t, "/non-root-path/device/auth/verify_code", h.getDeviceVerificationURI())
}

// TestCreateDeviceAuthorizationUsesInjectedClock pins the device request and
// token expiry to the handler's clock. Both were minted from a mix of
// time.Now() and h.Now(), which made the two expiries drift apart under a
// fixed test clock.
func TestCreateDeviceAuthorizationUsesInjectedClock(t *testing.T) {
	u, err := url.Parse("https://dex.example.com")
	require.NoError(t, err)

	fixed := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	h := &Handler{
		IssuerURL:        oauth2.IssuerURL{URL: *u},
		Storage:          memory.New(logger),
		Logger:           logger,
		Now:              func() time.Time { return fixed },
		RequestsValidFor: 5 * time.Minute,
	}

	resp, ferr := h.createDeviceAuthorization(t.Context(), deviceCodeRequest{
		clientID: "test",
		scopes:   []string{"openid"},
	})
	require.Nil(t, ferr)

	want := fixed.Add(5 * time.Minute)

	req, err := h.Storage.GetDeviceRequest(t.Context(), resp.UserCode)
	require.NoError(t, err)
	require.WithinDuration(t, want, req.Expiry, 0)

	token, err := h.Storage.GetDeviceToken(t.Context(), resp.DeviceCode)
	require.NoError(t, err)
	require.WithinDuration(t, want, token.Expiry, 0)
	require.WithinDuration(t, fixed, token.LastRequestTime, 0)
}

// TestBindingKey is a syntactically valid binding_key: 32 raw bytes,
// base64url-encoded without padding (43 characters). Exported so the server
// package's HTTP-level tests can reuse the same shape.
var TestBindingKey = "YmluZGluZ19rZXlfY29uZm9ybWFuY2VfMzJfYnl0ZXM"

func TestValidateBindingKey(t *testing.T) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(TestBindingKey)
	require.NoError(t, err)
	require.Len(t, raw, 32)

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"valid key", TestBindingKey, false},
		{"absent key is allowed", "", false},
		{"standard alphabet is rejected", base64.StdEncoding.EncodeToString(raw), true},
		{"padded urlsafe is rejected", base64.URLEncoding.EncodeToString(raw), true},
		{"wrong byte count", base64.RawURLEncoding.EncodeToString([]byte("31_bytes_____________________________")), true},
		{"not base64 at all", "!!!!not-base64~~~~", true},
		{"non-canonical trailing bits", TestBindingKey[:42] + "h", true},
		// Go's base64 decoder ignores CR and LF, so decoding alone accepts
		// whitespace-carrying spellings of a valid key; the canonical
		// round-trip check must reject every one of them (review finding 1).
		{"leading CR", "\r" + TestBindingKey, true},
		{"leading LF", "\n" + TestBindingKey, true},
		{"trailing CR", TestBindingKey + "\r", true},
		{"trailing LF", TestBindingKey + "\n", true},
		{"embedded CR", TestBindingKey[:10] + "\r" + TestBindingKey[10:], true},
		{"embedded LF", TestBindingKey[:10] + "\n" + TestBindingKey[10:], true},
		{"embedded CRLF", TestBindingKey[:10] + "\r\n" + TestBindingKey[10:], true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ferr := validateBindingKey(tc.key)
			if tc.wantErr {
				require.NotNil(t, ferr)
				require.Equal(t, http.StatusBadRequest, ferr.status)
				require.Equal(t, oauth2.InvalidRequest, ferr.code)
				return
			}
			require.Nil(t, ferr)
			require.Equal(t, tc.key, got)
		})
	}
}

// TestParseDeviceCodeRequestBindingKey checks the /device/code form parsing:
// the optional binding_key reaches the parsed request when well-formed and the
// request is rejected before anything is stored when it is not.
func TestParseDeviceCodeRequestBindingKey(t *testing.T) {
	newReq := func(form url.Values) *http.Request {
		req, err := http.NewRequest("POST", "https://dex.example.com/device/code", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}

	h := &Handler{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	form := url.Values{}
	form.Set("client_id", "test")
	form.Set("binding_key", TestBindingKey)
	req, ferr := h.parseDeviceCodeRequest(newReq(form))
	require.Nil(t, ferr)
	require.Equal(t, TestBindingKey, req.bindingKey)

	form.Del("binding_key")
	req, ferr = h.parseDeviceCodeRequest(newReq(form))
	require.Nil(t, ferr)
	require.Empty(t, req.bindingKey)

	form.Set("binding_key", "malformed")
	_, ferr = h.parseDeviceCodeRequest(newReq(form))
	require.NotNil(t, ferr)
	require.Equal(t, http.StatusBadRequest, ferr.status)
	require.Equal(t, oauth2.InvalidRequest, ferr.code)
}

// TestCreateDeviceAuthorizationPersistsBindingKey checks that a submitted
// binding_key is stored with the device request and that an omitted one stays
// absent — no behavior change for requests without the parameter.
func TestCreateDeviceAuthorizationPersistsBindingKey(t *testing.T) {
	u, err := url.Parse("https://dex.example.com")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	h := &Handler{
		IssuerURL:        oauth2.IssuerURL{URL: *u},
		Storage:          memory.New(logger),
		Logger:           logger,
		Now:              func() time.Time { return time.Now() },
		RequestsValidFor: 5 * time.Minute,
	}

	resp, ferr := h.createDeviceAuthorization(t.Context(), deviceCodeRequest{
		clientID:   "test",
		scopes:     []string{"openid"},
		bindingKey: TestBindingKey,
	})
	require.Nil(t, ferr)

	stored, err := h.Storage.GetDeviceRequest(t.Context(), resp.UserCode)
	require.NoError(t, err)
	require.Equal(t, TestBindingKey, stored.BindingKey)

	resp, ferr = h.createDeviceAuthorization(t.Context(), deviceCodeRequest{
		clientID: "test",
		scopes:   []string{"openid"},
	})
	require.Nil(t, ferr)

	stored, err = h.Storage.GetDeviceRequest(t.Context(), resp.UserCode)
	require.NoError(t, err)
	require.Empty(t, stored.BindingKey)
}
