package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/device"
	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/storage"
)

// deviceBindingKey is a syntactically valid binding_key for the server-level
// tests: 32 raw bytes, base64url-encoded without padding (43 characters), the
// same value the device package's own tests use.
const deviceBindingKey = "YmluZGluZ19rZXlfY29uZm9ybWFuY2VfMzJfYnl0ZXM"

// verifyTestIDToken verifies an ID token's RS256 signature against the test
// signing key and returns its claims as a plain map, so a test can inspect
// individual claims (binding_key in particular) without a full OIDC client.
func verifyTestIDToken(t *testing.T, rawIDToken string) map[string]any {
	t.Helper()

	obj, err := jose.ParseSigned(rawIDToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	payload, err := obj.Verify(&testKey.PublicKey)
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

// deviceFlowToken runs the device flow end to end against s, minus the browser
// login handshake: it authorizes a device request (optionally with a
// binding_key), simulates the browser callback by planting an auth code bound to
// the device callback redirect, and returns the raw token-endpoint response of
// the completed device_code grant.
func deviceFlowToken(t *testing.T, s *Server, bindingKey string) (int, []byte) {
	t.Helper()
	ctx := t.Context()

	// 1. The device authorization request (RFC 8628 §3.1).
	form := url.Values{}
	form.Set("client_id", "testclient")
	form.Set("scope", "openid profile")
	if bindingKey != "" {
		form.Set("binding_key", bindingKey)
	}
	u, err := url.Parse(s.issuerURL.String())
	require.NoError(t, err)
	u.Path = path.Join(u.Path, "device/code")

	req, _ := http.NewRequest("POST", u.String(), bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	var deviceResp device.DeviceCodeResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &deviceResp))
	require.NotEmpty(t, deviceResp.DeviceCode)
	require.NotEmpty(t, deviceResp.UserCode)

	// The submitted key must be persisted with the device request.
	stored, err := s.storage.GetDeviceRequest(ctx, deviceResp.UserCode)
	require.NoError(t, err)
	require.Equal(t, bindingKey, stored.BindingKey)

	// 2. Client and auth code for the browser leg: the code is bound to the
	// device callback redirect, exactly as the /auth endpoint would mint it.
	client := storage.Client{
		ID:           "testclient",
		RedirectURIs: []string{oauth2.DeviceCallbackURI},
	}
	require.NoError(t, s.storage.CreateClient(ctx, client))

	authCode := storage.AuthCode{
		ID:          "somecode",
		ClientID:    "testclient",
		RedirectURI: oauth2.DeviceCallbackURI,
		Scopes:      []string{"openid", "profile"},
		ConnectorID: "mock",
		Claims:      storage.Claims{UserID: "1", Username: "jane", Email: "jane.doe@example.com"},
		Expiry:      time.Now().Add(5 * time.Minute),
	}
	require.NoError(t, s.storage.CreateAuthCode(ctx, authCode))

	// 3. The browser callback completes the authorization and mints the tokens.
	u, err = url.Parse(s.issuerURL.String())
	require.NoError(t, err)
	u.Path = path.Join(u.Path, "device/callback")
	q := u.Query()
	q.Set("state", deviceResp.UserCode)
	q.Set("code", authCode.ID)
	u.RawQuery = q.Encode()

	req, _ = http.NewRequest("GET", u.String(), nil)
	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	// 4. The device polls the token endpoint and receives the minted tokens.
	u, err = url.Parse(s.issuerURL.String())
	require.NoError(t, err)
	u.Path = path.Join(u.Path, "token")
	poll := url.Values{}
	poll.Set("grant_type", oauth2.GrantTypeDeviceCode)
	poll.Set("device_code", deviceResp.DeviceCode)

	req, _ = http.NewRequest("POST", u.String(), bytes.NewBufferString(poll.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr.Code, rr.Body.Bytes()
}

// TestDeviceFlowBindingKeyEcho is the holder-key binding contract: a binding_key
// submitted with the device authorization request is echoed, issuer-signed,
// inside the ID token the device_code grant returns — the device-flow analogue
// of nonce binding the code flow.
func TestDeviceFlowBindingKeyEcho(t *testing.T) {
	_, s := newTestServer(t, func(c *Config) { c.Issuer += "/non-root-path" })

	code, body := deviceFlowToken(t, s, deviceBindingKey)
	require.Equal(t, http.StatusOK, code, string(body))

	var resp struct {
		IDToken string `json:"id_token"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	require.NotEmpty(t, resp.IDToken)

	claims := verifyTestIDToken(t, resp.IDToken)
	require.Equal(t, deviceBindingKey, claims["binding_key"])
}

// TestDeviceFlowBindingKeyAbsent: without the parameter nothing changes — the
// flow succeeds and the ID token simply carries no binding_key claim.
func TestDeviceFlowBindingKeyAbsent(t *testing.T) {
	_, s := newTestServer(t, func(c *Config) { c.Issuer += "/non-root-path" })

	code, body := deviceFlowToken(t, s, "")
	require.Equal(t, http.StatusOK, code, string(body))

	var resp struct {
		IDToken string `json:"id_token"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	require.NotEmpty(t, resp.IDToken)

	claims := verifyTestIDToken(t, resp.IDToken)
	require.NotContains(t, claims, "binding_key")
}

// TestAuthorizationCodeFlowNeverEmitsBindingKey: the claim is device-flow only.
// An authorization_code exchange mints no binding_key even though the code flow
// shares the auth-code redemption path (ExchangeAuthCode) with the device flow.
func TestAuthorizationCodeFlowNeverEmitsBindingKey(t *testing.T) {
	ctx := t.Context()
	_, s := newTestServer(t, func(c *Config) { c.Issuer += "/non-root-path" })

	redirectURI := "https://example.com/callback"
	client := storage.Client{
		ID:           "testclient",
		Secret:       "testclientsecret",
		RedirectURIs: []string{redirectURI},
	}
	require.NoError(t, s.storage.CreateClient(ctx, client))

	authCode := storage.AuthCode{
		ID:          "somecode",
		ClientID:    "testclient",
		RedirectURI: redirectURI,
		Scopes:      []string{"openid", "profile"},
		ConnectorID: "mock",
		Claims:      storage.Claims{UserID: "1", Username: "jane", Email: "jane.doe@example.com"},
		Expiry:      time.Now().Add(5 * time.Minute),
	}
	require.NoError(t, s.storage.CreateAuthCode(ctx, authCode))

	u, err := url.Parse(s.issuerURL.String())
	require.NoError(t, err)
	u.Path = path.Join(u.Path, "token")
	form := url.Values{}
	form.Set("grant_type", oauth2.GrantTypeAuthorizationCode)
	form.Set("code", authCode.ID)
	form.Set("redirect_uri", redirectURI)

	req, _ := http.NewRequest("POST", u.String(), bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ID, client.Secret)

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	var resp struct {
		IDToken string `json:"id_token"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.IDToken)

	claims := verifyTestIDToken(t, resp.IDToken)
	require.NotContains(t, claims, "binding_key")
}

// TestRefreshGrantCarriesBindingKey (stretch goal): the ID token re-issued by
// the refresh_token grant carries the binding_key recorded on the refresh token
// at mint, so a device-flow session keeps its holder-key binding across
// refreshes.
func TestRefreshGrantCarriesBindingKey(t *testing.T) {
	ctx := t.Context()
	_, s := newTestServer(t, func(c *Config) { c.Issuer += "/non-root-path" })

	client := storage.Client{
		ID:           "test",
		Secret:       "barfoo",
		RedirectURIs: []string{"foo://bar.com/", "https://auth.example.com"},
	}
	require.NoError(t, s.storage.CreateClient(ctx, client))

	// A refresh token as the device flow mints it for a bound request.
	refresh := storage.RefreshToken{
		ID:          "test",
		Token:       "bar",
		Nonce:       "foo",
		BindingKey:  deviceBindingKey,
		ClientID:    "test",
		ConnectorID: "mock",
		Scopes:      []string{"openid", "email", "profile"},
		CreatedAt:   time.Now().UTC().Round(time.Millisecond),
		LastUsed:    time.Now().UTC().Round(time.Millisecond),
		Claims: storage.Claims{
			UserID:        "1",
			Username:      "jane",
			Email:         "jane.doe@example.com",
			EmailVerified: true,
		},
		// Connector data on the token keeps the refresh flow from re-reading the
		// offline session mid-rotation (the memory store is not re-entrant).
		ConnectorData: []byte(`{"some":"data"}`),
	}
	require.NoError(t, s.storage.CreateRefresh(ctx, refresh))

	offlineSessions := storage.OfflineSessions{
		UserID:  "1",
		ConnID:  "mock",
		Refresh: map[string]*storage.RefreshTokenRef{"test": {ID: "test", ClientID: "test"}},
	}
	require.NoError(t, s.storage.CreateOfflineSessions(ctx, offlineSessions))

	u, err := url.Parse(s.issuerURL.String())
	require.NoError(t, err)
	u.Path = path.Join(u.Path, "token")

	refreshToken, err := internal.Marshal(&internal.RefreshToken{RefreshId: "test", Token: "bar"})
	require.NoError(t, err)

	form := url.Values{}
	form.Set("grant_type", oauth2.GrantTypeRefreshToken)
	form.Set("refresh_token", refreshToken)

	req, _ := http.NewRequest("POST", u.String(), bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ID, client.Secret)

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	var resp struct {
		IDToken string `json:"id_token"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.IDToken)

	claims := verifyTestIDToken(t, resp.IDToken)
	require.Equal(t, deviceBindingKey, claims["binding_key"])
}
