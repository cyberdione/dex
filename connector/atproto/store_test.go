package atproto

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/google/uuid"

	"github.com/dexidp/dex/connector"
)

func testStore(t *testing.T) *stateStore {
	t.Helper()
	store, err := openStore(t.TempDir()+"/state.db", []byte("01234567890123456789012345678901"), 5*time.Minute, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store
}

func TestAuthRequestPersistenceAndOneUseCallbackClaim(t *testing.T) {
	store := testStore(t)
	transactionID := uuid.NewString()
	tx := transaction{ID: transactionID, Status: "initiating", ExpiresAt: time.Now().Add(time.Minute)}
	if err := store.createTransaction(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	ctx, outcome := withLoginTransaction(context.Background(), transactionID)
	info := oauth.AuthRequestData{State: "indigo-state", PKCEVerifier: "secret-verifier-marker", DPoPPrivateKeyMultibase: "secret-dpop-marker"}
	if err := store.SaveAuthRequestInfo(ctx, info); err != nil {
		t.Fatal(err)
	}
	if outcome.err != nil {
		t.Fatal(outcome.err)
	}
	if err := store.markOAuthStarted(transactionID, rosterEntry{DID: "did:plc:abc", Handle: "alice.example"}); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.claimOAuthRequest(info.State)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != transactionID || claimed.Status != "oauth_processing" {
		t.Fatalf("unexpected claimed transaction: %#v", claimed)
	}
	loaded, err := store.GetAuthRequestInfo(context.Background(), info.State)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PKCEVerifier != info.PKCEVerifier || loaded.DPoPPrivateKeyMultibase != info.DPoPPrivateKeyMultibase {
		t.Fatal("encrypted request data did not round-trip")
	}
	if _, err := store.claimOAuthRequest(info.State); err == nil {
		t.Fatal("OAuth state was claimed twice")
	}
	if err := store.DeleteAuthRequestInfo(context.Background(), info.State); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAuthRequestInfo(context.Background(), info.State); err == nil {
		t.Fatal("consumed OAuth state remained usable")
	}
}

func TestBrowserBindingAndOAuthPreviewAreOneUse(t *testing.T) {
	store := testStore(t)
	id := uuid.NewString()
	if err := store.createTransaction(context.Background(), transaction{ID: id, Status: "created", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := store.bindBrowser(id, "browser", "csrf"); err != nil {
		t.Fatal(err)
	}
	if err := store.bindBrowser(id, "other-browser", "other-csrf"); err == nil {
		t.Fatal("browser binding was replaced")
	}
	if _, err := store.beginTransaction(id, "wrong-browser", "csrf"); err == nil {
		t.Fatal("transaction accepted a different browser")
	}
	if _, err := store.beginTransaction(id, "browser", "csrf"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.beginTransaction(id, "browser", "csrf"); err == nil {
		t.Fatal("browser transaction advanced twice")
	}
	if err := store.SaveAuthRequestInfo(withContextForTest(id), oauth.AuthRequestData{State: "state"}); err != nil {
		t.Fatal(err)
	}
	if err := store.markOAuthStarted(id, rosterEntry{DID: "did:plc:abc", Handle: "alice.example"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.previewOAuthRequest("state"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.claimOAuthRequest("state"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.previewOAuthRequest("state"); err == nil {
		t.Fatal("claimed OAuth state passed preflight")
	}
}

func withContextForTest(id string) context.Context {
	ctx, outcome := withLoginTransaction(context.Background(), id)
	_ = outcome
	return ctx
}

func TestCookiePathIsDexIssuerScoped(t *testing.T) {
	if got := cookiePath("/dex/connectors/atproto"); got != "/dex" {
		t.Fatalf("unexpected connector cookie path: %q", got)
	}
}

func TestLoginURLKeepsDexCallbackStateSeparate(t *testing.T) {
	store := testStore(t)
	base, err := url.Parse("https://id.example/dex/connectors/atproto")
	if err != nil {
		t.Fatal(err)
	}
	conn := &atprotoConnector{id: "atproto", base: base, store: store, transactionTTL: 5 * time.Minute}
	loginURL, connData, err := conn.LoginURL(connector.Scopes{}, "https://id.example/dex/callback", "dex-state")
	if err != nil {
		t.Fatal(err)
	}
	parsedLogin, err := url.Parse(loginURL)
	if err != nil {
		t.Fatal(err)
	}
	if parsedLogin.Path != "/dex/connectors/atproto/login" || !validID(parsedLogin.Query().Get("tx")) || string(connData) != parsedLogin.Query().Get("tx") {
		t.Fatalf("unexpected connector login URL or data: %s %q", loginURL, connData)
	}
	tx, err := store.getTransaction(string(connData))
	if err != nil {
		t.Fatal(err)
	}
	if tx.DexState != "dex-state" || tx.DexCallback != "https://id.example/dex/callback/atproto" {
		t.Fatalf("Dex state/callback were not stored independently: %#v", tx)
	}
	if _, _, err := conn.LoginURL(connector.Scopes{}, "https://attacker.example/dex/callback", "other-state"); err == nil {
		t.Fatal("accepted a callback on a different authority")
	}
}

func TestLoginFormUsesDexThemeAndPreservesTransaction(t *testing.T) {
	for _, test := range []struct {
		issuerPath string
		open       bool
		prompt     string
	}{
		{issuerPath: "/dex", open: true, prompt: "AT Protocol handle"},
		{issuerPath: "/", open: false, prompt: "Enrolled handle or DID"},
	} {
		t.Run(test.issuerPath, func(t *testing.T) {
			base, err := url.Parse("https://id.example" + strings.TrimSuffix(test.issuerPath, "/") + "/connectors/atproto")
			if err != nil {
				t.Fatal(err)
			}
			conn := &atprotoConnector{
				id: "atproto", base: base, store: testStore(t),
				config: Config{AllowUnlistedAccounts: test.open}, transactionTTL: 5 * time.Minute,
			}
			loginURL, _, err := conn.LoginURL(connector.Scopes{}, "https://id.example"+strings.TrimSuffix(test.issuerPath, "/")+"/callback", "dex-state")
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			conn.loginForm(response, httptest.NewRequest(http.MethodGet, loginURL, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("login form returned %d", response.Code)
			}
			page := response.Body.String()
			for _, expected := range []string{
				`href="` + strings.TrimSuffix(test.issuerPath, "/") + `/static/main.css"`,
				`href="` + strings.TrimSuffix(test.issuerPath, "/") + `/theme/styles.css"`,
				`class="theme-form-input"`,
				`class="dex-btn theme-btn--primary"`,
				`name="tx"`, `name="csrf"`, `name="account"`, test.prompt,
			} {
				if !strings.Contains(page, expected) {
					t.Errorf("login form missing %q", expected)
				}
			}
			if len(response.Result().Cookies()) != 1 || response.Result().Cookies()[0].Path != test.issuerPath {
				t.Error("login form did not preserve the issuer-scoped browser cookie")
			}
		})
	}
}

func TestOpenAccountEntryBindsVerifiedHandleAndDID(t *testing.T) {
	entry, err := openAccountEntry("Alice.Example", "did:web:alice.example", "alice.example")
	if err != nil {
		t.Fatal(err)
	}
	if entry.DID != "did:web:alice.example" || entry.Handle != "alice.example" || !entry.Enabled {
		t.Fatalf("unexpected open account identity: %#v", entry)
	}

	tests := []struct {
		name, requested, did, handle string
	}{
		{name: "handle mismatch", requested: "alice.example", did: "did:plc:z72i7hdynmk6r22z27h6tvur", handle: "other.example"},
		{name: "invalid DID", requested: "alice.example", did: "not-a-did", handle: "alice.example"},
		{name: "DID input is not accepted in open mode", requested: "did:plc:z72i7hdynmk6r22z27h6tvur", did: "did:plc:z72i7hdynmk6r22z27h6tvur", handle: "alice.example"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := openAccountEntry(test.requested, test.did, test.handle); err == nil {
				t.Fatal("accepted an invalid open account identity")
			}
		})
	}
}

func TestOpenAccountClaimsDoNotGrantWorkshopMembership(t *testing.T) {
	did, handle := "did:plc:abc", "alice.example"
	open := identityForVerifiedAccount(did, handle, true)
	if open.UserID != did || open.PreferredUsername != handle || len(open.Groups) != 0 {
		t.Fatalf("open account must expose verified identity without workshop authorization: %#v", open)
	}
	rostered := identityForVerifiedAccount(did, handle, false)
	if len(rostered.Groups) != 1 || rostered.Groups[0] != "workshop-attendee" {
		t.Fatalf("roster mode lost its workshop claim: %#v", rostered)
	}
}

func TestEncryptedStateAndSingleUseDexCompletion(t *testing.T) {
	store := testStore(t)
	id := uuid.NewString()
	ticket, browser := "completion-ticket-marker", "browser-cookie-marker"
	identity := connector.Identity{UserID: "did:plc:abc", PreferredUsername: "alice.example", Email: "", EmailVerified: false}
	tx := transaction{ID: id, DexState: "dex-state", DexCallback: "https://dex.example/callback/atproto", Status: "oauth_processing", ExpiresAt: time.Now().Add(time.Minute), BrowserHash: digest(browser)}
	if err := store.createTransaction(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if err := store.finishTransaction(id, "complete", transaction{TicketHash: digest(ticket), Identity: identity}); err != nil {
		t.Fatal(err)
	}
	var payload []byte
	if err := store.db.QueryRow(`SELECT payload FROM atproto_transactions WHERE id=?`, id).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), ticket) || strings.Contains(string(payload), browser) || strings.Contains(string(payload), identity.UserID) {
		t.Fatal("sensitive transaction fields are stored in plaintext")
	}
	got, err := store.consumeCompletion(id, "dex-state", ticket, browser)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != identity.UserID || got.PreferredUsername != identity.PreferredUsername {
		t.Fatalf("wrong identity: %#v", got)
	}
	if _, err := store.consumeCompletion(id, "dex-state", ticket, browser); err == nil {
		t.Fatal("Dex completion ticket was consumed twice")
	}
}

type responseTransport struct{ response *http.Response }

func (r responseTransport) RoundTrip(*http.Request) (*http.Response, error) { return r.response, nil }

func TestDPoPResponseRequiresServerNonce(t *testing.T) {
	request, _ := http.NewRequest(http.MethodPost, "https://pds.example/token", nil)
	request.Header.Set("DPoP", "proof")
	response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}
	if _, err := (requireDPoPNonce{next: responseTransport{response}}).RoundTrip(request); err == nil {
		t.Fatal("accepted DPoP response with no nonce")
	}
	response = &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Dpop-Nonce": []string{"server-nonce"}}, Body: http.NoBody}
	if _, err := (requireDPoPNonce{next: responseTransport{response}}).RoundTrip(request); err != nil {
		t.Fatalf("rejected response containing required nonce: %v", err)
	}
}
