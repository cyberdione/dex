// Package atproto authenticates atproto identities with atproto OAuth and can
// optionally restrict identities to an operator-maintained roster.
package atproto

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/ghodss/yaml"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/dexidp/dex/connector"
)

const (
	maxFormBytes          = 4096
	maxRosterBytes        = 1 << 20
	defaultTransactionTTL = 5 * time.Minute
	defaultCompletionTTL  = 30 * time.Second
)

// Config is the atproto connector configuration. PublicBaseURL is the
// externally reachable Dex-prefixed connector route base.
type Config struct {
	Workshop               string `json:"workshop"`
	PublicBaseURL          string `json:"publicBaseURL"`
	RosterFile             string `json:"rosterFile"`
	AllowUnlistedAccounts  bool   `json:"allowUnlistedAccounts"`
	StateDB                string `json:"stateDB"`
	StateEncryptionKeyFile string `json:"stateEncryptionKeyFile"`
	ClientKeyFile          string `json:"clientKeyFile"`
	ClientKeyID            string `json:"clientKeyID"`
	TransactionTTL         string `json:"transactionTTL"`
	CompletionTTL          string `json:"completionTTL"`
}

// Open implements connectors.ConnectorConfig.
func (c *Config) Open(id string, logger *slog.Logger) (connector.Connector, error) {
	base, err := url.Parse(c.PublicBaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.RawPath != "" {
		return nil, fmt.Errorf("atproto publicBaseURL must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	if id == "" || base.Path != path.Join(path.Dir(path.Dir(base.Path)), "connectors", id) {
		return nil, fmt.Errorf("atproto publicBaseURL path must end in /connectors/%s", id)
	}
	if c.Workshop == "" || c.RosterFile == "" || c.StateDB == "" || c.StateEncryptionKeyFile == "" || c.ClientKeyFile == "" || c.ClientKeyID == "" {
		return nil, fmt.Errorf("atproto workshop, rosterFile, stateDB, stateEncryptionKeyFile, clientKeyFile, and clientKeyID are required")
	}
	transactionTTL, err := parseDuration(c.TransactionTTL, defaultTransactionTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid atproto transactionTTL: %w", err)
	}
	completionTTL, err := parseDuration(c.CompletionTTL, defaultCompletionTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid atproto completionTTL: %w", err)
	}
	if transactionTTL < time.Minute || transactionTTL > 15*time.Minute || completionTTL < 5*time.Second || completionTTL > time.Minute {
		return nil, fmt.Errorf("atproto transactionTTL must be 1m..15m and completionTTL 5s..1m")
	}

	key, err := os.ReadFile(c.StateEncryptionKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read atproto state encryption key: %w", err)
	}
	keyInfo, err := os.Stat(c.StateEncryptionKeyFile)
	if err != nil || !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm()&0o077 != 0 || len(key) != 32 {
		return nil, fmt.Errorf("atproto state encryption key must be a 32-byte regular file with no group/other permissions")
	}
	privateKeyText, err := os.ReadFile(c.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read atproto client key: %w", err)
	}
	clientKeyInfo, err := os.Stat(c.ClientKeyFile)
	if err != nil || !clientKeyInfo.Mode().IsRegular() || clientKeyInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("atproto client key must be a regular file with no group/other permissions")
	}
	privateKey, err := atcrypto.ParsePrivateMultibase(strings.TrimSpace(string(privateKeyText)))
	if err != nil {
		return nil, fmt.Errorf("parse atproto client key: %w", err)
	}

	store, err := openStore(c.StateDB, key, transactionTTL, completionTTL)
	if err != nil {
		return nil, err
	}
	clientConfig := oauth.NewPublicConfig(c.PublicBaseURL+"/client-metadata.json", c.PublicBaseURL+"/oauth/callback", []string{"atproto"})
	if err := clientConfig.SetClientSecret(privateKey, c.ClientKeyID); err != nil {
		store.Close()
		return nil, fmt.Errorf("configure atproto confidential client: %w", err)
	}
	client := oauth.NewClientApp(&clientConfig, store)
	client.Client.Transport = requireDPoPNonce{next: client.Client.Transport}
	conn := &atprotoConnector{id: id, config: *c, base: base, store: store, client: client, transactionTTL: transactionTTL, logger: logger.With(slog.String("connector", id))}
	return conn, nil
}

type atprotoConnector struct {
	id             string
	config         Config
	base           *url.URL
	store          *stateStore
	client         *oauth.ClientApp
	transactionTTL time.Duration
	logger         *slog.Logger
}

var (
	_ connector.CallbackConnector         = (*atprotoConnector)(nil)
	_ connector.HTTPHandlerConnector      = (*atprotoConnector)(nil)
	_ connector.CallbackCompletionHandler = (*atprotoConnector)(nil)
	_ connector.RefreshConnector          = (*atprotoConnector)(nil)
)

func (c *atprotoConnector) LoginURL(scopes connector.Scopes, callbackURL, dexState string) (string, []byte, error) {
	if dexState == "" {
		return "", nil, fmt.Errorf("missing Dex authorization state")
	}
	callback, err := url.Parse(callbackURL)
	expectedCallbackPath := path.Join(path.Dir(path.Dir(c.base.Path)), "callback")
	if err != nil || callback.Scheme != "https" || callback.Host != c.base.Host || callback.Path != expectedCallbackPath || callback.User != nil || callback.RawQuery != "" || callback.Fragment != "" {
		return "", nil, fmt.Errorf("invalid Dex callback URL")
	}
	callback.Path = path.Join(callback.Path, c.id)
	txID := uuid.NewString()
	state := transaction{ID: txID, DexState: dexState, DexCallback: callback.String(), Status: "created", ExpiresAt: time.Now().Add(c.transactionTTL)}
	if err := c.store.createTransaction(context.Background(), state); err != nil {
		return "", nil, fmt.Errorf("create atproto transaction: %w", err)
	}
	loginURL := *c.base
	loginURL.Path = path.Join(loginURL.Path, "login")
	query := loginURL.Query()
	query.Set("tx", txID)
	loginURL.RawQuery = query.Encode()
	return loginURL.String(), []byte(txID), nil
}

func (c *atprotoConnector) HandleCallback(scopes connector.Scopes, connData []byte, r *http.Request) (connector.Identity, error) {
	txID := string(connData)
	if !validID(txID) || len(r.URL.Query()["state"]) != 1 || len(r.URL.Query()["ticket"]) != 1 {
		return connector.Identity{}, fmt.Errorf("invalid atproto completion")
	}
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie(cookieName(txID))
	if err != nil {
		return connector.Identity{}, fmt.Errorf("missing atproto browser binding")
	}
	identity, err := c.store.consumeCompletion(txID, state, r.URL.Query().Get("ticket"), cookie.Value)
	if err != nil {
		return connector.Identity{}, err
	}
	return identity, nil
}

func (c *atprotoConnector) CallbackCompleted(w http.ResponseWriter, r *http.Request, connData []byte) {
	txID := string(connData)
	if !validID(txID) {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName(txID), Value: "", Path: cookiePath(c.base.Path), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// Refresh implements connector.RefreshConnector. It re-attests a previously
// issued identity without user interaction: the subject DID is re-resolved
// through the AT Protocol directory and, in roster mode, the roster entry is
// re-read and re-verified, mirroring the checks the OAuth callback applies
// after authorization. A deleted account, an unresolvable DID, a handle that
// no longer verifies against the DID, or a disabled/expired roster entry
// fails closed and denies the refresh. The subject (UserID) is the DID and is
// never rewritten, keeping ID token subjects stable across refreshes; the
// handle claims follow the current verified state of the DID document.
func (c *atprotoConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	did, err := syntax.ParseAtIdentifier(strings.TrimSpace(identity.UserID))
	if err != nil || !did.IsDID() {
		return connector.Identity{}, fmt.Errorf("atproto refresh requires a DID subject")
	}
	var handle string
	if c.config.AllowUnlistedAccounts {
		if err := c.client.Dir.Purge(ctx, did); err != nil {
			return connector.Identity{}, fmt.Errorf("purge atproto DID cache: %w", err)
		}
		verified, err := c.client.Dir.Lookup(ctx, did)
		if err != nil {
			return connector.Identity{}, fmt.Errorf("resolve atproto DID: %w", err)
		}
		if verified == nil || verified.DID.String() != did.String() {
			return connector.Identity{}, fmt.Errorf("atproto DID resolution mismatch")
		}
		// Lookup by DID reports a failed bidirectional handle verification as
		// the handle.invalid sentinel instead of an error. Treat it as a
		// failed re-attestation: the handle can no longer be verified against
		// the DID, so the identity must not be silently extended.
		if verified.Handle.IsInvalidHandle() {
			return connector.Identity{}, fmt.Errorf("atproto handle no longer verifies against the DID")
		}
		handle = verified.Handle.String()
	} else {
		current, err := c.rosterEntry(did.String())
		if err == nil {
			err = c.verifyRosterIdentity(ctx, current)
		}
		if err != nil {
			return connector.Identity{}, fmt.Errorf("atproto roster identity no longer verified: %w", err)
		}
		handle = current.Handle
	}
	return identityForVerifiedAccount(did.String(), handle, c.config.AllowUnlistedAccounts), nil
}

// ConnectorHTTPHandler serves only the finite protocol routes owned by this
// connector. Dex's auth endpoints and callback remain separately dispatched.
func (c *atprotoConnector) ConnectorHTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /client-metadata.json", c.clientMetadata)
	mux.HandleFunc("GET /jwks.json", c.jwks)
	mux.HandleFunc("GET /login", c.loginForm)
	mux.HandleFunc("POST /login", c.beginLogin)
	mux.HandleFunc("GET /oauth/callback", c.oauthCallback)
	return mux
}

func (c *atprotoConnector) clientMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := c.client.Config.ClientMetadata()
	metadata.GrantTypes = []string{"authorization_code"}
	metadata.JWKSURI = stringPtr(c.config.PublicBaseURL + "/jwks.json")
	metadata.ClientName = stringPtr("Federate by Cyberdione Labs")
	metadata.ClientURI = stringPtr(c.base.Scheme + "://" + c.base.Host + "/")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		c.logger.Error("encode atproto client metadata", "err", err)
	}
}

func (c *atprotoConnector) jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := json.NewEncoder(w).Encode(c.client.Config.PublicJWKS()); err != nil {
		c.logger.Error("encode atproto client JWKS", "err", err)
	}
}

var loginPage = template.Must(template.New("atproto-login").Parse(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in with AT Protocol | Federate</title>
    <link href="{{.MainCSS}}" rel="stylesheet">
    <link href="{{.ThemeCSS}}" rel="stylesheet">
    <link rel="icon" href="{{.Favicon}}">
  </head>
  <body class="theme-body">
    <div class="theme-navbar">
      <div class="theme-navbar__logo-wrap">
        <img class="theme-navbar__logo" src="{{.Logo}}" alt="">
        <span class="theme-navbar__brand">
          <span class="theme-navbar__brand-name">Federate</span>
          <span class="theme-navbar__brand-byline">by Cyberdione Labs</span>
        </span>
      </div>
    </div>
    <main class="dex-container">
      <div class="theme-panel">
        <h1 class="theme-heading">Sign in with AT Protocol</h1>
        <form method="post" action="login">
          <input type="hidden" name="tx" value="{{.Transaction}}">
          <input type="hidden" name="csrf" value="{{.CSRF}}">
          <div class="theme-form-row">
            <div class="theme-form-label"><label for="account">{{.AccountPrompt}}</label></div>
            <input id="account" name="account" type="text" class="theme-form-input"
              placeholder="{{.AccountPlaceholder}}" required autocomplete="username"
              autocapitalize="none" spellcheck="false" autofocus>
          </div>
          <p class="dex-subtle-text">{{.AccountHint}}</p>
          <button type="submit" class="dex-btn theme-btn--primary">Continue to AT Protocol</button>
        </form>
        <p class="theme-login-notice">By signing in, you agree to Federate’s <a href="{{.TermsURL}}">Terms of Service</a> and acknowledge its <a href="{{.PrivacyURL}}">Privacy Policy</a>.</p>
      </div>
    </main>
    <footer class="theme-footer">
      <div class="theme-footer__inner">
        <span>© {{.Year}} Cyberdione Labs Corporation. All rights reserved.</span>
        <nav aria-label="Legal and company">
          <a href="{{.TermsURL}}">Terms of Service</a>
          <a href="{{.PrivacyURL}}">Privacy Policy</a>
          <a href="https://www.cyberdione.com/">Company</a>
        </nav>
      </div>
    </footer>
  </body>
</html>`))

func (c *atprotoConnector) loginForm(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Query()["tx"]) != 1 || !validID(r.URL.Query().Get("tx")) {
		http.Error(w, "invalid login transaction", http.StatusBadRequest)
		return
	}
	txID := r.URL.Query().Get("tx")
	tx, err := c.store.getTransaction(txID)
	if err != nil || tx.Status != "created" || time.Now().After(tx.ExpiresAt) {
		http.Error(w, "login transaction expired", http.StatusGone)
		return
	}
	csrf, err := randomToken()
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	browser, err := randomToken()
	if err != nil || c.store.bindBrowser(txID, browser, csrf) != nil {
		http.Error(w, "login transaction already used", http.StatusConflict)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName(txID), Value: browser, Path: cookiePath(c.base.Path), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(c.transactionTTL.Seconds())})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	accountPrompt := "Enrolled handle or DID"
	accountPlaceholder := "alice.bsky.social or did:plc:..."
	accountHint := "Enter the handle or DID registered for your account."
	if c.config.AllowUnlistedAccounts {
		accountPrompt = "AT Protocol handle"
		accountPlaceholder = "alice.bsky.social"
		accountHint = "Enter your handle to continue to your account's authorization page."
	}
	issuerPath := path.Dir(path.Dir(c.base.Path))
	if err := loginPage.Execute(w, struct {
		Transaction        string
		CSRF               string
		AccountPrompt      string
		AccountPlaceholder string
		AccountHint        string
		MainCSS            string
		ThemeCSS           string
		Favicon            string
		Logo               string
		TermsURL           string
		PrivacyURL         string
		Year               int
	}{
		Transaction:        txID,
		CSRF:               csrf,
		AccountPrompt:      accountPrompt,
		AccountPlaceholder: accountPlaceholder,
		AccountHint:        accountHint,
		MainCSS:            path.Join(issuerPath, "static/main.css"),
		ThemeCSS:           path.Join(issuerPath, "theme/styles.css"),
		Favicon:            path.Join(issuerPath, "theme/favicon.png"),
		Logo:               path.Join(issuerPath, "theme/logo.png"),
		TermsURL:           path.Join(issuerPath, "static/legal/terms.html"),
		PrivacyURL:         path.Join(issuerPath, "static/legal/privacy.html"),
		Year:               time.Now().Year(),
	}); err != nil {
		c.logger.Error("render atproto login form", "err", err)
	}
}

func (c *atprotoConnector) beginLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil || len(r.PostForm["tx"]) != 1 || len(r.PostForm["csrf"]) != 1 || len(r.PostForm["account"]) != 1 {
		http.Error(w, "invalid login form", http.StatusBadRequest)
		return
	}
	txID, account := r.PostForm.Get("tx"), strings.TrimSpace(r.PostForm.Get("account"))
	cookie, err := r.Cookie(cookieName(txID))
	if err != nil || !validID(txID) {
		http.Error(w, "login transaction expired", http.StatusGone)
		return
	}
	tx, err := c.store.beginTransaction(txID, cookie.Value, r.PostForm.Get("csrf"))
	if err != nil || time.Now().After(tx.ExpiresAt) {
		http.Error(w, "login transaction expired or already used", http.StatusGone)
		return
	}
	entry, err := c.accountEntry(r.Context(), account)
	if err != nil {
		c.store.finishTransaction(txID, "denied", transaction{})
		http.Error(w, "atproto account is not allowed", http.StatusForbidden)
		return
	}
	if !c.config.AllowUnlistedAccounts {
		err = c.verifyRosterIdentity(r.Context(), entry)
	}
	if err != nil {
		c.store.finishTransaction(txID, "denied", transaction{})
		http.Error(w, "account identity could not be verified", http.StatusForbidden)
		return
	}
	ctx, saveOutcome := withLoginTransaction(r.Context(), txID)
	redirectURL, err := c.client.StartAuthFlow(ctx, entry.Handle)
	if err == nil && saveOutcome.err != nil {
		err = saveOutcome.err
	}
	if err != nil {
		c.store.finishTransaction(txID, "failed", transaction{})
		c.logger.WarnContext(r.Context(), "start atproto authorization", "err", err)
		http.Error(w, "atproto authorization could not be started", http.StatusBadGateway)
		return
	}
	if err := c.store.markOAuthStarted(txID, entry); err != nil {
		http.Error(w, "atproto authorization could not be stored", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (c *atprotoConnector) oauthCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if len(query["state"]) != 1 || len(query["iss"]) > 1 || len(query["code"]) > 1 {
		http.Error(w, "invalid atproto callback", http.StatusBadRequest)
		return
	}
	state := query.Get("state")
	tx, err := c.store.previewOAuthRequest(state)
	if err != nil {
		http.Error(w, "atproto login expired or already used", http.StatusGone)
		return
	}
	cookie, err := r.Cookie(cookieName(tx.ID))
	if err != nil || !sameSecret(tx.BrowserHash, cookie.Value) {
		http.Error(w, "atproto browser binding failed", http.StatusForbidden)
		return
	}
	claimed, err := c.store.claimOAuthRequest(state)
	if err != nil || claimed.ID != tx.ID {
		http.Error(w, "atproto login expired or already used", http.StatusGone)
		return
	}
	tx = claimed
	session, err := c.client.ProcessCallback(r.Context(), query)
	if err != nil {
		c.store.finishTransaction(tx.ID, "failed", transaction{})
		c.logger.WarnContext(r.Context(), "complete atproto authorization", "err", err)
		http.Error(w, "atproto authorization failed", http.StatusBadGateway)
		return
	}
	if session.AccountDID.String() != tx.ExpectedDID || !contains(session.Scopes, "atproto") {
		c.store.finishTransaction(tx.ID, "denied", transaction{})
		http.Error(w, "atproto account or scope mismatch", http.StatusForbidden)
		return
	}
	var current rosterEntry
	if c.config.AllowUnlistedAccounts {
		current, err = c.openAccountEntry(r.Context(), tx.ExpectedHandle)
	} else {
		current, err = c.rosterEntry(tx.ExpectedDID)
		if err == nil {
			err = c.verifyRosterIdentity(r.Context(), current)
		}
	}
	if err != nil || current.DID != tx.ExpectedDID || !strings.EqualFold(current.Handle, tx.ExpectedHandle) {
		c.store.finishTransaction(tx.ID, "denied", transaction{})
		http.Error(w, "atproto handle is no longer verified", http.StatusForbidden)
		return
	}
	identity := identityForVerifiedAccount(tx.ExpectedDID, tx.ExpectedHandle, c.config.AllowUnlistedAccounts)
	ticket, err := randomToken()
	if err != nil || c.store.finishTransaction(tx.ID, "complete", transaction{TicketHash: digest(ticket), Identity: identity}) != nil {
		http.Error(w, "atproto completion could not be stored", http.StatusInternalServerError)
		return
	}
	completion, err := url.Parse(tx.DexCallback)
	if err != nil {
		http.Error(w, "invalid Dex callback", http.StatusInternalServerError)
		return
	}
	params := completion.Query()
	params.Set("state", tx.DexState)
	params.Set("ticket", ticket)
	completion.RawQuery = params.Encode()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, completion.String(), http.StatusSeeOther)
}

func identityForVerifiedAccount(did, handle string, allowUnlistedAccounts bool) connector.Identity {
	identity := connector.Identity{UserID: did, Username: handle, PreferredUsername: handle, Email: "", EmailVerified: false}
	if !allowUnlistedAccounts {
		identity.Groups = []string{"workshop-attendee"}
	}
	return identity
}

func (c *atprotoConnector) accountEntry(ctx context.Context, account string) (rosterEntry, error) {
	if c.config.AllowUnlistedAccounts {
		return c.openAccountEntry(ctx, account)
	}
	return c.rosterEntry(account)
}

// openAccountEntry resolves a submitted handle through Indigo and binds it to
// the currently verified DID. The caller repeats this resolution after OAuth,
// so a handle change or transfer during login fails closed.
func (c *atprotoConnector) openAccountEntry(ctx context.Context, account string) (rosterEntry, error) {
	parsed, err := syntax.ParseAtIdentifier(strings.ToLower(strings.TrimSpace(account)))
	if err != nil || !parsed.IsHandle() {
		return rosterEntry{}, fmt.Errorf("open atproto login requires a handle")
	}
	handle := parsed.String()
	if err := c.client.Dir.Purge(ctx, parsed); err != nil {
		return rosterEntry{}, fmt.Errorf("purge handle cache: %w", err)
	}
	verified, err := c.client.Dir.Lookup(ctx, parsed)
	if err != nil {
		return rosterEntry{}, fmt.Errorf("resolve and verify atproto handle: %w", err)
	}
	return openAccountEntry(handle, verified.DID.String(), verified.Handle.String())
}

func openAccountEntry(requestedHandle, didValue, handleValue string) (rosterEntry, error) {
	requested, err := syntax.ParseAtIdentifier(strings.ToLower(strings.TrimSpace(requestedHandle)))
	if err != nil || !requested.IsHandle() {
		return rosterEntry{}, fmt.Errorf("open atproto login requires a handle")
	}
	did, err := syntax.ParseAtIdentifier(didValue)
	if err != nil || !did.IsDID() {
		return rosterEntry{}, fmt.Errorf("atproto account did is invalid")
	}
	handle, err := syntax.ParseAtIdentifier(handleValue)
	if err != nil || !handle.IsHandle() || handle.String() != strings.ToLower(handleValue) || !strings.EqualFold(requested.String(), handle.String()) {
		return rosterEntry{}, fmt.Errorf("atproto handle is not verified")
	}
	return rosterEntry{DID: did.String(), Handle: handle.String(), Enabled: true}, nil
}

func (c *atprotoConnector) rosterEntry(account string) (rosterEntry, error) {
	var roster rosterFile
	b, err := os.ReadFile(c.config.RosterFile)
	if err != nil || len(b) > maxRosterBytes || yaml.Unmarshal(b, &roster) != nil || roster.Workshop != c.config.Workshop || roster.Version < 1 {
		return rosterEntry{}, fmt.Errorf("could not read valid roster")
	}
	atid, err := syntax.ParseAtIdentifier(account)
	if err != nil {
		return rosterEntry{}, err
	}
	var found *rosterEntry
	dids := make(map[string]struct{})
	handles := make(map[string]struct{})
	for i := range roster.Attendees {
		entry := &roster.Attendees[i]
		if !entry.Enabled {
			continue
		}
		end, err := time.Parse(time.RFC3339, entry.ValidUntil)
		if err != nil {
			return rosterEntry{}, fmt.Errorf("invalid active roster expiry")
		}
		if !end.After(time.Now()) {
			continue
		}
		did, err := syntax.ParseAtIdentifier(entry.DID)
		if err != nil || !did.IsDID() || !strings.HasPrefix(entry.DID, "did:plc:") {
			return rosterEntry{}, fmt.Errorf("invalid active roster DID")
		}
		handle, err := syntax.ParseAtIdentifier(entry.Handle)
		if err != nil || !handle.IsHandle() || entry.Handle != strings.ToLower(entry.Handle) {
			return rosterEntry{}, fmt.Errorf("invalid active roster handle")
		}
		if _, exists := dids[entry.DID]; exists {
			return rosterEntry{}, fmt.Errorf("duplicate active roster DID")
		}
		normalizedHandle := strings.ToLower(entry.Handle)
		if _, exists := handles[normalizedHandle]; exists {
			return rosterEntry{}, fmt.Errorf("duplicate active roster handle")
		}
		dids[entry.DID] = struct{}{}
		handles[normalizedHandle] = struct{}{}
		if (atid.IsDID() && atid.String() != entry.DID) || (atid.IsHandle() && !strings.EqualFold(atid.String(), entry.Handle)) {
			continue
		}
		if found != nil {
			return rosterEntry{}, fmt.Errorf("ambiguous roster entry")
		}
		found = entry
	}
	if found == nil {
		return rosterEntry{}, fmt.Errorf("roster miss")
	}
	return *found, nil
}

func (c *atprotoConnector) verifyRosterIdentity(ctx context.Context, entry rosterEntry) error {
	did, err := syntax.ParseAtIdentifier(entry.DID)
	if err != nil || !did.IsDID() || !strings.HasPrefix(entry.DID, "did:plc:") {
		return fmt.Errorf("roster DID must be a valid did:plc identifier")
	}
	handle, err := syntax.ParseAtIdentifier(entry.Handle)
	if err != nil || !handle.IsHandle() {
		return fmt.Errorf("invalid roster handle")
	}
	if err := c.client.Dir.Purge(ctx, handle); err != nil {
		return fmt.Errorf("purge handle cache: %w", err)
	}
	verified, err := c.client.Dir.Lookup(ctx, handle)
	if err != nil {
		return fmt.Errorf("resolve and verify roster handle: %w", err)
	}
	if verified.DID.String() != entry.DID || !strings.EqualFold(verified.Handle.String(), entry.Handle) {
		return fmt.Errorf("roster handle and DID no longer match")
	}
	return nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func stringPtr(value string) *string { return &value }

func parseDuration(value string, fallback time.Duration) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	return time.ParseDuration(value)
}

func validID(id string) bool {
	if len(id) != 36 {
		return false
	}
	_, err := uuid.Parse(id)
	return err == nil
}

func cookieName(txID string) string { return "atproto_tx_" + strings.ReplaceAll(txID, "-", "_") }

func cookiePath(basePath string) string {
	parent := path.Dir(path.Dir(basePath))
	if parent == "." || parent == "/" {
		return "/"
	}
	return parent
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func sameSecret(expectedHash, value string) bool {
	got, err := hex.DecodeString(digest(value))
	want, wantErr := hex.DecodeString(expectedHash)
	return err == nil && wantErr == nil && subtle.ConstantTimeCompare(got, want) == 1
}

type nonceTransport struct{ next http.RoundTripper }

func (t nonceTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if request.Header.Get("DPoP") != "" && response.Header.Get("DPoP-Nonce") == "" {
		response.Body.Close()
		return nil, fmt.Errorf("atproto OAuth response omitted the required DPoP-Nonce header")
	}
	return response, nil
}

// requireDPoPNonce is the typed transport wrapper used by Config.Open.
type requireDPoPNonce struct{ next http.RoundTripper }

func (t requireDPoPNonce) RoundTrip(request *http.Request) (*http.Response, error) {
	next := t.next
	if next == nil {
		next = http.DefaultTransport
	}
	return nonceTransport{next: next}.RoundTrip(request)
}

// Keep imports and the interface contract checked as the Indigo API evolves.
var (
	_ oauth.ClientAuthStore      = (*stateStore)(nil)
	_ interface{ Close() error } = (*stateStore)(nil)
)
