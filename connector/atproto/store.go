package atproto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/dexidp/dex/connector"
)

type rosterFile struct {
	Workshop  string        `json:"workshop"`
	Version   int           `json:"version"`
	Attendees []rosterEntry `json:"attendees"`
}

type rosterEntry struct {
	DID         string   `json:"did"`
	Handle      string   `json:"handle"`
	Enabled     bool     `json:"enabled"`
	VMIDs       []string `json:"vmIds"`
	UnixAccount string   `json:"unixAccount"`
	ValidUntil  string   `json:"validUntil"`
}

type transaction struct {
	ID             string             `json:"id"`
	DexState       string             `json:"dexState"`
	DexCallback    string             `json:"dexCallback"`
	Status         string             `json:"status"`
	ExpiresAt      time.Time          `json:"expiresAt"`
	BrowserHash    string             `json:"browserHash,omitempty"`
	CSRFHash       string             `json:"csrfHash,omitempty"`
	ExpectedDID    string             `json:"expectedDID,omitempty"`
	ExpectedHandle string             `json:"expectedHandle,omitempty"`
	TicketHash     string             `json:"ticketHash,omitempty"`
	TicketExpiry   time.Time          `json:"ticketExpiry,omitempty"`
	Identity       connector.Identity `json:"identity,omitempty"`
}

type stateStore struct {
	db             *sql.DB
	aead           cipher.AEAD
	transactionTTL time.Duration
	completionTTL  time.Duration
}

type loginContextKey struct{}
type saveOutcomeKey struct{}
type saveOutcome struct{ err error }

func withLoginTransaction(ctx context.Context, transactionID string) (context.Context, *saveOutcome) {
	outcome := &saveOutcome{}
	ctx = context.WithValue(ctx, loginContextKey{}, transactionID)
	ctx = context.WithValue(ctx, saveOutcomeKey{}, outcome)
	return ctx, outcome
}

func openStore(filename string, encryptionKey []byte, transactionTTL, completionTTL time.Duration) (*stateStore, error) {
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		return nil, fmt.Errorf("create atproto state directory: %w", err)
	}
	db, err := sql.Open("sqlite3", filename+"?_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("open atproto state database: %w", err)
	}
	db.SetMaxOpenConns(1)
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		db.Close()
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		db.Close()
		return nil, err
	}
	store := &stateStore{db: db, aead: aead, transactionTTL: transactionTTL, completionTTL: completionTTL}
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS atproto_transactions (
 id TEXT PRIMARY KEY,
 expires_at INTEGER NOT NULL,
 payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS atproto_oauth_requests (
 state TEXT PRIMARY KEY,
 transaction_id TEXT NOT NULL REFERENCES atproto_transactions(id) ON DELETE CASCADE,
 status TEXT NOT NULL,
 expires_at INTEGER NOT NULL,
 payload BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS atproto_transactions_expiry ON atproto_transactions(expires_at);
CREATE INDEX IF NOT EXISTS atproto_oauth_expiry ON atproto_oauth_requests(expires_at);`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize atproto state database: %w", err)
	}
	_, err = db.Exec(`DELETE FROM atproto_oauth_requests WHERE expires_at <= ?; DELETE FROM atproto_transactions WHERE expires_at <= ?`, time.Now().Unix(), time.Now().Unix())
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("garbage-collect atproto state: %w", err)
	}
	if err := os.Chmod(filename, 0600); err != nil {
		db.Close()
		return nil, fmt.Errorf("restrict atproto state database permissions: %w", err)
	}
	return store, nil
}

func (s *stateStore) Close() error { return s.db.Close() }

func (s *stateStore) seal(aad string, value any) ([]byte, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plain, []byte(aad)), nil
}

func (s *stateStore) open(aad string, encrypted []byte, value any) error {
	if len(encrypted) < s.aead.NonceSize() {
		return fmt.Errorf("truncated encrypted atproto state")
	}
	nonce := encrypted[:s.aead.NonceSize()]
	plain, err := s.aead.Open(nil, nonce, encrypted[s.aead.NonceSize():], []byte(aad))
	if err != nil {
		return fmt.Errorf("decrypt atproto state: %w", err)
	}
	return json.Unmarshal(plain, value)
}

func (s *stateStore) createTransaction(ctx context.Context, tx transaction) error {
	data, err := s.seal("transaction:"+tx.ID, tx)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO atproto_transactions(id, expires_at, payload) VALUES(?, ?, ?)`, tx.ID, tx.ExpiresAt.Unix(), data)
	return err
}

func (s *stateStore) getTransaction(id string) (transaction, error) {
	var data []byte
	var tx transaction
	err := s.db.QueryRow(`SELECT payload FROM atproto_transactions WHERE id=? AND expires_at>?`, id, time.Now().Unix()).Scan(&data)
	if err != nil {
		return tx, err
	}
	err = s.open("transaction:"+id, data, &tx)
	return tx, err
}

func (s *stateStore) bindBrowser(id, browser, csrf string) error {
	return s.updateTransaction(id, func(tx *transaction) error {
		if tx.Status != "created" || tx.BrowserHash != "" {
			return fmt.Errorf("transaction is already bound or expired")
		}
		tx.BrowserHash, tx.CSRFHash = digest(browser), digest(csrf)
		return nil
	})
}

func (s *stateStore) beginTransaction(id, browser, csrf string) (transaction, error) {
	var result transaction
	err := s.updateTransaction(id, func(tx *transaction) error {
		if tx.Status != "created" || !sameSecret(tx.BrowserHash, browser) || !sameSecret(tx.CSRFHash, csrf) {
			return fmt.Errorf("browser binding, CSRF, or state mismatch")
		}
		tx.Status = "initiating"
		result = *tx
		return nil
	})
	return result, err
}

func (s *stateStore) markOAuthStarted(id string, entry rosterEntry) error {
	return s.updateTransaction(id, func(tx *transaction) error {
		if tx.Status != "initiating" {
			return fmt.Errorf("transaction has already advanced")
		}
		tx.Status, tx.ExpectedDID, tx.ExpectedHandle = "oauth_pending", entry.DID, entry.Handle
		return nil
	})
}

func (s *stateStore) finishTransaction(id, status string, result transaction) error {
	return s.updateTransaction(id, func(tx *transaction) error {
		switch status {
		case "complete":
			if tx.Status != "oauth_processing" || result.TicketHash == "" {
				return fmt.Errorf("OAuth transaction was not claimed")
			}
			tx.TicketHash, tx.TicketExpiry, tx.Identity = result.TicketHash, time.Now().Add(s.completionTTL), result.Identity
		case "failed", "denied":
			if tx.Status != "initiating" && tx.Status != "oauth_processing" {
				return fmt.Errorf("transaction cannot finish from status %q", tx.Status)
			}
		default:
			return fmt.Errorf("invalid terminal transaction status %q", status)
		}
		tx.Status = status
		return nil
	})
}

// updateTransaction serializes read/check/write transitions in SQLite so two
// concurrent requests cannot both advance the same browser transaction.
func (s *stateStore) updateTransaction(id string, update func(*transaction) error) error {
	dbtx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer dbtx.Rollback()
	var data []byte
	if err := dbtx.QueryRow(`SELECT payload FROM atproto_transactions WHERE id=? AND expires_at>?`, id, time.Now().Unix()).Scan(&data); err != nil {
		return err
	}
	var tx transaction
	if err := s.open("transaction:"+id, data, &tx); err != nil {
		return err
	}
	if err := update(&tx); err != nil {
		return err
	}
	sealed, err := s.seal("transaction:"+id, tx)
	if err != nil {
		return err
	}
	res, err := dbtx.Exec(`UPDATE atproto_transactions SET payload=? WHERE id=? AND expires_at>?`, sealed, id, time.Now().Unix())
	if err != nil {
		return err
	}
	changed, err := res.RowsAffected()
	if err != nil || changed != 1 {
		return fmt.Errorf("transaction expired or changed")
	}
	return dbtx.Commit()
}

func (s *stateStore) claimOAuthRequest(state string) (transaction, error) {
	var txID string
	var tx transaction
	dbtx, err := s.db.Begin()
	if err != nil {
		return tx, err
	}
	defer dbtx.Rollback()
	var expires int64
	if err := dbtx.QueryRow(`SELECT transaction_id, expires_at FROM atproto_oauth_requests WHERE state=? AND status='pending'`, state).Scan(&txID, &expires); err != nil {
		return tx, err
	}
	if expires <= time.Now().Unix() {
		return tx, fmt.Errorf("OAuth state expired")
	}
	res, err := dbtx.Exec(`UPDATE atproto_oauth_requests SET status='processing' WHERE state=? AND status='pending' AND expires_at>?`, state, time.Now().Unix())
	if err != nil {
		return tx, err
	}
	count, err := res.RowsAffected()
	if err != nil || count != 1 {
		return tx, fmt.Errorf("OAuth state already claimed")
	}
	var data []byte
	if err := dbtx.QueryRow(`SELECT payload FROM atproto_transactions WHERE id=? AND expires_at>?`, txID, time.Now().Unix()).Scan(&data); err != nil {
		return tx, err
	}
	if err := s.open("transaction:"+txID, data, &tx); err != nil {
		return tx, err
	}
	if tx.Status != "oauth_pending" {
		return tx, fmt.Errorf("transaction is not awaiting OAuth")
	}
	tx.Status = "oauth_processing"
	sealed, err := s.seal("transaction:"+tx.ID, tx)
	if err != nil {
		return tx, err
	}
	if _, err := dbtx.Exec(`UPDATE atproto_transactions SET payload=? WHERE id=?`, sealed, tx.ID); err != nil {
		return tx, err
	}
	if err := dbtx.Commit(); err != nil {
		return tx, err
	}
	return tx, nil
}

func (s *stateStore) previewOAuthRequest(state string) (transaction, error) {
	var tx transaction
	var txID string
	var expires int64
	var status string
	if err := s.db.QueryRow(`SELECT transaction_id, status, expires_at FROM atproto_oauth_requests WHERE state=?`, state).Scan(&txID, &status, &expires); err != nil {
		return tx, err
	}
	if status != "pending" || expires <= time.Now().Unix() {
		return tx, fmt.Errorf("OAuth state expired or already claimed")
	}
	tx, err := s.getTransaction(txID)
	if err != nil {
		return tx, err
	}
	if tx.Status != "oauth_pending" {
		return tx, fmt.Errorf("transaction is not awaiting OAuth")
	}
	return tx, nil
}

func (s *stateStore) consumeCompletion(id, dexState, ticket, browser string) (connector.Identity, error) {
	var ident connector.Identity
	dbtx, err := s.db.Begin()
	if err != nil {
		return ident, err
	}
	defer dbtx.Rollback()
	var data []byte
	if err := dbtx.QueryRow(`SELECT payload FROM atproto_transactions WHERE id=? AND expires_at>?`, id, time.Now().Unix()).Scan(&data); err != nil {
		return ident, err
	}
	var tx transaction
	if err := s.open("transaction:"+id, data, &tx); err != nil {
		return ident, err
	}
	if tx.Status != "complete" || tx.DexState != dexState || time.Now().After(tx.TicketExpiry) || !sameSecret(tx.TicketHash, ticket) || !sameSecret(tx.BrowserHash, browser) {
		return ident, fmt.Errorf("completion ticket expired, mismatched, or consumed")
	}
	ident = tx.Identity
	tx.Status, tx.Identity, tx.TicketHash = "consumed", connector.Identity{}, ""
	sealed, err := s.seal("transaction:"+id, tx)
	if err != nil {
		return connector.Identity{}, err
	}
	if _, err := dbtx.Exec(`UPDATE atproto_transactions SET payload=? WHERE id=? AND expires_at>?`, sealed, id, time.Now().Unix()); err != nil {
		return connector.Identity{}, err
	}
	if err := dbtx.Commit(); err != nil {
		return connector.Identity{}, err
	}
	return ident, nil
}

// The OAuth flow is authentication-only, so tokens and DPoP session keys are
// intentionally never retained for session refresh.
func (s *stateStore) GetSession(context.Context, syntax.DID, string) (*oauth.ClientSessionData, error) {
	return nil, nil
}
func (s *stateStore) SaveSession(context.Context, oauth.ClientSessionData) error { return nil }
func (s *stateStore) DeleteSession(context.Context, syntax.DID, string) error    { return nil }

func (s *stateStore) SaveAuthRequestInfo(ctx context.Context, info oauth.AuthRequestData) error {
	txID, _ := ctx.Value(loginContextKey{}).(string)
	result, _ := ctx.Value(saveOutcomeKey{}).(*saveOutcome)
	if txID == "" || result == nil {
		return fmt.Errorf("OAuth request is not bound to a Dex transaction")
	}
	var txData []byte
	var state transaction
	err := s.db.QueryRowContext(ctx, `SELECT payload FROM atproto_transactions WHERE id=? AND expires_at>?`, txID, time.Now().Unix()).Scan(&txData)
	if err == nil {
		err = s.open("transaction:"+txID, txData, &state)
	}
	if err == nil && state.Status != "initiating" {
		err = fmt.Errorf("Dex transaction is not initiating")
	}
	var payload []byte
	if err == nil {
		payload, err = s.seal("oauth:"+info.State, info)
	}
	if err == nil {
		_, err = s.db.ExecContext(ctx, `INSERT INTO atproto_oauth_requests(state, transaction_id, status, expires_at, payload) VALUES(?, ?, 'pending', ?, ?)`, info.State, txID, time.Now().Add(s.transactionTTL).Unix(), payload)
	}
	result.err = err
	return err
}

func (s *stateStore) GetAuthRequestInfo(ctx context.Context, state string) (*oauth.AuthRequestData, error) {
	var data []byte
	var status string
	var expires int64
	err := s.db.QueryRowContext(ctx, `SELECT payload, status, expires_at FROM atproto_oauth_requests WHERE state=?`, state).Scan(&data, &status, &expires)
	if err != nil {
		return nil, err
	}
	if status != "processing" || expires <= time.Now().Unix() {
		return nil, fmt.Errorf("OAuth state expired or not claimed")
	}
	var info oauth.AuthRequestData
	if err := s.open("oauth:"+state, data, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (s *stateStore) DeleteAuthRequestInfo(ctx context.Context, state string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE atproto_oauth_requests SET status='consumed', payload=x'' WHERE state=? AND status='processing'`, state)
	return err
}

var _ oauth.ClientAuthStore = (*stateStore)(nil)
