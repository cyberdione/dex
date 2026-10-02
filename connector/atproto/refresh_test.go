package atproto

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/dexidp/dex/connector"
)

// fakeDirectory is an in-memory identity.Directory for refresh tests. Lookups
// resolve against fixed tables; per-identifier failures can be injected.
type fakeDirectory struct {
	byHandle  map[string]*identity.Identity
	byDID     map[string]*identity.Identity
	lookupErr map[string]error
	purged    []string
}

func (d *fakeDirectory) LookupHandle(ctx context.Context, handle syntax.Handle) (*identity.Identity, error) {
	return d.lookup(handle.String())
}

func (d *fakeDirectory) LookupDID(ctx context.Context, did syntax.DID) (*identity.Identity, error) {
	return d.lookup(did.String())
}

func (d *fakeDirectory) Lookup(ctx context.Context, atid syntax.AtIdentifier) (*identity.Identity, error) {
	return d.lookup(atid.String())
}

func (d *fakeDirectory) lookup(id string) (*identity.Identity, error) {
	if err, ok := d.lookupErr[id]; ok {
		return nil, err
	}
	if ident, ok := d.byDID[id]; ok {
		return ident, nil
	}
	if ident, ok := d.byHandle[id]; ok {
		return ident, nil
	}
	return nil, fmt.Errorf("identifier not found: %s", id)
}

func (d *fakeDirectory) Purge(ctx context.Context, atid syntax.AtIdentifier) error {
	d.purged = append(d.purged, atid.String())
	return nil
}

func verifiedIdentity(did, handle string) *identity.Identity {
	return &identity.Identity{DID: syntax.DID(did), Handle: syntax.Handle(handle)}
}

const refreshRoster = `workshop: ws-test
version: 1
attendees:
  - did: did:plc:aaaaaaaaaaaaaaaaaaaaa
    handle: alice.example
    enabled: true
    validUntil: "2099-01-01T00:00:00Z"
`

func refreshConnector(t *testing.T, openMode bool, roster string, dir identity.Directory) *atprotoConnector {
	t.Helper()
	rosterPath := filepath.Join(t.TempDir(), "roster.yaml")
	if err := os.WriteFile(rosterPath, []byte(roster), 0o644); err != nil {
		t.Fatal(err)
	}
	return &atprotoConnector{
		id:     "atproto",
		config: Config{Workshop: "ws-test", RosterFile: rosterPath, AllowUnlistedAccounts: openMode},
		client: &oauth.ClientApp{Dir: dir},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func rosterDirectory() *fakeDirectory {
	return &fakeDirectory{
		byHandle: map[string]*identity.Identity{
			"alice.example": verifiedIdentity("did:plc:aaaaaaaaaaaaaaaaaaaaa", "alice.example"),
		},
		byDID: map[string]*identity.Identity{
			"did:plc:aaaaaaaaaaaaaaaaaaaaa": verifiedIdentity("did:plc:aaaaaaaaaaaaaaaaaaaaa", "alice.example"),
		},
	}
}

func TestRefreshRosterModeReattests(t *testing.T) {
	dir := rosterDirectory()
	c := refreshConnector(t, false, refreshRoster, dir)
	identity, err := c.Refresh(context.Background(), connector.Scopes{OfflineAccess: true, Groups: true}, connector.Identity{UserID: "did:plc:aaaaaaaaaaaaaaaaaaaaa", Username: "alice.stale.example", Groups: []string{"workshop-attendee"}})
	if err != nil {
		t.Fatal(err)
	}
	if identity.UserID != "did:plc:aaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("subject rewritten: %q", identity.UserID)
	}
	if identity.Username != "alice.example" || identity.PreferredUsername != "alice.example" {
		t.Fatalf("unexpected handle claims: %#v", identity)
	}
	if len(identity.Groups) != 1 || identity.Groups[0] != "workshop-attendee" {
		t.Fatalf("expected workshop-attendee group, got %#v", identity.Groups)
	}
	if len(dir.purged) == 0 {
		t.Fatal("expected a cache purge so verification uses fresh resolution")
	}
}

func TestRefreshRosterModeFailsClosed(t *testing.T) {
	did := "did:plc:aaaaaaaaaaaaaaaaaaaaa"
	tests := []struct {
		name         string
		roster       string
		dir          identity.Directory
		subject      string
		noRosterFile bool
	}{
		{
			name:    "subject is a handle",
			roster:  refreshRoster,
			dir:     rosterDirectory(),
			subject: "alice.example",
		},
		{
			name:    "not on roster",
			roster:  refreshRoster,
			dir:     rosterDirectory(),
			subject: "did:plc:zzzzzzzzzzzzzzzzzzzzz",
		},
		{
			name: "entry disabled",
			roster: `workshop: ws-test
version: 1
attendees:
  - did: did:plc:aaaaaaaaaaaaaaaaaaaaa
    handle: alice.example
    enabled: false
    validUntil: "2099-01-01T00:00:00Z"
`,
			dir:     rosterDirectory(),
			subject: did,
		},
		{
			name: "entry expired",
			roster: `workshop: ws-test
version: 1
attendees:
  - did: did:plc:aaaaaaaaaaaaaaaaaaaaa
    handle: alice.example
    enabled: true
    validUntil: "2000-01-01T00:00:00Z"
`,
			dir:     rosterDirectory(),
			subject: did,
		},
		{
			name: "roster for a different workshop",
			roster: `workshop: other-workshop
version: 1
attendees:
  - did: did:plc:aaaaaaaaaaaaaaaaaaaaa
    handle: alice.example
    enabled: true
    validUntil: "2099-01-01T00:00:00Z"
`,
			dir:     rosterDirectory(),
			subject: did,
		},
		{
			name:    "handle resolves to a different DID",
			roster:  refreshRoster,
			dir:     &fakeDirectory{byHandle: map[string]*identity.Identity{"alice.example": verifiedIdentity("did:plc:eeeeeeeeeeeeeeeeeeeeeee", "alice.example")}},
			subject: did,
		},
		{
			name:    "handle no longer resolves",
			roster:  refreshRoster,
			dir:     &fakeDirectory{lookupErr: map[string]error{"alice.example": fmt.Errorf("resolution failed")}},
			subject: did,
		},
		{
			name:         "roster file unreadable",
			roster:       refreshRoster,
			dir:          rosterDirectory(),
			subject:      did,
			noRosterFile: true,
		},
		{
			name: "roster entry has malformed expiry",
			roster: `workshop: ws-test
version: 1
attendees:
  - did: did:plc:aaaaaaaaaaaaaaaaaaaaa
    handle: alice.example
    enabled: true
    validUntil: "not-a-timestamp"
`,
			dir:     rosterDirectory(),
			subject: did,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := refreshConnector(t, false, tt.roster, tt.dir)
			if tt.noRosterFile {
				c.config.RosterFile = filepath.Join(t.TempDir(), "missing-roster.yaml")
			}
			if _, err := c.Refresh(context.Background(), connector.Scopes{OfflineAccess: true}, connector.Identity{UserID: tt.subject, Username: "alice.example"}); err == nil {
				t.Fatal("expected refresh to fail closed")
			}
		})
	}
}

func TestRefreshOpenModeFollowsDIDDocument(t *testing.T) {
	dir := &fakeDirectory{
		byDID: map[string]*identity.Identity{
			"did:plc:bbbbbbbbbbbbbbbbbbbbb": verifiedIdentity("did:plc:bbbbbbbbbbbbbbbbbbbbb", "bob.renamed.example"),
		},
	}
	c := refreshConnector(t, true, "", dir)
	identity, err := c.Refresh(context.Background(), connector.Scopes{OfflineAccess: true}, connector.Identity{UserID: "did:plc:bbbbbbbbbbbbbbbbbbbbb", Username: "bob.original.example"})
	if err != nil {
		t.Fatal(err)
	}
	if identity.UserID != "did:plc:bbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("subject rewritten: %q", identity.UserID)
	}
	if identity.Username != "bob.renamed.example" || identity.PreferredUsername != "bob.renamed.example" {
		t.Fatalf("expected handle claims to follow the DID document: %#v", identity)
	}
	if len(identity.Groups) != 0 {
		t.Fatalf("open identities must stay free of workshop membership: %#v", identity.Groups)
	}
	if len(dir.purged) == 0 {
		t.Fatal("expected a cache purge so re-attestation uses fresh resolution")
	}
}

func TestRefreshOpenModeFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		dir     identity.Directory
		subject string
	}{
		{
			name:    "DID no longer resolves",
			dir:     &fakeDirectory{lookupErr: map[string]error{"did:plc:ccccccccccccccccccccc": fmt.Errorf("DID not found")}},
			subject: "did:plc:ccccccccccccccccccccc",
		},
		{
			name: "handle does not verify against the DID",
			dir: &fakeDirectory{byDID: map[string]*identity.Identity{
				"did:plc:ddddddddddddddddddddd": {DID: syntax.DID("did:plc:ddddddddddddddddddddd"), Handle: syntax.HandleInvalid},
			}},
			subject: "did:plc:ddddddddddddddddddddd",
		},
		{
			name:    "subject is not a DID",
			dir:     &fakeDirectory{},
			subject: "not-a-did",
		},
		{
			name: "DID resolves to a different DID",
			dir: &fakeDirectory{byDID: map[string]*identity.Identity{
				"did:plc:eeeeeeeeeeeeeeeeeeeeeee": verifiedIdentity("did:plc:fffffffffffffffffffffff", "eve.example"),
			}},
			subject: "did:plc:eeeeeeeeeeeeeeeeeeeeeee",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := refreshConnector(t, true, "", tt.dir)
			if _, err := c.Refresh(context.Background(), connector.Scopes{OfflineAccess: true}, connector.Identity{UserID: tt.subject, Username: "someone.example"}); err == nil {
				t.Fatal("expected refresh to fail closed")
			}
		})
	}
}
