package atproto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rosterConnector builds a minimal connector wired to a roster file so the
// fail-closed authorization-data sweep can be exercised end to end.
func rosterConnector(t *testing.T, rosterYAML string) *atprotoConnector {
	t.Helper()
	path := filepath.Join(t.TempDir(), "roster.yaml")
	if err := os.WriteFile(path, []byte(rosterYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	return &atprotoConnector{config: Config{Workshop: "oz-workshop-2026", RosterFile: path}}
}

const groupsRosterHeader = `workshop: oz-workshop-2026
version: 1
attendees:
  - did: did:plc:ewi7swmd5cbqtyovy434c6ny
    handle: alice.example.com
    enabled: true
    validUntil: "2037-01-01T00:00:00Z"
`

func TestRosterGroupEmission(t *testing.T) {
	withGroups := rosterConnector(t, groupsRosterHeader+`    groups: [mesh-operator, gitlab-partners]
`)
	entry, err := withGroups.rosterEntry("did:plc:ewi7swmd5cbqtyovy434c6ny")
	if err != nil {
		t.Fatalf("roster read failed: %v", err)
	}
	if len(entry.Groups) != 2 || entry.Groups[0] != "mesh-operator" || entry.Groups[1] != "gitlab-partners" {
		t.Fatalf("roster groups not read: %v", entry.Groups)
	}
	identity := identityForVerifiedAccount(entry.DID, entry.Handle, entry.Groups)
	if len(identity.Groups) != 2 {
		t.Fatalf("identity groups not emitted: %v", identity.Groups)
	}

	noGroups := rosterConnector(t, groupsRosterHeader)
	entry, err = noGroups.rosterEntry("did:plc:ewi7swmd5cbqtyovy434c6ny")
	if err != nil {
		t.Fatalf("roster read failed: %v", err)
	}
	if len(entry.Groups) != 0 {
		t.Fatalf("absent groups key must read as no groups: %v", entry.Groups)
	}
	identity = identityForVerifiedAccount(entry.DID, entry.Handle, entry.Groups)
	if len(identity.Groups) != 0 {
		t.Fatalf("empty roster groups must emit no groups: %v", identity.Groups)
	}
}

func TestRosterGroupsValidationFailClosed(t *testing.T) {
	cases := map[string]string{
		"uppercase":    "    groups: [Mesh-Operator]\n",
		"leading dash": "    groups: [-leading]\n",
		"whitespace":   "    groups: [has space]\n",
		"duplicate":    "    groups: [dup, dup]\n",
		"too long":     "    groups: [" + strings.Repeat("g", 65) + "]\n",
		"too many":     "    groups: [" + strings.Repeat("g1-", 6) + "x, a, b, c, d, e, f, h, i, j, k, l, m, n, o, p, q]\n",
	}
	for name, suffix := range cases {
		c := rosterConnector(t, groupsRosterHeader+suffix)
		if _, err := c.rosterEntry("did:plc:ewi7swmd5cbqtyovy434c6ny"); err == nil {
			t.Fatalf("%s: malformed authorization data was accepted", name)
		}
	}

	// A malformed entry on a DIFFERENT attendee must also fail the read:
	// authorization data is fail-closed for the whole roster, not per-hit.
	brokenPeer := groupsRosterHeader + `  - did: did:plc:aaaaaaaaaaaaaaaaaaaaaaaa
    handle: bob.example.com
    enabled: true
    validUntil: "2037-01-01T00:00:00Z"
    groups: [Bad_Group]
`
	c := rosterConnector(t, brokenPeer)
	if _, err := c.rosterEntry("did:plc:ewi7swmd5cbqtyovy434c6ny"); err == nil {
		t.Fatal("malformed groups on another attendee were accepted")
	}
}

func TestIdentityForVerifiedAccountInvariants(t *testing.T) {
	did := "did:plc:ewi7swmd5cbqtyovy434c6ny"
	handle := "alice.example.com"

	open := identityForVerifiedAccount(did, handle, nil)
	if len(open.Groups) != 0 {
		t.Fatalf("open-account identity must carry no groups, got %v", open.Groups)
	}
	if open.UserID != did || open.Username != handle || open.PreferredUsername != handle {
		t.Fatalf("identity fields drifted: %+v", open)
	}
	if open.Email != "" || open.EmailVerified {
		t.Fatalf("connector must not invent email claims: %+v", open)
	}

	// The emitted slice must be a copy, not an alias of roster memory.
	src := []string{"mesh-operator"}
	copied := identityForVerifiedAccount(did, handle, src)
	src[0] = "mutated"
	if len(copied.Groups) != 1 || copied.Groups[0] != "mesh-operator" {
		t.Fatalf("identity aliases roster memory: %v", copied.Groups)
	}
}
