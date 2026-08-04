package server

import (
	"path/filepath"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPNoOpControlRollsBackWrites(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		testLDAPNoOpControlRollsBackWrites(t, storage.NewMemory())
	})
	t.Run("bbolt", func(t *testing.T) {
		store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
		if err != nil {
			t.Fatalf("OpenBolt(): %v", err)
		}
		testLDAPNoOpControlRollsBackWrites(t, store)
	})
}

func testLDAPNoOpControlRollsBackWrites(t *testing.T, store storage.Store) {
	t.Helper()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	const (
		rootDN       = "cn=admin,dc=example,dc=com"
		rootPassword = "admin-secret"
	)
	address, stop := startServer(t, store, Config{
		RootDN:       rootDN,
		RootPassword: []byte(rootPassword),
	})
	defer stop()
	connection := dialAndBindRawLDAP(t, address, rootDN, rootPassword)
	defer connection.Close()

	addDN := "uid=noop-add,ou=people,dc=example,dc=com"
	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawAddRequest(readControlTestEntry(addDN, "noop-add")),
		rawOIDControl(noOpControlOID, true),
		rawReadControl(postReadControlOID, true, "cn"),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultNoOperation))
	assertNoRawResponseControls(t, response)
	if entryExists(t, store, addDN) {
		t.Fatal("No-Op Add persisted the entry")
	}

	response = sendRawLDAPOperation(
		t,
		connection,
		3,
		rawModifyReplaceRequest(aliceDN, "cn", "No-Op Alice"),
		rawOIDControl(noOpControlOID, true),
		rawReadControl(preReadControlOID, true, "cn"),
		rawReadControl(postReadControlOID, true, "cn"),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultNoOperation))
	assertNoRawResponseControls(t, response)
	if !readStoredEntry(t, store, aliceDN).HasValue("cn", []byte("Alice Example")) {
		t.Fatal("No-Op Modify changed the stored entry")
	}

	response = sendRawLDAPOperation(
		t,
		connection,
		4,
		rawDeleteRequest(aliceDN),
		rawOIDControl(noOpControlOID, true),
		rawReadControl(preReadControlOID, true, "cn"),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultNoOperation))
	assertNoRawResponseControls(t, response)
	if !entryExists(t, store, aliceDN) {
		t.Fatal("No-Op Delete removed the entry")
	}

	renamedDN := "uid=noop-renamed,ou=people,dc=example,dc=com"
	response = sendRawLDAPOperation(
		t,
		connection,
		5,
		rawModifyDNRequest(aliceDN, "uid=noop-renamed", true),
		rawOIDControl(noOpControlOID, true),
		rawReadControl(preReadControlOID, true, "uid"),
		rawReadControl(postReadControlOID, true, "uid"),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultNoOperation))
	assertNoRawResponseControls(t, response)
	if !entryExists(t, store, aliceDN) || entryExists(t, store, renamedDN) {
		t.Fatal("No-Op ModifyDN changed the stored DN")
	}
}

func assertNoRawResponseControls(t *testing.T, response *ber.Packet) {
	t.Helper()
	if response == nil || len(response.Children) != 2 {
		t.Fatalf("unexpected response controls: %#v", response)
	}
}

func TestLDAPPermissiveModifyControl(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	const rootDN = "cn=admin,dc=example,dc=com"
	address, stop := startServer(t, store, Config{
		RootDN:       rootDN,
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(rootDN, "admin-secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	duplicate := ldap.NewModifyRequest(aliceDN, nil)
	duplicate.Add("cn", []string{"Alice Example"})
	assertLDAPResultCode(
		t,
		client.Modify(duplicate),
		ldap.LDAPResultAttributeOrValueExists,
	)

	permissive := ldap.NewControlString(permissiveModifyControlOID, true, "")
	mixedAdd := ldap.NewModifyRequest(aliceDN, []ldap.Control{permissive})
	mixedAdd.Add("cn", []string{"Alice Example", "Alice Alternate"})
	if err := client.Modify(mixedAdd); err != nil {
		t.Fatalf("permissive duplicate Add: %v", err)
	}
	entry := readStoredEntry(t, store, aliceDN)
	if !entry.HasValue("cn", []byte("Alice Example")) ||
		!entry.HasValue("cn", []byte("Alice Alternate")) {
		t.Fatalf("cn after permissive Add = %q", entry.Values("cn"))
	}

	mixedDelete := ldap.NewModifyRequest(aliceDN, []ldap.Control{permissive})
	mixedDelete.Delete("cn", []string{"missing", "Alice Alternate"})
	if err := client.Modify(mixedDelete); err != nil {
		t.Fatalf("permissive missing-value Delete: %v", err)
	}
	entry = readStoredEntry(t, store, aliceDN)
	if !entry.HasValue("cn", []byte("Alice Example")) ||
		entry.HasValue("cn", []byte("Alice Alternate")) {
		t.Fatalf("cn after permissive Delete = %q", entry.Values("cn"))
	}

	missingAttribute := ldap.NewModifyRequest(aliceDN, []ldap.Control{permissive})
	missingAttribute.Delete("description", nil)
	if err := client.Modify(missingAttribute); err != nil {
		t.Fatalf("permissive missing-attribute Delete: %v", err)
	}
	normalMissingAttribute := ldap.NewModifyRequest(aliceDN, nil)
	normalMissingAttribute.Delete("description", nil)
	assertLDAPResultCode(
		t,
		client.Modify(normalMissingAttribute),
		ldap.LDAPResultNoSuchAttribute,
	)

	addDescription := ldap.NewModifyRequest(aliceDN, nil)
	addDescription.Add("description", []string{"temporary"})
	if err := client.Modify(addDescription); err != nil {
		t.Fatalf("Add description: %v", err)
	}
	deleteDescription := ldap.NewModifyRequest(aliceDN, []ldap.Control{permissive})
	deleteDescription.Delete("description", nil)
	if err := client.Modify(deleteDescription); err != nil {
		t.Fatalf("permissive whole-attribute Delete: %v", err)
	}
	if readStoredEntry(t, store, aliceDN).HasAttribute("description") {
		t.Fatal("permissive whole-attribute Delete retained description")
	}
}

func TestParseNoOpAndPermissiveModifyControls(t *testing.T) {
	t.Parallel()

	parsed, failure := parseRequestControls(
		[]ldapwire.Control{
			{OID: noOpControlOID, Critical: true},
			{OID: permissiveModifyControlOID, Critical: true},
		},
		supportsNoOp|supportsPermissiveModify,
	)
	if failure != nil || !parsed.noOp || !parsed.permissiveModify {
		t.Fatalf("valid controls = %#v, failure %#v", parsed, failure)
	}

	tests := []struct {
		name      string
		controls  []ldapwire.Control
		supported requestControlSupport
		want      ldapwire.ResultCode
	}{
		{
			name: "No-Op value present",
			controls: []ldapwire.Control{{
				OID:      noOpControlOID,
				HasValue: true,
			}},
			supported: supportsNoOp,
			want:      ldapwire.ResultProtocolError,
		},
		{
			name: "No-Op duplicate",
			controls: []ldapwire.Control{
				{OID: noOpControlOID},
				{OID: noOpControlOID},
			},
			supported: supportsNoOp,
			want:      ldapwire.ResultProtocolError,
		},
		{
			name: "permissiveModify value present",
			controls: []ldapwire.Control{{
				OID:      permissiveModifyControlOID,
				HasValue: true,
			}},
			supported: supportsPermissiveModify,
			want:      ldapwire.ResultProtocolError,
		},
		{
			name: "permissiveModify duplicate",
			controls: []ldapwire.Control{
				{OID: permissiveModifyControlOID},
				{OID: permissiveModifyControlOID},
			},
			supported: supportsPermissiveModify,
			want:      ldapwire.ResultProtocolError,
		},
		{
			name:      "unsupported critical No-Op",
			controls:  []ldapwire.Control{{OID: noOpControlOID, Critical: true}},
			supported: supportsPermissiveModify,
			want:      ldapwire.ResultUnavailableCriticalExtension,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, failure := parseRequestControls(test.controls, test.supported)
			if failure == nil || failure.Code != test.want {
				t.Fatalf("parseRequestControls() failure = %#v, want %d", failure, test.want)
			}
		})
	}
}
