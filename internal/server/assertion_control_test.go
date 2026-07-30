package server

import (
	"context"
	"errors"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientAssertionControlOnWrites(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	modify := ldap.NewModifyRequest(
		aliceDN,
		[]ldap.Control{newAssertionControl(t, "(cn=Alice Example)")},
	)
	modify.Replace("description", []string{"assertion matched"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify() with matching assertion: %v", err)
	}
	failedModify := ldap.NewModifyRequest(
		aliceDN,
		[]ldap.Control{newAssertionControl(t, "(description=missing)")},
	)
	failedModify.Replace("description", []string{"must not be stored"})
	assertLDAPResultCode(
		t,
		client.Modify(failedModify),
		ldap.LDAPResultAssertionFailed,
	)
	if values := readStoredEntry(t, store, aliceDN).Values("description"); len(values) != 1 ||
		string(values[0]) != "assertion matched" {
		t.Fatalf("description after failed assertion = %q", values)
	}

	failedAddDN := "uid=assert-add-failed,ou=people,dc=example,dc=com"
	failedAdd := newPersonAddRequest("assert-add-failed")
	failedAdd.Controls = []ldap.Control{newAssertionControl(t, "(uid=different)")}
	assertLDAPResultCode(t, client.Add(failedAdd), ldap.LDAPResultAssertionFailed)
	if entryExists(t, store, failedAddDN) {
		t.Fatal("entry from failed asserted Add was stored")
	}

	addDN := "uid=assert-added,ou=people,dc=example,dc=com"
	add := newPersonAddRequest("assert-added")
	add.Controls = []ldap.Control{newAssertionControl(t, "(uid=assert-added)")}
	if err := client.Add(add); err != nil {
		t.Fatalf("Add() with matching assertion: %v", err)
	}
	failedDelete := ldap.NewDelRequest(
		addDN,
		[]ldap.Control{newAssertionControl(t, "(uid=different)")},
	)
	assertLDAPResultCode(t, client.Del(failedDelete), ldap.LDAPResultAssertionFailed)
	if !entryExists(t, store, addDN) {
		t.Fatal("failed asserted Delete removed the entry")
	}
	deleteRequest := ldap.NewDelRequest(
		addDN,
		[]ldap.Control{newAssertionControl(t, "(uid=assert-added)")},
	)
	if err := client.Del(deleteRequest); err != nil {
		t.Fatalf("Delete() with matching assertion: %v", err)
	}

	renameDN := "uid=assert-rename,ou=people,dc=example,dc=com"
	renameAdd := newPersonAddRequest("assert-rename")
	if err := client.Add(renameAdd); err != nil {
		t.Fatalf("Add(rename source): %v", err)
	}
	failedRename := ldap.NewModifyDNRequest(
		renameDN,
		"uid=must-not-move",
		true,
		"",
	)
	failedRename.Controls = []ldap.Control{newAssertionControl(t, "(uid=different)")}
	assertLDAPResultCode(
		t,
		client.ModifyDN(failedRename),
		ldap.LDAPResultAssertionFailed,
	)
	if !entryExists(t, store, renameDN) {
		t.Fatal("failed asserted ModifyDN moved the entry")
	}
	rename := ldap.NewModifyDNRequest(
		renameDN,
		"uid=assert-renamed",
		true,
		"",
	)
	rename.Controls = []ldap.Control{newAssertionControl(t, "(uid=assert-rename)")}
	if err := client.ModifyDN(rename); err != nil {
		t.Fatalf("ModifyDN() with matching assertion: %v", err)
	}
	if !entryExists(
		t,
		store,
		"uid=assert-renamed,ou=people,dc=example,dc=com",
	) {
		t.Fatal("matching asserted ModifyDN did not move the entry")
	}
}

func TestLDAPClientAssertionControlOnSearchAndCompare(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	search := ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=alice)",
		[]string{"uid"},
		[]ldap.Control{newAssertionControl(t, "(dc=example)")},
	)
	result, err := client.Search(search)
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("Search() with matching assertion = %#v, %v", result, err)
	}
	search.Controls = []ldap.Control{newAssertionControl(t, "(dc=other)")}
	_, err = client.Search(search)
	assertLDAPResultCode(t, err, ldap.LDAPResultAssertionFailed)

	if code := rawCompareWithAssertion(
		t,
		address,
		"(cn=Alice Example)",
	); code != int64(ldap.LDAPResultCompareTrue) {
		t.Fatalf("matching asserted Compare result = %d", code)
	}
	if code := rawCompareWithAssertion(
		t,
		address,
		"(cn=Different)",
	); code != int64(ldap.LDAPResultAssertionFailed) {
		t.Fatalf("failed asserted Compare result = %d", code)
	}

	rootDSE, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedControl"},
		nil,
	))
	if err != nil || len(rootDSE.Entries) != 1 {
		t.Fatalf("Control Root DSE = %#v, %v", rootDSE, err)
	}
	supportedControls := rootDSE.Entries[0].GetAttributeValues("supportedControl")
	for _, oid := range []string{
		assertionControlOID,
		preReadControlOID,
		postReadControlOID,
	} {
		if !containsString(supportedControls, oid) {
			t.Fatalf("supportedControl = %q, missing %s", supportedControls, oid)
		}
	}
}

func TestParseRequestControlsRejectsInvalidAssertion(t *testing.T) {
	t.Parallel()

	filter, err := ldap.CompileFilter("(uid=alice)")
	if err != nil {
		t.Fatalf("CompileFilter(): %v", err)
	}
	valid := ldapwire.Control{
		OID:      assertionControlOID,
		Critical: true,
		Value:    filter.Bytes(),
		HasValue: true,
	}
	tests := []struct {
		name     string
		controls []ldapwire.Control
		wantCode ldapwire.ResultCode
	}{
		{
			name:     "absent value",
			controls: []ldapwire.Control{{OID: assertionControlOID, Critical: true}},
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name: "empty value",
			controls: []ldapwire.Control{{
				OID:      assertionControlOID,
				Critical: true,
				HasValue: true,
			}},
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name: "malformed filter",
			controls: []ldapwire.Control{{
				OID:      assertionControlOID,
				Critical: true,
				Value:    []byte{0x30, 0x00},
				HasValue: true,
			}},
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name:     "duplicate",
			controls: []ldapwire.Control{valid, valid},
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name: "unknown critical",
			controls: []ldapwire.Control{{
				OID:      "1.2.3.4",
				Critical: true,
			}},
			wantCode: ldapwire.ResultUnavailableCriticalExtension,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, result := parseRequestControls(
				test.controls,
				supportsAssertion,
			)
			if result == nil || result.Code != test.wantCode {
				t.Fatalf("parseRequestControls() result = %#v", result)
			}
		})
	}

	parsed, result := parseRequestControls(
		[]ldapwire.Control{
			{OID: "1.2.3.4", Critical: false},
			valid,
		},
		supportsAssertion,
	)
	if result != nil || parsed.assertion == nil {
		t.Fatalf("valid parseRequestControls() = %#v, %#v", parsed, result)
	}
}

func newAssertionControl(t *testing.T, filter string) ldap.Control {
	t.Helper()

	packet, err := ldap.CompileFilter(filter)
	if err != nil {
		t.Fatalf("CompileFilter(%q): %v", filter, err)
	}
	return ldap.NewControlString(
		assertionControlOID,
		true,
		string(packet.Bytes()),
	)
}

func entryExists(t *testing.T, store storage.Store, rawDN string) bool {
	t.Helper()

	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", rawDN, err)
	}
	err = store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Get(dn)
		return err
	})
	if errors.Is(err, storage.ErrEntryNotFound) {
		return false
	}
	if err != nil {
		t.Fatalf("read entry %q: %v", rawDN, err)
	}
	return true
}

func rawCompareWithAssertion(
	t *testing.T,
	address, assertion string,
) int64 {
	t.Helper()

	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	defer connection.Close()

	bind := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationBindRequest,
		nil,
		"BindRequest",
	)
	bind.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		3,
		"version",
	))
	bind.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		"cn=admin,dc=example,dc=com",
		"name",
	))
	bind.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		"admin-secret",
		"simple",
	))
	writeRawLDAPRequest(t, connection, 1, bind, nil)
	if code := readRawLDAPResultCode(t, connection); code != 0 {
		t.Fatalf("raw Bind result = %d", code)
	}

	compare := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationCompareRequest,
		nil,
		"CompareRequest",
	)
	compare.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		aliceDN,
		"entry",
	))
	ava := ber.NewSequence("AttributeValueAssertion")
	ava.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		"uid",
		"attribute",
	))
	ava.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		"alice",
		"value",
	))
	compare.AppendChild(ava)

	filter, err := ldap.CompileFilter(assertion)
	if err != nil {
		t.Fatalf("CompileFilter(%q): %v", assertion, err)
	}
	control := ber.NewSequence("AssertionControl")
	control.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		assertionControlOID,
		"controlType",
	))
	control.AppendChild(ber.NewBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		true,
		"criticality",
	))
	control.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		string(filter.Bytes()),
		"controlValue",
	))
	writeRawLDAPRequest(t, connection, 2, compare, control)
	return readRawLDAPResultCode(t, connection)
}

func writeRawLDAPRequest(
	t *testing.T,
	connection net.Conn,
	messageID int64,
	operation, control *ber.Packet,
) {
	t.Helper()

	message := ber.NewSequence("LDAPMessage")
	message.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		messageID,
		"messageID",
	))
	message.AppendChild(operation)
	if control != nil {
		controls := ber.Encode(
			ber.ClassContext,
			ber.TypeConstructed,
			0,
			nil,
			"controls",
		)
		controls.AppendChild(control)
		message.AppendChild(controls)
	}
	if err := ldapwire.Write(connection, message.Bytes()); err != nil {
		t.Fatalf("write LDAP request: %v", err)
	}
}

func readRawLDAPResultCode(t *testing.T, connection net.Conn) int64 {
	t.Helper()

	response, err := ber.ReadPacket(connection)
	if err != nil {
		t.Fatalf("read LDAP response: %v", err)
	}
	if len(response.Children) < 2 ||
		len(response.Children[1].Children) < 1 {
		t.Fatalf("malformed LDAP response: %#v", response)
	}
	code, err := ber.ParseInt64(response.Children[1].Children[0].Data.Bytes())
	if err != nil {
		t.Fatalf("parse LDAP result code: %v", err)
	}
	return code
}
