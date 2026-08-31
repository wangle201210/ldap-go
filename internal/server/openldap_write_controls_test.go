package server

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type writeControlReferenceResult struct {
	permissiveCodes  []uint16
	cnAfterAdd       []string
	cnAfterDelete    []string
	noOpCodes        []uint16
	noOpReadControls []string
	aliceCN          []string
	addExists        bool
	renameExists     bool
}

func TestOpenLDAPReferenceWriteControls(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServer(t, tools, nil)
	defer stopOpenLDAP()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedCoreReferenceDirectory(t, store)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	defer stopLDAPGo()

	reference := observeWriteControls(t, openLDAPURI)
	implementation := observeWriteControls(t, "ldap://"+ldapGoAddress)
	if !reflect.DeepEqual(reference, implementation) {
		t.Fatalf(
			"write-control behavior mismatch\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			implementation,
		)
	}
}

func observeWriteControls(t *testing.T, uri string) writeControlReferenceResult {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(%s): %v", uri, err)
	}

	const alice = "uid=alice,ou=people,dc=example,dc=com"
	permissive := ldap.NewControlString(permissiveModifyControlOID, true, "")
	result := writeControlReferenceResult{}

	mixedAdd := ldap.NewModifyRequest(alice, []ldap.Control{permissive})
	mixedAdd.Add("cn", []string{"Alice", "Alice Alternate"})
	result.permissiveCodes = append(
		result.permissiveCodes,
		monitorLDAPResultCode(client.Modify(mixedAdd)),
	)
	result.cnAfterAdd = readReferenceAttribute(t, client, alice, "cn")

	mixedDelete := ldap.NewModifyRequest(alice, []ldap.Control{permissive})
	mixedDelete.Delete("cn", []string{"missing", "Alice Alternate"})
	result.permissiveCodes = append(
		result.permissiveCodes,
		monitorLDAPResultCode(client.Modify(mixedDelete)),
	)
	result.cnAfterDelete = readReferenceAttribute(t, client, alice, "cn")

	missingPermissive := ldap.NewModifyRequest(alice, []ldap.Control{permissive})
	missingPermissive.Delete("description", nil)
	result.permissiveCodes = append(
		result.permissiveCodes,
		monitorLDAPResultCode(client.Modify(missingPermissive)),
	)
	missingNormal := ldap.NewModifyRequest(alice, nil)
	missingNormal.Delete("description", nil)
	result.permissiveCodes = append(
		result.permissiveCodes,
		monitorLDAPResultCode(client.Modify(missingNormal)),
	)

	noOp := ldap.NewControlString(noOpControlOID, true, "")
	addDN := "uid=noop-add,ou=people,dc=example,dc=com"
	add := coreReferencePersonAdd(addDN, "noop-add")
	add.Controls = []ldap.Control{noOp}
	modify := ldap.NewModifyRequest(alice, []ldap.Control{noOp})
	modify.Replace("cn", []string{"No-Op Alice"})
	deleteRequest := ldap.NewDelRequest(alice, []ldap.Control{noOp})
	rename := ldap.NewModifyDNRequest(alice, "uid=noop-renamed", true, "")
	rename.Controls = []ldap.Control{noOp}
	result.noOpCodes = []uint16{
		monitorLDAPResultCode(client.Add(add)),
		monitorLDAPResultCode(client.Modify(modify)),
		monitorLDAPResultCode(client.Del(deleteRequest)),
		monitorLDAPResultCode(client.ModifyDN(rename)),
	}

	raw := dialAndBindRawLDAP(
		t,
		strings.TrimPrefix(uri, "ldap://"),
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	defer raw.Close()
	response := sendRawLDAPOperation(
		t,
		raw,
		2,
		rawModifyReplaceRequest(alice, "cn", "No-Op Read Alice"),
		rawOIDControl(noOpControlOID, true),
		rawReadControl(preReadControlOID, true, "cn"),
		rawReadControl(postReadControlOID, true, "cn"),
	)
	result.noOpCodes = append(
		result.noOpCodes,
		uint16(rawLDAPResultCode(t, response.Children[1])),
	)
	if len(response.Children) == 3 {
		for _, control := range response.Children[2].Children {
			if len(control.Children) > 0 {
				result.noOpReadControls = append(
					result.noOpReadControls,
					control.Children[0].Data.String(),
				)
			}
		}
		sort.Strings(result.noOpReadControls)
	}

	result.aliceCN = readReferenceAttribute(t, client, alice, "cn")
	result.addExists = referenceEntryExists(t, client, addDN)
	result.renameExists = referenceEntryExists(
		t,
		client,
		"uid=noop-renamed,ou=people,dc=example,dc=com",
	)
	return result
}

func readReferenceAttribute(
	t *testing.T,
	client *ldap.Conn,
	dn,
	description string,
) []string {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{description},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("read %s from %s: %#v, %v", description, dn, result, err)
	}
	values := append([]string(nil), result.Entries[0].GetAttributeValues(description)...)
	sort.Strings(values)
	return values
}

func referenceEntryExists(t *testing.T, client *ldap.Conn, dn string) bool {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	if err != nil {
		if monitorLDAPResultCode(err) == ldap.LDAPResultNoSuchObject {
			return false
		}
		t.Fatalf("Search(%s): %v", dn, err)
	}
	return len(result.Entries) == 1
}
