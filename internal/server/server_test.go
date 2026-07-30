package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientBindAndSearch(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()

	if err := client.UnauthenticatedBind(""); err != nil {
		t.Fatalf("anonymous Bind(): %v", err)
	}

	root, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"namingContexts", "supportedLDAPVersion", "subschemaSubentry"},
		nil,
	))
	if err != nil {
		t.Fatalf("root DSE Search(): %v", err)
	}
	if len(root.Entries) != 1 ||
		root.Entries[0].GetAttributeValue("namingContexts") != "dc=example,dc=com" ||
		root.Entries[0].GetAttributeValue("subschemaSubentry") != "cn=Subschema" {
		t.Fatalf("root DSE entries = %#v", root.Entries)
	}

	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("user Bind(): %v", err)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=inetOrgPerson)(cn=Alice*))",
		[]string{"uid", "cn", "jpegPhoto"},
		nil,
	))
	if err != nil {
		t.Fatalf("subtree Search(): %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(result.Entries))
	}
	if got := result.Entries[0].GetAttributeValue("uid"); got != "alice" {
		t.Fatalf("uid = %q, want alice", got)
	}
	if got := result.Entries[0].GetRawAttributeValue("jpegPhoto"); len(got) != 3 ||
		got[0] != 0x00 || got[1] != 0xff || got[2] != 0x10 {
		t.Fatalf("jpegPhoto = %v", got)
	}

	passwordResult, err := client.Search(ldap.NewSearchRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"userPassword"},
		nil,
	))
	if err != nil {
		t.Fatalf("password Search(): %v", err)
	}
	if len(passwordResult.Entries) != 1 ||
		len(passwordResult.Entries[0].GetRawAttributeValues("userPassword")) != 0 {
		t.Fatal("non-root search disclosed userPassword")
	}
}

func TestLDAPClientRejectsInvalidPassword(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()

	err = client.Bind("uid=alice,ou=people,dc=example,dc=com", "wrong")
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("Bind() error = %v, want invalid credentials", err)
	}
}

func TestLDAPClientCoreWriteOperations(t *testing.T) {
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
		t.Fatalf("root Bind(): %v", err)
	}

	add := ldap.NewAddRequest("uid=bob,ou=people,dc=example,dc=com", nil)
	add.Attribute("objectClass", []string{
		"top",
		"person",
		"organizationalPerson",
		"inetOrgPerson",
		"posixAccount",
	})
	add.Attribute("uid", []string{"bob"})
	add.Attribute("cn", []string{"Bob Example"})
	add.Attribute("sn", []string{"Example"})
	add.Attribute("uidNumber", []string{"1"})
	add.Attribute("gidNumber", []string{"1000"})
	add.Attribute("homeDirectory", []string{"/home/bob"})
	if err := client.Add(add); err != nil {
		t.Fatalf("Add(): %v", err)
	}

	matches, err := client.Compare("uid=bob,ou=people,dc=example,dc=com", "cn", "bob example")
	if err != nil {
		t.Fatalf("Compare(): %v", err)
	}
	if !matches {
		t.Fatal("Compare() = false, want true")
	}

	modify := ldap.NewModifyRequest("uid=bob,ou=people,dc=example,dc=com", nil)
	modify.Replace("cn", []string{"Robert Example"})
	modify.Add("mail", []string{"robert@example.com"})
	modify.Increment("uidNumber", "2")
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify(): %v", err)
	}

	result, err := client.Search(ldap.NewSearchRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{
			"cn",
			"mail",
			"uidNumber",
			"entryUUID",
			"entryCSN",
			"modifyTimestamp",
			"structuralObjectClass",
			"subschemaSubentry",
		},
		nil,
	))
	if err != nil {
		t.Fatalf("Search after Modify(): %v", err)
	}
	entry := result.Entries[0]
	if entry.GetAttributeValue("cn") != "Robert Example" ||
		entry.GetAttributeValue("uidNumber") != "3" ||
		entry.GetAttributeValue("entryUUID") == "" ||
		entry.GetAttributeValue("entryCSN") == "" ||
		entry.GetAttributeValue("modifyTimestamp") == "" ||
		entry.GetAttributeValue("structuralObjectClass") != "inetOrgPerson" ||
		entry.GetAttributeValue("subschemaSubentry") != "cn=Subschema" {
		t.Fatalf("modified entry = %#v", entry)
	}

	child := ldap.NewAddRequest("cn=profile,uid=bob,ou=people,dc=example,dc=com", nil)
	child.Attribute("objectClass", []string{"top", "organizationalRole"})
	child.Attribute("cn", []string{"profile"})
	if err := client.Add(child); err != nil {
		t.Fatalf("Add(child): %v", err)
	}

	rename := ldap.NewModifyDNRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		"uid=robert",
		true,
		"ou=archive,dc=example,dc=com",
	)
	if err := client.ModifyDN(rename); err != nil {
		t.Fatalf("ModifyDN(): %v", err)
	}

	movedChild := "cn=profile,uid=robert,ou=archive,dc=example,dc=com"
	if _, err := client.Search(ldap.NewSearchRequest(
		movedChild,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	)); err != nil {
		t.Fatalf("moved child Search(): %v", err)
	}

	parentDN := "uid=robert,ou=archive,dc=example,dc=com"
	err = client.Del(ldap.NewDelRequest(parentDN, nil))
	assertLDAPResultCode(t, err, ldap.LDAPResultNotAllowedOnNonLeaf)
	if err := client.Del(ldap.NewDelRequest(movedChild, nil)); err != nil {
		t.Fatalf("Del(child): %v", err)
	}
	if err := client.Del(ldap.NewDelRequest(parentDN, nil)); err != nil {
		t.Fatalf("Del(parent): %v", err)
	}
}

func TestLDAPClientLoadsAndPublishesOpenLDAPSchema(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	schemaEntry := directory.Entry{
		DN: "cn={1}application,cn=schema,cn=config",
		Attributes: []directory.Attribute{
			{
				Description: "olcAttributeTypes",
				Values: stringValues(
					"{0}( 1.2.3.4 NAME 'appID' EQUALITY caseIgnoreMatch " +
						"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
				),
			},
			{
				Description: "olcObjectClasses",
				Values: stringValues(
					"{0}( 1.2.3.5 NAME 'appUser' SUP top AUXILIARY MUST appID )",
				),
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		return tx.Put(schemaEntry, false)
	}); err != nil {
		t.Fatalf("seed OpenLDAP schema: %v", err)
	}

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
		t.Fatalf("root Bind(): %v", err)
	}

	add := ldap.NewAddRequest("uid=custom,ou=people,dc=example,dc=com", nil)
	add.Attribute("objectClass", []string{"inetOrgPerson", "appUser"})
	add.Attribute("uid", []string{"custom"})
	add.Attribute("cn", []string{"Custom User"})
	add.Attribute("sn", []string{"User"})
	add.Attribute("appID", []string{"Portal"})
	if err := client.Add(add); err != nil {
		t.Fatalf("Add(custom schema): %v", err)
	}

	userAttributes, err := client.Search(ldap.NewSearchRequest(
		"uid=custom,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(appID=portal)",
		[]string{"*"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(user attributes): %v", err)
	}
	if len(userAttributes.Entries) != 1 ||
		userAttributes.Entries[0].GetAttributeValue("appID") != "Portal" ||
		userAttributes.Entries[0].GetAttributeValue("entryUUID") != "" {
		t.Fatalf("user attributes = %#v", userAttributes.Entries)
	}

	operational, err := client.Search(ldap.NewSearchRequest(
		"uid=custom,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"+"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(operational attributes): %v", err)
	}
	if len(operational.Entries) != 1 ||
		operational.Entries[0].GetAttributeValue("entryUUID") == "" ||
		operational.Entries[0].GetAttributeValue("structuralObjectClass") != "inetOrgPerson" ||
		operational.Entries[0].GetAttributeValue("uid") != "" {
		t.Fatalf("operational attributes = %#v", operational.Entries)
	}

	subSchema, err := client.Search(ldap.NewSearchRequest(
		"cn=Subschema",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=subschema)",
		[]string{"attributeTypes", "objectClasses"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(cn=Subschema): %v", err)
	}
	if len(subSchema.Entries) != 1 ||
		!containsSubstring(subSchema.Entries[0].GetAttributeValues("attributeTypes"), "NAME 'appID'") ||
		!containsSubstring(subSchema.Entries[0].GetAttributeValues("objectClasses"), "NAME 'appUser'") {
		t.Fatalf("subschema entry = %#v", subSchema.Entries)
	}
}

func TestLDAPClientSchemaViolations(t *testing.T) {
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
		t.Fatalf("root Bind(): %v", err)
	}

	undefined := ldap.NewAddRequest("uid=undefined,ou=people,dc=example,dc=com", nil)
	undefined.Attribute("objectClass", []string{"inetOrgPerson"})
	undefined.Attribute("uid", []string{"undefined"})
	undefined.Attribute("cn", []string{"Undefined"})
	undefined.Attribute("sn", []string{"Undefined"})
	undefined.Attribute("loginCount", []string{"1"})
	assertLDAPResultCode(t, client.Add(undefined), ldap.LDAPResultUndefinedAttributeType)

	missingRequired := ldap.NewAddRequest("uid=incomplete,ou=people,dc=example,dc=com", nil)
	missingRequired.Attribute("objectClass", []string{"inetOrgPerson", "posixAccount"})
	missingRequired.Attribute("uid", []string{"incomplete"})
	missingRequired.Attribute("cn", []string{"Incomplete"})
	missingRequired.Attribute("sn", []string{"Incomplete"})
	missingRequired.Attribute("uidNumber", []string{"2"})
	missingRequired.Attribute("homeDirectory", []string{"/home/incomplete"})
	assertLDAPResultCode(t, client.Add(missingRequired), ldap.LDAPResultObjectClassViolation)
}

func TestLDAPClientWriteRequiresRoot(t *testing.T) {
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
	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("user Bind(): %v", err)
	}

	add := ldap.NewAddRequest("uid=denied,ou=people,dc=example,dc=com", nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"denied"})
	add.Attribute("cn", []string{"Denied"})
	add.Attribute("sn", []string{"Denied"})
	assertLDAPResultCode(t, client.Add(add), ldap.LDAPResultInsufficientAccessRights)
}

func seedDirectory(t *testing.T, store storage.Store) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: "dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: [][]byte{[]byte("domain")}},
				{Description: "dc", Values: [][]byte{[]byte("example")}},
			},
		},
		{
			DN: "ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: [][]byte{[]byte("organizationalUnit")}},
				{Description: "ou", Values: [][]byte{[]byte("people")}},
			},
		},
		{
			DN: "ou=archive,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: [][]byte{[]byte("organizationalUnit")}},
				{Description: "ou", Values: [][]byte{[]byte("archive")}},
			},
		},
		{
			DN: "uid=alice,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: [][]byte{[]byte("inetOrgPerson")}},
				{Description: "uid", Values: [][]byte{[]byte("alice")}},
				{Description: "cn", Values: [][]byte{[]byte("Alice Example")}},
				{Description: "sn", Values: [][]byte{[]byte("Example")}},
				{Description: "userPassword", Values: [][]byte{[]byte("secret")}},
				{Description: "jpegPhoto", Values: [][]byte{{0x00, 0xff, 0x10}}},
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return tx.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed directory: %v", err)
	}
}

func assertLDAPResultCode(t *testing.T, err error, want uint16) {
	t.Helper()
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != want {
		t.Fatalf("LDAP error = %v, want result code %d", err, want)
	}
}

func containsSubstring(values []string, substring string) bool {
	for _, value := range values {
		if strings.Contains(value, substring) {
			return true
		}
	}
	return false
}

func startServer(t *testing.T, store storage.Store, config Config) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	config.Store = store
	instance, err := New(config)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- instance.Serve(ctx, listener)
	}()
	stop := func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve(): %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	}
	return fmt.Sprint(listener.Addr()), stop
}
