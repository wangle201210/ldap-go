package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
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

func TestLDAPClientGroupACLControlsAttributeWrites(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	entries := []directory.Entry{
		{
			DN: "uid=bob,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("bob")},
				{Description: "cn", Values: stringValues("Bob Example")},
				{Description: "sn", Values: stringValues("Example")},
				{Description: "mail", Values: stringValues("bob@example.com")},
				{Description: "userPassword", Values: stringValues("bob-secret")},
			},
		},
		{
			DN: "cn=mail editors,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("groupOfNames")},
				{Description: "cn", Values: stringValues("mail editors")},
				{
					Description: "member",
					Values:      stringValues("uid=alice,ou=people,dc=example,dc=com"),
				},
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		configDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		config, err := tx.Get(configDN)
		if err != nil {
			return err
		}
		config.ReplaceValues("olcAccess", stringValues(
			"{0}to attrs=userPassword by self =xw by anonymous auth by * none",
			"{1}to attrs=mail,entry by group.exact=\"cn=mail editors,dc=example,dc=com\" write by users read by * none",
			"{2}to * by users read by * none",
		))
		if err := tx.Put(config, true); err != nil {
			return err
		}
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed group ACL: %v", err)
	}

	address, stop := startServer(t, store, Config{})
	defer stop()

	alice, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(alice): %v", err)
	}
	defer alice.Close()
	if err := alice.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(alice): %v", err)
	}
	modifyBob := ldap.NewModifyRequest("uid=bob,ou=people,dc=example,dc=com", nil)
	modifyBob.Replace("mail", []string{"edited@example.com"})
	if err := alice.Modify(modifyBob); err != nil {
		t.Fatalf("group-authorized Modify(): %v", err)
	}

	bob, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(bob): %v", err)
	}
	defer bob.Close()
	if err := bob.Bind("uid=bob,ou=people,dc=example,dc=com", "bob-secret"); err != nil {
		t.Fatalf("Bind(bob): %v", err)
	}
	modifyAlice := ldap.NewModifyRequest("uid=alice,ou=people,dc=example,dc=com", nil)
	modifyAlice.Replace("mail", []string{"denied@example.com"})
	assertLDAPResultCode(t, bob.Modify(modifyAlice), ldap.LDAPResultInsufficientAccessRights)
}

func TestLDAPClientSearchBaseRequiresSearchAccess(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		configDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		config, err := tx.Get(configDN)
		if err != nil {
			return err
		}
		config.ReplaceValues("olcAccess", stringValues(
			"{0}to attrs=userPassword by anonymous auth by self =xw by * none",
			"{1}to dn.exact=\"ou=people,dc=example,dc=com\" attrs=entry by users =d by * none",
			"{2}to * by users read by * none",
		))
		return tx.Put(config, true)
	}); err != nil {
		t.Fatalf("configure search ACL: %v", err)
	}

	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	request := ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	)
	_, err = client.Search(request)
	assertLDAPResultCode(t, err, ldap.LDAPResultInsufficientAccessRights)
}

func TestLDAPClientNoSuchObjectHidesUndisclosedMatchedDN(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		configDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		config, err := tx.Get(configDN)
		if err != nil {
			return err
		}
		config.ReplaceValues("olcAccess", stringValues(
			"{0}to attrs=userPassword by anonymous auth by self =xw by * none",
			"{1}to * by users =s by * none",
		))
		return tx.Put(config, true)
	}); err != nil {
		t.Fatalf("configure disclose ACL: %v", err)
	}

	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	_, err = client.Search(ldap.NewSearchRequest(
		"uid=missing,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		nil,
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		t.Fatalf("Search() error = %T, want *ldap.Error", err)
	}
	if ldapError.MatchedDN != "" {
		t.Fatalf("matchedDN = %q, want empty", ldapError.MatchedDN)
	}
}

func TestLDAPClientFilterACLUsesAssertionAndUndefined(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		configDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		config, err := tx.Get(configDN)
		if err != nil {
			return err
		}
		config.ReplaceValues("olcAccess", stringValues(
			"{0}to attrs=userPassword by anonymous auth by self =xw by * none",
			"{1}to attrs=member by users selfread by * none",
			"{2}to * by users read by * none",
		))
		if err := tx.Put(config, true); err != nil {
			return err
		}
		return tx.Put(directory.Entry{
			DN: "cn=self readers,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("groupOfNames")},
				{Description: "cn", Values: stringValues("self readers")},
				{
					Description: "member",
					Values: stringValues(
						"uid=alice,ou=people,dc=example,dc=com",
						"uid=bob,ou=people,dc=example,dc=com",
					),
				},
			},
		}, false)
	}); err != nil {
		t.Fatalf("configure filter ACL: %v", err)
	}

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if err := registry.ParseAndRegisterAttributeType(
		"( 2.5.4.31 NAME 'member' EQUALITY distinguishedNameMatch SYNTAX " +
			schema.SyntaxDistinguishedName + " )",
	); err != nil {
		t.Fatalf("register member schema: %v", err)
	}
	address, stop := startServer(t, store, Config{Schema: registry})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	search := func(filter string) *ldap.SearchResult {
		t.Helper()
		result, err := client.Search(ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			filter,
			[]string{"cn", "member"},
			nil,
		))
		if err != nil {
			t.Fatalf("Search(%q): %v", filter, err)
		}
		return result
	}

	equality := search("(member=uid=alice,ou=people,dc=example,dc=com)")
	if len(equality.Entries) != 1 ||
		equality.Entries[0].DN != "cn=self readers,dc=example,dc=com" {
		t.Fatalf("equality entries = %#v", equality.Entries)
	}
	typesOnly, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		true,
		"(member=uid=alice,ou=people,dc=example,dc=com)",
		[]string{"member"},
		nil,
	))
	if err != nil {
		t.Fatalf("typesOnly Search(): %v", err)
	}
	if len(typesOnly.Entries) != 1 || len(typesOnly.Entries[0].Attributes) != 0 {
		t.Fatalf("typesOnly entries = %#v", typesOnly.Entries)
	}
	if entries := search("(member=*)").Entries; len(entries) != 0 {
		t.Fatalf("presence entries = %#v, want none", entries)
	}
	if entries := search("(!(member=*))").Entries; len(entries) != 0 {
		t.Fatalf("NOT presence entries = %#v, want none", entries)
	}
}

func TestLDAPClientConfigBackendDefaultsToNoAccess(t *testing.T) {
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
	request := ldap.NewSearchRequest(
		"olcDatabase={1}mdb,cn=config",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"olcAccess"},
		nil,
	)
	_, err = client.Search(request)
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
}

func TestLDAPClientLoadsScopedHashedRootFromConfig(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		configDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		config, err := tx.Get(configDN)
		if err != nil {
			return err
		}
		config.ReplaceValues("olcRootDN", stringValues("cn=admin,dc=example,dc=com"))
		config.ReplaceValues(
			"olcRootPW",
			stringValues("{SHA}ZCHf5VENMosrLzndLUwwLaKYD44="),
		)
		config.ReplaceValues("olcAccess", stringValues("{0}to * by * none"))
		if err := tx.Put(config, true); err != nil {
			return err
		}
		if err := tx.Put(directory.Entry{
			DN: "dc=other,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("domain")},
				{Description: "dc", Values: stringValues("other")},
			},
		}, false); err != nil {
			return err
		}
		if err := tx.Put(directory.Entry{
			DN: "olcDatabase={2}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{2}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=other,dc=com")},
				{Description: "olcAccess", Values: stringValues("{0}to * by * =d")},
			},
		}, false); err != nil {
			return err
		}
		return tx.SetNamingContexts([]string{"dc=example,dc=com", "dc=other,dc=com"})
	}); err != nil {
		t.Fatalf("configure database roots: %v", err)
	}

	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	assertLDAPResultCode(
		t,
		client.Bind("cn=admin,dc=example,dc=com", "wrong"),
		ldap.LDAPResultInvalidCredentials,
	)
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("root Bind(): %v", err)
	}

	result, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dc"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("root database Search() = %#v, %v", result, err)
	}

	_, err = client.Search(ldap.NewSearchRequest(
		"dc=other,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dc"},
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultInsufficientAccessRights)

	_, err = client.Search(ldap.NewSearchRequest(
		"olcDatabase={1}mdb,cn=config",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"olcRootDN"},
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
}

func TestLDAPClientConfigRootPasswordFallbackAndEmptyValue(t *testing.T) {
	t.Parallel()

	start := func(t *testing.T, rootPassword *string) (string, func()) {
		t.Helper()
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedDirectory(t, store)
		if err := store.Update(context.Background(), func(tx storage.Writer) error {
			configDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
			if err != nil {
				return err
			}
			config, err := tx.Get(configDN)
			if err != nil {
				return err
			}
			config.ReplaceValues(
				"olcRootDN",
				stringValues("uid=alice,ou=people,dc=example,dc=com"),
			)
			if rootPassword == nil {
				config.ReplaceValues("olcRootPW", nil)
			} else {
				config.ReplaceValues("olcRootPW", stringValues(*rootPassword))
			}
			config.ReplaceValues("olcAccess", stringValues(
				"{0}to attrs=userPassword by anonymous auth by * none",
				"{1}to * by * none",
			))
			return tx.Put(config, true)
		}); err != nil {
			t.Fatalf("configure root password: %v", err)
		}
		return startServer(t, store, Config{})
	}

	t.Run("unset falls back to entry", func(t *testing.T) {
		address, stop := start(t, nil)
		defer stop()
		client, err := ldap.DialURL("ldap://" + address)
		if err != nil {
			t.Fatalf("DialURL(): %v", err)
		}
		defer client.Close()
		if err := client.Bind(
			"uid=alice,ou=people,dc=example,dc=com",
			"secret",
		); err != nil {
			t.Fatalf("root entry Bind(): %v", err)
		}
		result, err := client.Search(ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"dc"},
			nil,
		))
		if err != nil || len(result.Entries) != 1 {
			t.Fatalf("root entry Search() = %#v, %v", result, err)
		}
	})

	t.Run("empty explicitly disables bind", func(t *testing.T) {
		empty := ""
		address, stop := start(t, &empty)
		defer stop()
		client, err := ldap.DialURL("ldap://" + address)
		if err != nil {
			t.Fatalf("DialURL(): %v", err)
		}
		defer client.Close()
		assertLDAPResultCode(
			t,
			client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"),
			ldap.LDAPResultInvalidCredentials,
		)
	})
}

func TestLDAPClientOnlineConfigReloadsAtomically(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()

	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("config root Bind(): %v", err)
	}
	anonymous, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(anonymous): %v", err)
	}
	defer anonymous.Close()

	searchData := func() error {
		_, err := anonymous.Search(ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"dc"},
			nil,
		))
		return err
	}
	if err := searchData(); err != nil {
		t.Fatalf("initial anonymous Search(): %v", err)
	}

	dataConfigDN := "olcDatabase={1}mdb,cn=config"
	deny := ldap.NewModifyRequest(dataConfigDN, nil)
	deny.Replace("olcAccess", []string{"{0}to * by * none"})
	if err := configClient.Modify(deny); err != nil {
		t.Fatalf("deny ACL Modify(): %v", err)
	}
	assertLDAPResultCode(t, searchData(), ldap.LDAPResultNoSuchObject)

	invalid := ldap.NewModifyRequest(dataConfigDN, nil)
	invalid.Replace("olcAccess", []string{`{0}to filter="(uid=*)" by * manage`})
	assertLDAPResultCode(t, configClient.Modify(invalid), ldap.LDAPResultConstraintViolation)
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		dn, err := directory.ParseDN(dataConfigDN)
		if err != nil {
			return err
		}
		entry, err := reader.Get(dn)
		if err != nil {
			return err
		}
		values := entry.Values("olcAccess")
		if len(values) != 1 || string(values[0]) != "{0}to * by * none" {
			return fmt.Errorf("rolled-back olcAccess = %q", values)
		}
		return nil
	}); err != nil {
		t.Fatalf("verify ACL rollback: %v", err)
	}

	allow := ldap.NewModifyRequest(dataConfigDN, nil)
	allow.Replace("olcAccess", []string{"{0}to * by * read"})
	if err := configClient.Modify(allow); err != nil {
		t.Fatalf("allow ACL Modify(): %v", err)
	}
	if err := searchData(); err != nil {
		t.Fatalf("re-enabled anonymous Search(): %v", err)
	}

	rootPassword := ldap.NewModifyRequest("olcDatabase={0}config,cn=config", nil)
	rootPassword.Replace("olcRootPW", []string{"new-config-secret"})
	if err := configClient.Modify(rootPassword); err != nil {
		t.Fatalf("root password Modify(): %v", err)
	}
	oldRoot, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(old root): %v", err)
	}
	defer oldRoot.Close()
	assertLDAPResultCode(
		t,
		oldRoot.Bind("cn=config", "config-secret"),
		ldap.LDAPResultInvalidCredentials,
	)
	newRoot, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(new root): %v", err)
	}
	defer newRoot.Close()
	if err := newRoot.Bind("cn=config", "new-config-secret"); err != nil {
		t.Fatalf("new config root Bind(): %v", err)
	}

	schemaDN := "cn={9}online,cn=schema,cn=config"
	addSchema := ldap.NewAddRequest(schemaDN, nil)
	addSchema.Attribute("objectClass", []string{"olcSchemaConfig"})
	addSchema.Attribute("cn", []string{"{9}online"})
	addSchema.Attribute("olcAttributeTypes", []string{
		"{0}( 1.2.840.113556.999.1 NAME 'onlineID' EQUALITY caseIgnoreMatch " +
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	})
	if err := configClient.Add(addSchema); err != nil {
		t.Fatalf("schema Add(): %v", err)
	}
	searchSchema := func() []string {
		t.Helper()
		result, err := configClient.Search(ldap.NewSearchRequest(
			"cn=Subschema",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"attributeTypes"},
			nil,
		))
		if err != nil {
			t.Fatalf("subschema Search(): %v", err)
		}
		return result.Entries[0].GetAttributeValues("attributeTypes")
	}
	if !containsSubstring(searchSchema(), "NAME 'onlineID'") {
		t.Fatal("online schema was not published")
	}
	if err := configClient.Del(ldap.NewDelRequest(schemaDN, nil)); err != nil {
		t.Fatalf("schema Delete(): %v", err)
	}
	if containsSubstring(searchSchema(), "NAME 'onlineID'") {
		t.Fatal("deleted online schema remained published")
	}
}

func TestLDAPClientAnonymousUpdateAllowanceReload(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()

	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("config root Bind(): %v", err)
	}
	writeACL := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	writeACL.Replace("olcAccess", []string{"{0}to * by * write"})
	if err := configClient.Modify(writeACL); err != nil {
		t.Fatalf("write ACL Modify(): %v", err)
	}

	anonymous, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(anonymous): %v", err)
	}
	defer anonymous.Close()
	assertLDAPResultCode(
		t,
		anonymous.Add(newPersonAddRequest("anon-blocked")),
		ldap.LDAPResultStrongAuthRequired,
	)

	enable := ldap.NewModifyRequest("cn=config", nil)
	enable.Add("olcAllows", []string{"update_anon"})
	if err := configClient.Modify(enable); err != nil {
		t.Fatalf("enable update_anon Modify(): %v", err)
	}
	if err := anonymous.Add(newPersonAddRequest("anon-enabled")); err != nil {
		t.Fatalf("anonymous Add() with update_anon: %v", err)
	}

	disable := ldap.NewModifyRequest("cn=config", nil)
	disable.Delete("olcAllows", []string{})
	if err := configClient.Modify(disable); err != nil {
		t.Fatalf("disable update_anon Modify(): %v", err)
	}
	assertLDAPResultCode(
		t,
		anonymous.Add(newPersonAddRequest("anon-disabled")),
		ldap.LDAPResultStrongAuthRequired,
	)

	invalid := ldap.NewModifyRequest("cn=config", nil)
	invalid.Replace("olcAllows", []string{"unknown_feature"})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	assertLDAPResultCode(
		t,
		anonymous.Add(newPersonAddRequest("anon-after-invalid")),
		ldap.LDAPResultStrongAuthRequired,
	)
}

func TestLDAPClientReadOnlyDatabaseReload(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)

	const dataRootDN = "cn=admin,dc=example,dc=com"
	address, stop := startServer(t, store, Config{
		RootDN:       dataRootDN,
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("config root Bind(): %v", err)
	}
	dataRoot, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(data root): %v", err)
	}
	defer dataRoot.Close()
	if err := dataRoot.Bind(dataRootDN, "admin-secret"); err != nil {
		t.Fatalf("data root Bind(): %v", err)
	}

	dataConfigDN := "olcDatabase={1}mdb,cn=config"
	readOnly := ldap.NewModifyRequest(dataConfigDN, nil)
	readOnly.Replace("olcReadOnly", []string{"TRUE"})
	if err := configClient.Modify(readOnly); err != nil {
		t.Fatalf("enable olcReadOnly Modify(): %v", err)
	}

	assertLDAPResultCode(
		t,
		dataRoot.Add(newPersonAddRequest("readonly-add")),
		ldap.LDAPResultUnwillingToPerform,
	)
	modify := ldap.NewModifyRequest("uid=alice,ou=people,dc=example,dc=com", nil)
	modify.Replace("mail", []string{"readonly@example.com"})
	assertLDAPResultCode(t, dataRoot.Modify(modify), ldap.LDAPResultUnwillingToPerform)
	assertLDAPResultCode(
		t,
		dataRoot.Del(ldap.NewDelRequest("ou=archive,dc=example,dc=com", nil)),
		ldap.LDAPResultUnwillingToPerform,
	)
	rename := ldap.NewModifyDNRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		"uid=alice-renamed",
		true,
		"ou=people,dc=example,dc=com",
	)
	assertLDAPResultCode(t, dataRoot.ModifyDN(rename), ldap.LDAPResultUnwillingToPerform)

	writable := ldap.NewModifyRequest(dataConfigDN, nil)
	writable.Replace("olcReadOnly", []string{"FALSE"})
	if err := configClient.Modify(writable); err != nil {
		t.Fatalf("disable olcReadOnly Modify(): %v", err)
	}
	if err := dataRoot.Add(newPersonAddRequest("writable")); err != nil {
		t.Fatalf("data root Add() after disabling olcReadOnly: %v", err)
	}

	invalid := ldap.NewModifyRequest(dataConfigDN, nil)
	invalid.Replace("olcReadOnly", []string{"sometimes"})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	if err := dataRoot.Add(newPersonAddRequest("writable-after-invalid")); err != nil {
		t.Fatalf("rolled-back olcReadOnly changed behavior: %v", err)
	}
}

func TestLDAPClientLastModReload(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)

	const dataRootDN = "cn=admin,dc=example,dc=com"
	address, stop := startServer(t, store, Config{
		RootDN:       dataRootDN,
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("config root Bind(): %v", err)
	}
	dataRoot, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(data root): %v", err)
	}
	defer dataRoot.Close()
	if err := dataRoot.Bind(dataRootDN, "admin-secret"); err != nil {
		t.Fatalf("data root Bind(): %v", err)
	}

	dataConfigDN := "olcDatabase={1}mdb,cn=config"
	disable := ldap.NewModifyRequest(dataConfigDN, nil)
	disable.Replace("olcLastMod", []string{"FALSE"})
	if err := configClient.Modify(disable); err != nil {
		t.Fatalf("disable olcLastMod Modify(): %v", err)
	}

	withoutAuditDN := "uid=without-audit,ou=people,dc=example,dc=com"
	if err := dataRoot.Add(newPersonAddRequest("without-audit")); err != nil {
		t.Fatalf("Add() with olcLastMod FALSE: %v", err)
	}
	auditAttributes := []string{
		"entryUUID",
		"entryCSN",
		"createTimestamp",
		"modifyTimestamp",
		"creatorsName",
		"modifiersName",
	}
	withoutAudit := readStoredEntry(t, store, withoutAuditDN)
	for _, attribute := range auditAttributes {
		if withoutAudit.HasAttribute(attribute) {
			t.Fatalf("olcLastMod FALSE generated %s", attribute)
		}
	}
	if !withoutAudit.HasAttribute("structuralObjectClass") ||
		!withoutAudit.HasAttribute("subschemaSubentry") {
		t.Fatal("schema operational attributes were suppressed with olcLastMod")
	}

	modify := ldap.NewModifyRequest(withoutAuditDN, nil)
	modify.Replace("mail", []string{"without-audit@example.com"})
	if err := dataRoot.Modify(modify); err != nil {
		t.Fatalf("Modify() with olcLastMod FALSE: %v", err)
	}
	withoutAudit = readStoredEntry(t, store, withoutAuditDN)
	for _, attribute := range auditAttributes {
		if withoutAudit.HasAttribute(attribute) {
			t.Fatalf("Modify() with olcLastMod FALSE generated %s", attribute)
		}
	}
	renamedWithoutAuditDN := "uid=without-audit-renamed,ou=people,dc=example,dc=com"
	rename := ldap.NewModifyDNRequest(
		withoutAuditDN,
		"uid=without-audit-renamed",
		true,
		"ou=people,dc=example,dc=com",
	)
	if err := dataRoot.ModifyDN(rename); err != nil {
		t.Fatalf("ModifyDN() with olcLastMod FALSE: %v", err)
	}
	withoutAudit = readStoredEntry(t, store, renamedWithoutAuditDN)
	for _, attribute := range auditAttributes {
		if withoutAudit.HasAttribute(attribute) {
			t.Fatalf("ModifyDN() with olcLastMod FALSE generated %s", attribute)
		}
	}

	enable := ldap.NewModifyRequest(dataConfigDN, nil)
	enable.Replace("olcLastMod", []string{"TRUE"})
	if err := configClient.Modify(enable); err != nil {
		t.Fatalf("enable olcLastMod Modify(): %v", err)
	}
	if err := dataRoot.Add(newPersonAddRequest("with-audit")); err != nil {
		t.Fatalf("Add() with olcLastMod TRUE: %v", err)
	}
	withAudit := readStoredEntry(
		t,
		store,
		"uid=with-audit,ou=people,dc=example,dc=com",
	)
	for _, attribute := range auditAttributes {
		if !withAudit.HasAttribute(attribute) {
			t.Fatalf("olcLastMod TRUE did not generate %s", attribute)
		}
	}

	invalid := ldap.NewModifyRequest(dataConfigDN, nil)
	invalid.Replace("olcLastMod", []string{"sometimes"})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	if err := dataRoot.Add(newPersonAddRequest("audit-after-invalid")); err != nil {
		t.Fatalf("Add() after invalid olcLastMod: %v", err)
	}
	afterInvalid := readStoredEntry(
		t,
		store,
		"uid=audit-after-invalid,ou=people,dc=example,dc=com",
	)
	for _, attribute := range auditAttributes {
		if !afterInvalid.HasAttribute(attribute) {
			t.Fatalf("rolled-back olcLastMod did not generate %s", attribute)
		}
	}
}

func TestLDAPClientConcurrentOnlineACLReload(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()
	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("config root Bind(): %v", err)
	}

	const readerCount = 4
	readers := make([]*ldap.Conn, readerCount)
	for index := range readers {
		readers[index], err = ldap.DialURL("ldap://" + address)
		if err != nil {
			t.Fatalf("DialURL(reader %d): %v", index, err)
		}
		defer readers[index].Close()
	}

	searchRequest := func() *ldap.SearchRequest {
		return ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"dc"},
			nil,
		)
	}
	unexpected := make(chan error, readerCount)
	var wait sync.WaitGroup
	for _, client := range readers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 25 {
				_, err := client.Search(searchRequest())
				if err == nil {
					continue
				}
				var ldapError *ldap.Error
				if !errors.As(err, &ldapError) ||
					ldapError.ResultCode != ldap.LDAPResultNoSuchObject {
					unexpected <- err
					return
				}
			}
		}()
	}

	for iteration := range 25 {
		value := "{0}to * by * read"
		if iteration%2 == 0 {
			value = "{0}to * by * none"
		}
		modify := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
		modify.Replace("olcAccess", []string{value})
		if err := configClient.Modify(modify); err != nil {
			t.Fatalf("ACL reload %d: %v", iteration, err)
		}
	}
	wait.Wait()
	close(unexpected)
	for err := range unexpected {
		t.Fatalf("concurrent Search(): %v", err)
	}
}

func TestLDAPClientGranularWriteACL(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		configDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		config, err := tx.Get(configDN)
		if err != nil {
			return err
		}
		config.ReplaceValues("olcAccess", stringValues(
			"{0}to attrs=userPassword by anonymous auth by self =xw by * none",
			"{1}to dn.subtree=\"ou=people,dc=example,dc=com\" attrs=children,entry,mail "+
				"by dn.exact=\"uid=alice,ou=people,dc=example,dc=com\" =a by users read by * none",
			"{2}to * by users read by * none",
		))
		return tx.Put(config, true)
	}); err != nil {
		t.Fatalf("configure granular write ACL: %v", err)
	}

	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	add := ldap.NewAddRequest("uid=created,ou=people,dc=example,dc=com", nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"created"})
	add.Attribute("cn", []string{"Created"})
	add.Attribute("sn", []string{"Created"})
	if err := client.Add(add); err != nil {
		t.Fatalf("Add() with =a: %v", err)
	}
	assertLDAPResultCode(
		t,
		client.Del(ldap.NewDelRequest("uid=created,ou=people,dc=example,dc=com", nil)),
		ldap.LDAPResultInsufficientAccessRights,
	)
	assertLDAPResultCode(
		t,
		client.Del(ldap.NewDelRequest("ou=people,dc=example,dc=com", nil)),
		ldap.LDAPResultInsufficientAccessRights,
	)

	addMail := ldap.NewModifyRequest("uid=alice,ou=people,dc=example,dc=com", nil)
	addMail.Add("mail", []string{"alice@example.com"})
	if err := client.Modify(addMail); err != nil {
		t.Fatalf("Modify(Add) with =a: %v", err)
	}
	deleteMail := ldap.NewModifyRequest("uid=alice,ou=people,dc=example,dc=com", nil)
	deleteMail.Delete("mail", []string{"alice@example.com"})
	assertLDAPResultCode(t, client.Modify(deleteMail), ldap.LDAPResultInsufficientAccessRights)
}

func TestLDAPClientAddContentACL(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		configDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		config, err := tx.Get(configDN)
		if err != nil {
			return err
		}
		config.ReplaceValues("olcAddContentAcl", stringValues("TRUE"))
		config.ReplaceValues("olcAccess", stringValues(
			"{0}to attrs=userPassword by anonymous auth by self =xw by * none",
			"{1}to dn.subtree=\"ou=people,dc=example,dc=com\" "+
				"attrs=children,entry,objectClass,uid,cn,sn "+
				"by dn.exact=\"uid=alice,ou=people,dc=example,dc=com\" =a by users read by * none",
			"{2}to * by users read by * none",
		))
		return tx.Put(config, true)
	}); err != nil {
		t.Fatalf("configure add content ACL: %v", err)
	}

	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	denied := ldap.NewAddRequest("uid=denied-content,ou=people,dc=example,dc=com", nil)
	denied.Attribute("objectClass", []string{"inetOrgPerson"})
	denied.Attribute("uid", []string{"denied-content"})
	denied.Attribute("cn", []string{"Denied Content"})
	denied.Attribute("sn", []string{"Content"})
	denied.Attribute("description", []string{"not authorized"})
	assertLDAPResultCode(t, client.Add(denied), ldap.LDAPResultInsufficientAccessRights)

	allowed := ldap.NewAddRequest("uid=allowed-content,ou=people,dc=example,dc=com", nil)
	allowed.Attribute("objectClass", []string{"inetOrgPerson"})
	allowed.Attribute("uid", []string{"allowed-content"})
	allowed.Attribute("cn", []string{"Allowed Content"})
	allowed.Attribute("sn", []string{"Content"})
	if err := client.Add(allowed); err != nil {
		t.Fatalf("Add() with authorized content: %v", err)
	}
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

	selfModify := ldap.NewModifyRequest("uid=alice,ou=people,dc=example,dc=com", nil)
	selfModify.Replace("mail", []string{"alice.updated@example.com"})
	if err := client.Modify(selfModify); err != nil {
		t.Fatalf("self Modify(): %v", err)
	}
	_, err = client.Compare(
		"uid=alice,ou=people,dc=example,dc=com",
		"userPassword",
		"secret",
	)
	assertLDAPResultCode(t, err, ldap.LDAPResultInsufficientAccessRights)
}

func seedOnlineConfiguration(t *testing.T, store storage.Store) {
	t.Helper()
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		dataConfigDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		dataConfig, err := tx.Get(dataConfigDN)
		if err != nil {
			return err
		}
		dataConfig.ReplaceValues("objectClass", stringValues("olcDatabaseConfig"))
		dataConfig.ReplaceValues("olcAccess", stringValues("{0}to * by * read"))
		if err := tx.Put(dataConfig, true); err != nil {
			return err
		}
		entries := []directory.Entry{
			{
				DN: "cn=config",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcGlobal")},
					{Description: "cn", Values: stringValues("config")},
				},
			},
			{
				DN: "cn=schema,cn=config",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcSchemaConfig")},
					{Description: "cn", Values: stringValues("schema")},
				},
			},
			{
				DN: "olcDatabase={0}config,cn=config",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
					{Description: "olcDatabase", Values: stringValues("{0}config")},
					{Description: "olcRootDN", Values: stringValues("cn=config")},
					{Description: "olcRootPW", Values: stringValues("config-secret")},
					{Description: "olcAccess", Values: stringValues("{0}to * by * none")},
				},
			},
		}
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return tx.SetNamingContexts([]string{"dc=example,dc=com", "cn=config"})
	}); err != nil {
		t.Fatalf("configure online cn=config: %v", err)
	}
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
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				{
					Description: "olcAccess",
					Values: stringValues(
						"{0}to attrs=userPassword by self =xw by anonymous auth by * none",
						"{1}to * by self write by users read by * none",
					),
				},
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

func newPersonAddRequest(uid string) *ldap.AddRequest {
	request := ldap.NewAddRequest(
		"uid="+uid+",ou=people,dc=example,dc=com",
		nil,
	)
	request.Attribute("objectClass", []string{"inetOrgPerson"})
	request.Attribute("uid", []string{uid})
	request.Attribute("cn", []string{"Test User"})
	request.Attribute("sn", []string{"User"})
	return request
}

func readStoredEntry(t *testing.T, store storage.Store, rawDN string) directory.Entry {
	t.Helper()

	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", rawDN, err)
	}
	var entry directory.Entry
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		entry, err = reader.Get(dn)
		return err
	}); err != nil {
		t.Fatalf("read stored entry %q: %v", rawDN, err)
	}
	return entry
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
