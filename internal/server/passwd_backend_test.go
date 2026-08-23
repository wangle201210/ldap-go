package server

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const passwdTestSuffix = "ou=accounts,dc=passwd,dc=test"

func TestPasswdBackendFixtureSearchProjectionACLAndReadOnlyResults(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	fixture := writePasswdBackendFixture(t, ""+
		"alice:x:1000:1000:Alice Example,Room 1:/home/alice:/bin/sh\n"+
		"bob:x:1001:1001:Bob & Builder:/home/bob:/bin/bash\n")
	seedPasswdBackendConfiguration(t, store, fixture)

	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()

	one, err := client.Search(ldap.NewSearchRequest(
		passwdTestSuffix,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=person)",
		[]string{"uid", "cn", "sn", "description"},
		nil,
	))
	if err != nil || len(one.Entries) != 2 {
		t.Fatalf("one-level passwd Search = %#v, %v", one, err)
	}

	alice, err := client.Search(ldap.NewSearchRequest(
		"uid=alice,"+passwdTestSuffix,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(uid=ALICE)(sn=example))",
		[]string{"objectClass", "uid", "cn", "sn", "description"},
		nil,
	))
	if err != nil || len(alice.Entries) != 1 {
		t.Fatalf("base passwd Search = %#v, %v", alice, err)
	}
	entry := alice.Entries[0]
	if got := entry.GetAttributeValues("objectClass"); !sameStringSet(got, []string{"person", "uidObject"}) {
		t.Fatalf("objectClass = %q", got)
	}
	if got := entry.GetAttributeValues("cn"); !sameStringSet(got, []string{"alice", "Alice Example"}) {
		t.Fatalf("cn = %q", got)
	}
	if got := entry.GetAttributeValues("sn"); !sameStringSet(got, []string{"alice", "Example"}) {
		t.Fatalf("sn = %q", got)
	}
	if got := entry.GetAttributeValues("description"); len(got) != 0 {
		t.Fatalf("ACL-visible description = %q, want hidden", got)
	}

	hiddenFilter, err := client.Search(ldap.NewSearchRequest(
		passwdTestSuffix,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(description=Alice Example,Room 1)",
		[]string{"uid"},
		nil,
	))
	if err != nil || len(hiddenFilter.Entries) != 0 {
		t.Fatalf("ACL-filtered passwd Search = %#v, %v", hiddenFilter, err)
	}

	typesOnly, err := client.Search(ldap.NewSearchRequest(
		"uid=bob,"+passwdTestSuffix,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		true,
		"(uid=bob)",
		[]string{"uid", "cn"},
		nil,
	))
	if err != nil || len(typesOnly.Entries) != 1 ||
		len(typesOnly.Entries[0].Attributes) != 2 {
		t.Fatalf("typesOnly passwd Search = %#v, %v", typesOnly, err)
	}
	for _, attribute := range typesOnly.Entries[0].Attributes {
		if len(attribute.ByteValues) != 0 {
			t.Fatalf("typesOnly %s values = %#v", attribute.Name, attribute.ByteValues)
		}
	}

	_, err = client.Search(ldap.NewSearchRequest(
		passwdTestSuffix,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultSizeLimitExceeded)

	assertLDAPResultCode(
		t,
		client.Bind("uid=alice,"+passwdTestSuffix, "secret"),
		ldap.LDAPResultUnwillingToPerform,
	)
	add := ldap.NewAddRequest("uid=new,"+passwdTestSuffix, nil)
	add.Attribute("objectClass", []string{"person", "uidObject"})
	add.Attribute("uid", []string{"new"})
	add.Attribute("cn", []string{"new"})
	add.Attribute("sn", []string{"new"})
	assertLDAPResultCode(t, client.Add(add), ldap.LDAPResultUnwillingToPerform)
}

func TestPasswdBackendSourceValidation(t *testing.T) {
	valid := writePasswdBackendFixture(t, "user:x:1:1:User:/home/user:/bin/sh\n")
	users, err := readPasswdUsers(valid)
	if err != nil || len(users) != 1 || users[0].name != "user" {
		t.Fatalf("readPasswdUsers(valid) = %#v, %v", users, err)
	}
	malformed := writePasswdBackendFixture(t, "not-a-passwd-record\n")
	if _, err := readPasswdUsers(malformed); err == nil {
		t.Fatal("readPasswdUsers accepted malformed record")
	}
	if runtime.GOOS != "windows" {
		before, err := os.Lstat(valid)
		if err != nil {
			t.Fatalf("Lstat(valid): %v", err)
		}
		opened, err := os.Open(valid)
		if err != nil {
			t.Fatalf("Open(valid): %v", err)
		}
		if err := os.Chmod(valid, 0o666); err != nil {
			_ = opened.Close()
			t.Fatalf("Chmod(valid): %v", err)
		}
		if _, _, err := readOpenedPasswdSnapshot(before, opened); err == nil {
			_ = opened.Close()
			t.Fatal("opened passwd source permissions were not rechecked")
		}
		_ = opened.Close()
		if err := os.Chmod(valid, 0o600); err != nil {
			t.Fatalf("restore passwd permissions: %v", err)
		}
		link := filepath.Join(t.TempDir(), "passwd-link")
		if err := os.Symlink(valid, link); err != nil {
			t.Fatalf("Symlink(): %v", err)
		}
		if _, err := readPasswdUsers(link); err == nil {
			t.Fatal("readPasswdUsers accepted symlink")
		}
	}
}

func TestPasswdBackendRefreshesChangedSourceOnSearch(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	fixture := writePasswdBackendFixture(
		t,
		"alice:x:1000:1000:Alice:/home/alice:/bin/sh\n",
	)
	seedPasswdBackendConfiguration(t, store, fixture)
	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	assertPasswdSearchUIDs(t, client, []string{"alice"})

	if err := os.WriteFile(
		fixture,
		[]byte("carol:x:1002:1002:Carol:/home/carol:/bin/sh\n"),
		0o600,
	); err != nil {
		t.Fatalf("replace passwd fixture: %v", err)
	}
	changed := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(fixture, changed, changed); err != nil {
		t.Fatalf("Chtimes(passwd fixture): %v", err)
	}
	assertPasswdSearchUIDs(t, client, []string{"carol"})
}

func assertPasswdSearchUIDs(t *testing.T, client *ldap.Conn, want []string) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		passwdTestSuffix,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=person)",
		[]string{"uid"},
		nil,
	))
	if err != nil || len(result.Entries) != len(want) {
		t.Fatalf("passwd refresh Search = %#v, %v; want %q", result, err, want)
	}
	for index, entry := range result.Entries {
		if got := entry.GetAttributeValue("uid"); got != want[index] {
			t.Fatalf("passwd refresh uid[%d] = %q, want %q", index, got, want[index])
		}
	}
}

func seedPasswdBackendConfiguration(t *testing.T, store storage.Store, fixture string) {
	t.Helper()
	entry := directory.Entry{
		DN: "olcDatabase={1}passwd,cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcPasswdConfig")},
			{Description: "olcDatabase", Values: stringValues("{1}passwd")},
			{Description: "olcSuffix", Values: stringValues(passwdTestSuffix)},
			{Description: "olcPasswdFile", Values: stringValues(fixture)},
			{Description: "olcAccess", Values: stringValues(
				"{0}to attrs=description by * none",
				"{1}to * by * read",
			)},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.PutIn(configurationStoragePartition, entry, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{passwdTestSuffix})
	}); err != nil {
		t.Fatalf("seed passwd backend: %v", err)
	}
}

func writePasswdBackendFixture(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile(passwd fixture): %v", err)
	}
	return path
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[string]int, len(left))
	for _, value := range left {
		seen[value]++
	}
	for _, value := range right {
		seen[value]--
	}
	for _, count := range seen {
		if count != 0 {
			return false
		}
	}
	return true
}
