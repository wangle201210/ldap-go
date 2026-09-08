package server

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/mdbentry"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const entryLimitConfigDN = "olcDatabase={1}mdb,cn=config"

func entryLimitStore(t *testing.T, bolt bool) storage.Store {
	t.Helper()
	if !bolt {
		return storage.NewMemory()
	}
	s, err := storage.OpenBolt(filepath.Join(t.TempDir(), "entry-limit.db"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func seedEntryLimit(t *testing.T, store storage.Store, limit string, lastmod bool) {
	t.Helper()
	seedOnlineConfiguration(t, store)
	setUnsupportedRuntimeConfigurationAttribute(t, store, entryLimitConfigDN, "olcRootDN", "cn=admin,dc=example,dc=com")
	setUnsupportedRuntimeConfigurationAttribute(t, store, entryLimitConfigDN, "olcRootPW", "secret")
	setUnsupportedRuntimeConfigurationAttribute(t, store, entryLimitConfigDN, "olcDbMaxEntrySize", limit)
	if !lastmod {
		setUnsupportedRuntimeConfigurationAttribute(t, store, entryLimitConfigDN, "olcLastMod", "FALSE")
	}
}

func replaceEntryLimit(t *testing.T, client *ldap.Conn, value uint64) {
	t.Helper()
	m := ldap.NewModifyRequest(entryLimitConfigDN, nil)
	m.Replace(mdbentry.Attribute, []string{strconv.FormatUint(value, 10)})
	if err := client.Modify(m); err != nil {
		t.Fatal(err)
	}
}

func entryLimitPerson(dn string, description string) *ldap.AddRequest {
	a := ldap.NewAddRequest(dn, nil)
	a.Attribute("objectClass", []string{"inetOrgPerson"})
	a.Attribute("cn", []string{"limit"})
	a.Attribute("sn", []string{"Example"})
	if description != "" {
		a.Attribute("description", []string{description})
	}
	return a
}

func TestMaxEntrySizeWritesAndRollback(t *testing.T) {
	for _, bolt := range []bool{false, true} {
		t.Run(strconv.FormatBool(bolt), func(t *testing.T) {
			store := entryLimitStore(t, bolt)
			defer store.Close()
			seedEntryLimit(t, store, "0", true)
			instance, address, stop := startConfigurationCapabilityServer(t, store)
			defer stop()
			config := bindConstraintClient(t, address, "cn=config", "config-secret")
			defer config.Close()
			client := bindConstraintClient(t, address, "cn=admin,dc=example,dc=com", "secret")
			defer client.Close()
			dn := "cn=limit,ou=people,dc=example,dc=com"
			if err := client.Add(entryLimitPerson(dn, strings.Repeat("x", 2048))); err != nil {
				t.Fatal(err)
			}
			before := readStoredEntry(t, store, dn)
			replaceEntryLimit(t, config, 1024)
			if _, err := client.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"*"}, nil)); err != nil {
				t.Fatal(err)
			}
			for _, n := range []int{4096, 2048, 1024} {
				m := ldap.NewModifyRequest(dn, nil)
				m.Replace("description", []string{strings.Repeat("x", n)})
				assertLDAPResultCode(t, client.Modify(m), ldap.LDAPResultAdminLimitExceeded)
				if got := readStoredEntry(t, store, dn); !got.Equal(before) {
					t.Fatal("failed modify changed entry or operational attributes")
				}
			}
			assertLDAPResultCode(t, client.ModifyDN(ldap.NewModifyDNRequest(dn, "cn=renamed", true, "")), ldap.LDAPResultAdminLimitExceeded)
			password, err := client.PasswordModify(ldap.NewPasswordModifyRequest(dn, "", ""))
			assertLDAPResultCode(t, err, ldap.LDAPResultAdminLimitExceeded)
			if password != nil && password.GeneratedPassword != "" {
				t.Fatal("failed password change returned a generated password")
			}
			assertLDAPResultCode(t, client.Add(entryLimitPerson("cn=limit,ou=archive,dc=example,dc=com", strings.Repeat("x", 2048))), ldap.LDAPResultAdminLimitExceeded)
			active := instance.runtime.Load()
			m := ldap.NewModifyRequest(entryLimitConfigDN, nil)
			m.Replace(mdbentry.Attribute, []string{"0"})
			m.Replace("olcThreads", []string{"32"})
			assertLDAPResultCode(t, config.Modify(m), ldap.LDAPResultConstraintViolation)
			if instance.runtime.Load() != active {
				t.Fatal("invalid configuration activated runtime")
			}
			if got := readStoredEntry(t, store, entryLimitConfigDN).Values(mdbentry.Attribute); string(got[0]) != "1024" {
				t.Fatalf("rollback limit=%q", got)
			}
			m = ldap.NewModifyRequest(dn, nil)
			m.Delete("description", nil)
			if err := client.Modify(m); err != nil {
				t.Fatalf("shrink below limit: %v", err)
			}
			if err := client.Del(ldap.NewDelRequest(dn, nil)); err != nil {
				t.Fatal(err)
			}
			replaceEntryLimit(t, config, 1)
			assertLDAPResultCode(t, client.Add(entryLimitPerson("cn=limit,ou=missing,dc=example,dc=com", "x")), ldap.LDAPResultNoSuchObject)
			if err := client.Del(ldap.NewDelRequest("uid=alice,ou=people,dc=example,dc=com", nil)); err != nil {
				t.Fatalf("delete existing oversized entry: %v", err)
			}
			m = ldap.NewModifyRequest(entryLimitConfigDN, nil)
			m.Delete(mdbentry.Attribute, nil)
			if err := config.Modify(m); err != nil {
				t.Fatal(err)
			}
			if err := client.Add(entryLimitPerson(dn, strings.Repeat("x", 2048))); err != nil {
				t.Fatalf("deleted limit: %v", err)
			}
		})
	}
}

func TestMaxEntrySizeRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.db")
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	seedEntryLimit(t, store, "0", true)
	_, address, stop := startConfigurationCapabilityServer(t, store)
	config := bindConstraintClient(t, address, "cn=config", "config-secret")
	replaceEntryLimit(t, config, 1)
	config.Close()
	stop()
	store.Close()
	store, err = storage.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	instance, address, stop := startConfigurationCapabilityServer(t, store)
	defer stop()
	if databaseForDN(instance.runtime.Load(), mustLegacyDNIdentityDN(t, "dc=example,dc=com")).entryLimit.bytes != 1 {
		t.Fatal("lost runtime limit after restart")
	}
	client := bindConstraintClient(t, address, "cn=admin,dc=example,dc=com", "secret")
	defer client.Close()
	assertLDAPResultCode(t, client.Add(entryLimitPerson("cn=limit,dc=example,dc=com", "x")), ldap.LDAPResultAdminLimitExceeded)
}

func TestMaxEntrySizeTransaction(t *testing.T) {
	for _, bolt := range []bool{false, true} {
		t.Run(strconv.FormatBool(bolt), func(t *testing.T) {
			store := entryLimitStore(t, bolt)
			defer store.Close()
			seedEntryLimit(t, store, "1024", true)
			_, address, stop := startConfigurationCapabilityServer(t, store)
			defer stop()
			connection := dialAndBindRawLDAP(t, address, "cn=admin,dc=example,dc=com", "secret")
			defer connection.Close()
			id := startRawLDAPTransaction(t, connection, 2)
			entry := transactionTestPerson("limit-txn")
			assertRawLDAPResult(t, sendRawLDAPOperation(t, connection, 3, rawAddRequest(entry), rawTransactionSpecificationControl(id, true, true)), 0)
			assertRawLDAPResult(t, sendRawLDAPOperation(t, connection, 4, rawModifyReplaceRequest(entry.DN, "description", strings.Repeat("x", 2048)), rawTransactionSpecificationControl(id, true, true)), 0)
			response := endRawLDAPTransaction(t, connection, 5, true, id)
			assertRawLDAPResult(t, response, int64(ldapwire.ResultAdminLimitExceeded))
			if transactionEntryExists(t, store, entry.DN) {
				t.Fatal("failed transaction retained its first Add")
			}
			value, present := rawExtendedResponseValue(response)
			if !present {
				t.Fatal("missing failed transaction message ID")
			}
			decoded, err := ldapwire.DecodeTransactionEndResponseValue(value)
			if err != nil {
				t.Fatal(err)
			}
			if !decoded.HasFailedMessageID || decoded.FailedMessageID != 4 {
				t.Fatalf("failed transaction response: %+v", decoded)
			}
		})
	}
}

func TestMaxEntrySizeStartupGrammarAndScope(t *testing.T) {
	for _, value := range []string{"010", "+1", "-1", "18446744073709551616", " 1", "1k"} {
		t.Run(value, func(t *testing.T) {
			store := storage.NewMemory()
			defer store.Close()
			seedEntryLimit(t, store, value, true)
			if _, err := New(Config{Store: store}); err == nil {
				t.Fatal("accepted invalid startup limit")
			}
		})
	}
	store := storage.NewMemory()
	defer store.Close()
	seedEntryLimit(t, store, "1", true)
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	runtime := instance.runtime.Load()
	db := *databaseForDN(runtime, mustLegacyDNIdentityDN(t, "dc=example,dc=com"))
	entry := directory.Entry{DN: "cn=limit,dc=example,dc=com", Attributes: []directory.Attribute{{Description: "cn", Values: stringValues("limit")}}}
	for _, name := range []string{"{1}mdb", "{2}mdb", "{3}ldap", "{4}null"} {
		candidate := db
		candidate.name = name
		candidate.partition = name
		if name == "{2}mdb" {
			candidate.entryLimit.bytes = 0
		}
		err := store.Update(context.Background(), func(w storage.Writer) error { return writerForDatabase(w, candidate).Put(entry, false) })
		if name == "{1}mdb" {
			if failure := asOperationFailure(err); failure == nil || failure.result.Code != 11 {
				t.Fatalf("limit error=%v", err)
			}
		} else if err != nil {
			t.Fatalf("unrelated database %s: %v", name, err)
		}
	}
	for _, config := range []syncConsumerConfig{{partition: db.partition, entryLimit: db.entryLimit, normalizer: runtime.schema}} {
		err := store.Update(context.Background(), func(w storage.Writer) error { return syncConsumerWriter(w, nil, config).Put(entry, true) })
		if failure := asOperationFailure(err); failure == nil || failure.result.Code != 11 {
			t.Fatalf("changelog bypassed limit: %v", err)
		}
	}
}
