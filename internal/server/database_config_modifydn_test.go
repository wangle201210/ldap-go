package server

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	databaseConfigModifyDNOldDN  = "olcDatabase={1}mdb,cn=config"
	databaseConfigModifyDNNewDN  = "olcDatabase={2}mdb,cn=config"
	databaseConfigModifyDNDataDN = "uid=alice,ou=people,dc=example,dc=com"
)

func TestOnlineDatabaseConfigurationModifyDNRequiresEntryUUID(t *testing.T) {
	t.Run("missing entryUUID is rejected and data survives restart", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "directory.db")
		store := openDatabaseConfigModifyDNBolt(t, path)
		seedOnlineConfiguration(t, store)

		address, stop := startServer(t, store, Config{})
		configClient := dialDatabaseConfigModifyDNConfigRoot(t, address)
		err := configClient.ModifyDN(ldap.NewModifyDNRequest(
			databaseConfigModifyDNOldDN,
			"olcDatabase={2}mdb",
			true,
			"",
		))
		var ldapErr *ldap.Error
		if !errors.As(err, &ldapErr) ||
			ldapErr.ResultCode != ldap.LDAPResultUnwillingToPerform {
			t.Fatalf("ModifyDN() error = %v, want unwillingToPerform", err)
		}
		if ldapErr.Err == nil || !strings.Contains(ldapErr.Err.Error(), "entryUUID") {
			t.Fatalf("ModifyDN() diagnostic = %v, want entryUUID guidance", ldapErr.Err)
		}
		assertDatabaseConfigModifyDNState(
			t,
			address,
			databaseConfigModifyDNOldDN,
			false,
			false,
		)

		configClient.Close()
		stop()
		if err := store.Close(); err != nil {
			t.Fatalf("CloseBolt(): %v", err)
		}

		store = openDatabaseConfigModifyDNBolt(t, path)
		defer store.Close()
		address, stop = startServer(t, store, Config{})
		defer stop()
		assertDatabaseConfigModifyDNState(
			t,
			address,
			databaseConfigModifyDNOldDN,
			false,
			false,
		)
	})

	t.Run("entryUUID keeps the partition stable across rename and restart", func(t *testing.T) {
		const databaseUUID = "8d59a743-b64c-4c90-905c-3045dd69714c"
		path := filepath.Join(t.TempDir(), "directory.db")
		store := openDatabaseConfigModifyDNBolt(t, path)
		seedOnlineConfiguration(t, store)
		if err := store.Update(context.Background(), func(writer storage.Writer) error {
			dn, err := directory.ParseDN(databaseConfigModifyDNOldDN)
			if err != nil {
				return err
			}
			entry, err := writer.Get(dn)
			if err != nil {
				return err
			}
			entry.ReplaceValues("entryUUID", stringValues(databaseUUID))
			if err := writer.Put(entry, true); err != nil {
				return err
			}
			return writer.PutIn(storage.OpenLDAPConfigPartition, directory.Entry{
				DN: "olcDatabase={2}null,cn=config",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
					{Description: "olcDatabase", Values: stringValues("{2}null")},
					{Description: "olcSuffix", Values: stringValues("dc=other,dc=example")},
					{Description: "entryUUID", Values: stringValues("33333333-3333-4333-8333-333333333333")},
				},
			}, false)
		}); err != nil {
			t.Fatalf("set database entryUUID: %v", err)
		}

		address, stop := startServer(t, store, Config{})
		configClient := dialDatabaseConfigModifyDNConfigRoot(t, address)
		if err := configClient.ModifyDN(ldap.NewModifyDNRequest(
			databaseConfigModifyDNOldDN,
			"olcDatabase={2}mdb",
			true,
			"",
		)); err != nil {
			t.Fatalf("ModifyDN() with entryUUID: %v", err)
		}
		assertDatabaseConfigModifyDNState(
			t,
			address,
			databaseConfigModifyDNNewDN,
			true,
			true,
		)

		configClient.Close()
		stop()
		if err := store.Close(); err != nil {
			t.Fatalf("CloseBolt(): %v", err)
		}

		store = openDatabaseConfigModifyDNBolt(t, path)
		defer store.Close()
		address, stop = startServer(t, store, Config{})
		defer stop()
		assertDatabaseConfigModifyDNState(
			t,
			address,
			databaseConfigModifyDNNewDN,
			true,
			true,
		)
	})
}

func openDatabaseConfigModifyDNBolt(t *testing.T, path string) storage.Store {
	t.Helper()
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	return store
}

func dialDatabaseConfigModifyDNConfigRoot(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		client.Close()
		t.Fatalf("Bind(cn=config): %v", err)
	}
	return client
}

func assertDatabaseConfigModifyDNState(
	t *testing.T,
	address string,
	wantConfigDN string,
	wantUUID bool,
	wantSwappedSibling bool,
) {
	t.Helper()
	configClient := dialDatabaseConfigModifyDNConfigRoot(t, address)
	defer configClient.Close()

	configResult, err := configClient.Search(ldap.NewSearchRequest(
		wantConfigDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"olcDatabase", "entryUUID"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(database config %q): %v", wantConfigDN, err)
	}
	if len(configResult.Entries) != 1 {
		t.Fatalf("Search(database config %q) entries = %d, want 1", wantConfigDN, len(configResult.Entries))
	}
	if got := configResult.Entries[0].GetAttributeValue("entryUUID"); (got != "") != wantUUID {
		t.Fatalf("database config entryUUID = %q, want present=%v", got, wantUUID)
	}

	if wantSwappedSibling {
		return
	}
	missingConfigDN := databaseConfigModifyDNNewDN
	if wantConfigDN == databaseConfigModifyDNNewDN {
		missingConfigDN = databaseConfigModifyDNOldDN
	}
	_, err = configClient.Search(ldap.NewSearchRequest(
		missingConfigDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"olcDatabase"},
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)

	dataClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(data): %v", err)
	}
	defer dataClient.Close()
	dataResult, err := dataClient.Search(ldap.NewSearchRequest(
		databaseConfigModifyDNDataDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(data %q): %v", databaseConfigModifyDNDataDN, err)
	}
	if len(dataResult.Entries) != 1 || dataResult.Entries[0].GetAttributeValue("uid") != "alice" {
		t.Fatalf("Search(data %q) entries = %#v", databaseConfigModifyDNDataDN, dataResult.Entries)
	}
}
