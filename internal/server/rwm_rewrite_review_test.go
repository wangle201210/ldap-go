package server

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	rwmReviewRelayDatabaseDN = "olcDatabase={2}relay,cn=config"
	rwmReviewLocalOverlayDN  = "olcOverlay={0}rwm,olcDatabase={1}mdb,cn=config"
)

type rwmRelayWriteOrderingObservation struct {
	add      uint16
	modify   uint16
	delete   uint16
	rename   uint16
	critical uint16
}

func TestRWMRewriteRelayOriginalRestrictionsAndOrdering(t *testing.T) {
	for _, test := range []struct {
		name       string
		readOnly   bool
		restrict   bool
		wantWrites uint16
	}{
		{name: "rewrite result", wantWrites: ldap.LDAPResultBusy},
		{name: "read only", readOnly: true, wantWrites: ldap.LDAPResultUnwillingToPerform},
		{name: "restricted writes", restrict: true, wantWrites: ldap.LDAPResultUnwillingToPerform},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedRWMRelayConfiguration(t, store)
			configureRWMReviewRelay(t, store, test.readOnly, test.restrict)
			replaceRWMRewriteConfiguration(
				t,
				store,
				rwmOverlayConfigDN,
				"olcRwmRewrite",
				rwmReviewTerminalWriteDirectives()...,
			)
			address, stop := startServer(t, store, Config{})
			defer stop()

			got := observeRWMRelayWriteOrdering(t, "ldap://"+address)
			want := rwmRelayWriteOrderingObservation{
				add:      test.wantWrites,
				modify:   test.wantWrites,
				delete:   test.wantWrites,
				rename:   test.wantWrites,
				critical: ldap.LDAPResultUnavailableCriticalExtension,
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("write ordering = %#v, want %#v", got, want)
			}
		})
	}
}

func configureRWMReviewRelay(
	t *testing.T,
	store storage.Store,
	readOnly,
	restrict bool,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(rwmReviewRelayDatabaseDN)
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		if readOnly {
			entry.ReplaceValues("olcReadOnly", stringValues("TRUE"))
		}
		if restrict {
			entry.ReplaceValues(
				"olcRestrict",
				stringValues("add modify delete rename"),
			)
		}
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure relay restrictions: %v", err)
	}
}

func rwmReviewTerminalWriteDirectives() []string {
	directives := rwmRewriteOverlayDirectives(
		"dc=virtual,dc=test",
		"dc=example,dc=com",
	)
	for _, context := range []string{"addDN", "modifyDN", "deleteDN", "renameDN"} {
		directives = append(
			directives,
			fmt.Sprintf("{%d}rewriteContext %s", len(directives), context),
			fmt.Sprintf(`{%d}rewriteRule ".*" "$0" ":U{51}"`, len(directives)+1),
		)
	}
	return directives
}

func observeRWMRelayWriteOrdering(
	t *testing.T,
	uri string,
) rwmRelayWriteOrderingObservation {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=virtual,dc=test", "secret"); err != nil {
		t.Fatalf("bind relay root: %v", err)
	}

	add := ldap.NewAddRequest("uid=ordering,ou=people,dc=virtual,dc=test", nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"ordering"})
	add.Attribute("cn", []string{"Ordering"})
	add.Attribute("sn", []string{"Ordering"})
	alice := "uid=alice,ou=people,dc=virtual,dc=test"
	modify := ldap.NewModifyRequest(alice, nil)
	modify.Replace("cn", []string{"Ordering"})
	rename := ldap.NewModifyDNRequest(alice, "uid=ordering", true, "")
	unknownCritical := ldap.NewControlString("1.3.6.1.4.1.4203.666.99.99", true, "")
	critical := ldap.NewAddRequest("uid=critical,ou=people,dc=virtual,dc=test", []ldap.Control{unknownCritical})
	critical.Attribute("objectClass", []string{"inetOrgPerson"})
	critical.Attribute("uid", []string{"critical"})
	critical.Attribute("cn", []string{"Critical"})
	critical.Attribute("sn", []string{"Critical"})
	return rwmRelayWriteOrderingObservation{
		add:      monitorLDAPResultCode(client.Add(add)),
		modify:   monitorLDAPResultCode(client.Modify(modify)),
		delete:   monitorLDAPResultCode(client.Del(ldap.NewDelRequest(alice, nil))),
		rename:   monitorLDAPResultCode(client.ModifyDN(rename)),
		critical: monitorLDAPResultCode(client.Add(critical)),
	}
}

func TestRWMRewriteRelayDeleteRejectionInTransaction(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedRWMRelayConfiguration(t, store)
	directives := rwmRewriteOverlayDirectives(
		"dc=virtual,dc=test",
		"dc=example,dc=com",
	)
	directives = append(
		directives,
		fmt.Sprintf("{%d}rewriteContext deleteDN", len(directives)),
		fmt.Sprintf(`{%d}rewriteRule ".*" "" "#"`, len(directives)+1),
	)
	replaceRWMRewriteConfiguration(
		t,
		store,
		rwmOverlayConfigDN,
		"olcRwmRewrite",
		directives...,
	)
	address, stop := startServer(t, store, Config{})
	defer stop()
	const localAlice = "uid=alice,ou=people,dc=virtual,dc=test"

	ordinary := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=virtual,dc=test",
		"secret",
	)
	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(t, ordinary, 2, rawDeleteRequest(localAlice)),
		int64(ldapwire.ResultUnwillingToPerform),
	)
	_ = ordinary.Close()

	transaction := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=virtual,dc=test",
		"secret",
	)
	defer transaction.Close()
	identifier := startRawLDAPTransaction(t, transaction, 2)
	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			transaction,
			3,
			rawDeleteRequest(localAlice),
			rawTransactionSpecificationControl(identifier, true, true),
		),
		int64(ldapwire.ResultSuccess),
	)
	response := endRawLDAPTransaction(t, transaction, 4, true, identifier)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultUnwillingToPerform))
	value, present := rawExtendedResponseValue(response)
	if !present {
		t.Fatal("transaction failure response value is absent")
	}
	decoded, err := ldapwire.DecodeTransactionEndResponseValue(value)
	if err != nil {
		t.Fatalf("decode transaction response: %v", err)
	}
	if !decoded.HasFailedMessageID || decoded.FailedMessageID != 3 {
		t.Fatalf("transaction response = %#v, want failed message ID 3", decoded)
	}
	if !transactionEntryExists(t, store, "uid=alice,ou=people,dc=example,dc=com") {
		t.Fatal("deleteDN rejection did not preserve the entry")
	}
}

func TestRWMRewriteLocalBackendRulesFailClosed(t *testing.T) {
	t.Run("startup", func(t *testing.T) {
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedRWMReviewLocalConfiguration(t, store, []string{
			"{0}rewriteEngine on",
			"{1}rewriteContext deleteDN",
			`{2}rewriteRule ".*" "" "#"`,
		})
		instance, err := New(Config{Store: store})
		if err == nil {
			instance.closeSQLBackends()
			t.Fatal("New accepted common rewrite rules on local mdb")
		}
		for _, fragment := range []string{rwmReviewLocalOverlayDN, "common rewrite", "local backend"} {
			if !strings.Contains(err.Error(), fragment) {
				t.Fatalf("startup error %q does not contain %q", err, fragment)
			}
		}
	})

	t.Run("online rollback", func(t *testing.T) {
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedRWMReviewLocalConfiguration(t, store, nil)
		instance, address, stop := startRWMConfigurationServer(t, store)
		defer stop()
		client := bindConstraintClient(t, address, "cn=config", "config-secret")
		defer client.Close()
		active := instance.runtime.Load()
		request := ldap.NewModifyRequest(rwmReviewLocalOverlayDN, nil)
		request.Replace("olcRwmRewrite", []string{
			"{0}rewriteEngine on",
			"{1}rewriteContext deleteDN",
			`{2}rewriteRule ".*" "" "#"`,
		})
		assertLDAPResultCode(t, client.Modify(request), ldap.LDAPResultConstraintViolation)
		if instance.runtime.Load() != active {
			t.Fatal("rejected local rewrite activated a new runtime")
		}
		entry := readStoredEntry(t, store, rwmReviewLocalOverlayDN)
		if got := byteValuesToStrings(entry.Values("olcRwmRewrite")); len(got) != 0 {
			t.Fatalf("rejected local rewrite persisted values %q", got)
		}
		if got := byteValuesToStrings(entry.Values("olcRwmMap")); !slices.Equal(got, []string{"{0}attribute description displayName"}) {
			t.Fatalf("local map after rollback = %q", got)
		}
	})
}

func seedRWMReviewLocalConfiguration(
	t *testing.T,
	store storage.Store,
	rewrite []string,
) {
	t.Helper()
	overlay := directory.Entry{
		DN: rwmReviewLocalOverlayDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcRwmConfig")},
			{Description: "olcOverlay", Values: stringValues("{0}rwm")},
			{Description: "olcRwmMap", Values: stringValues("{0}attribute description displayName")},
		},
	}
	if len(rewrite) != 0 {
		overlay.Attributes = append(overlay.Attributes, directory.Attribute{
			Description: "olcRwmRewrite",
			Values:      stringValues(rewrite...),
		})
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
			DN: "olcDatabase={0}config,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{0}config")},
				{Description: "olcRootDN", Values: stringValues("cn=config")},
				{Description: "olcRootPW", Values: stringValues("config-secret")},
			},
		},
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcMdbConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			},
		},
		overlay,
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com", "cn=config"})
	}); err != nil {
		t.Fatalf("seed local RWM configuration: %v", err)
	}
}
