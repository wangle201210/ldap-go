package server

import (
	"net"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	defaultReferralTargetDN = "uid=outside,dc=remote,dc=example"
	defaultReferralURI      = "ldap://referral.example:1389"
)

func TestLDAPMissingGlobalReferralDoesNotEmitEmptyReferral(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()

	_, err := client.Search(ldap.NewSearchRequest(
		defaultReferralTargetDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
	_, err = client.Compare(defaultReferralTargetDN, "cn", "outside")
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
}

func TestLDAPGlobalDefaultReferralCoreOperations(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	putDefaultReferralConfigGlobalEntry(t, store, []string{defaultReferralURI})
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	client := bindPagedRootClient(t, address)
	defer client.Close()
	rootDSE, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"ref"},
		nil,
	))
	if err != nil || len(rootDSE.Entries) != 1 ||
		rootDSE.Entries[0].GetAttributeValue("ref") != defaultReferralURI {
		t.Fatalf("Root DSE default referral = %#v, %v", rootDSE, err)
	}

	for _, search := range []struct {
		name  string
		base  string
		scope int
		want  string
	}{
		{"base", defaultReferralTargetDN, ldap.ScopeBaseObject, defaultReferralURI + "/" + defaultReferralTargetDN + "??base"},
		{"one", defaultReferralTargetDN, ldap.ScopeSingleLevel, defaultReferralURI + "/" + defaultReferralTargetDN + "??one"},
		{"subtree", defaultReferralTargetDN, ldap.ScopeWholeSubtree, defaultReferralURI + "/" + defaultReferralTargetDN + "??sub"},
		{"children", defaultReferralTargetDN, ldap.ScopeChildren, defaultReferralURI + "/" + defaultReferralTargetDN + "??subordinate"},
		{"empty one", "", ldap.ScopeSingleLevel, defaultReferralURI + "/??one"},
	} {
		t.Run(search.name, func(t *testing.T) {
			_, err := client.Search(ldap.NewSearchRequest(
				search.base,
				search.scope,
				ldap.NeverDerefAliases,
				0,
				0,
				false,
				"(objectClass=*)",
				[]string{"dn"},
				nil,
			))
			assertLDAPReferral(t, err, "", search.want)
		})
	}

	want := defaultReferralURI + "/" + defaultReferralTargetDN
	_, err = client.Compare(defaultReferralTargetDN, "cn", "outside")
	assertLDAPReferral(t, err, "", want)
	add := ldap.NewAddRequest(defaultReferralTargetDN, nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"outside"})
	add.Attribute("cn", []string{"Outside"})
	add.Attribute("sn", []string{"Outside"})
	assertLDAPReferral(t, client.Add(add), "", want)
	modify := ldap.NewModifyRequest(defaultReferralTargetDN, nil)
	modify.Replace("cn", []string{"Changed"})
	assertLDAPReferral(t, client.Modify(modify), "", want)
	assertLDAPReferral(t, client.Del(ldap.NewDelRequest(defaultReferralTargetDN, nil)), "", want)
	rename := ldap.NewModifyDNRequest(defaultReferralTargetDN, "uid=renamed", true, "")
	assertLDAPReferral(t, client.ModifyDN(rename), "", want)
}

func TestLDAPGlobalDefaultReferralWhenBackendHasNoMatchedAncestor(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		for _, entry := range []directory.Entry{
			{
				DN: "cn=config",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcGlobal")},
					{Description: "cn", Values: stringValues("config")},
					{Description: "olcReferral", Values: stringValues(defaultReferralURI)},
				},
			},
			{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{1}mdb")},
					{Description: "olcSuffix", Values: stringValues("dc=orphan,dc=example")},
				},
			},
		} {
			if err := writer.PutIn(storage.OpenLDAPConfigPartition, entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=orphan,dc=example"})
	}); err != nil {
		t.Fatalf("seed orphan backend: %v", err)
	}
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=orphan,dc=example",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=orphan,dc=example", "admin-secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}
	target := "uid=missing,dc=orphan,dc=example"
	want := defaultReferralURI + "/" + target

	_, err = client.Search(ldap.NewSearchRequest(
		target,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	))
	assertLDAPReferral(t, err, "", want+"??base")
	_, err = client.Compare(target, "cn", "missing")
	assertLDAPReferral(t, err, "", want)
	modify := ldap.NewModifyRequest(target, nil)
	modify.Replace("cn", []string{"Missing"})
	assertLDAPReferral(t, client.Modify(modify), "", want)
	assertLDAPReferral(t, client.Del(ldap.NewDelRequest(target, nil)), "", want)
	assertLDAPReferral(
		t,
		client.ModifyDN(ldap.NewModifyDNRequest(target, "uid=renamed", true, "")),
		"",
		want,
	)
}

func TestLDAPGlobalDefaultReferralChainsThroughFrontend(t *testing.T) {
	t.Parallel()

	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedDirectory(t, providerStore)
	seedChainProviderEntries(t, providerStore)
	if err := providerStore.Update(t.Context(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccess", stringValues("{0}to * by * read"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("allow provider reads: %v", err)
	}
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       chainTestRootDN,
		RootPassword: []byte(chainTestRootPassword),
	})
	defer stopProvider()

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	overlayDN := "olcOverlay={0}chain,olcDatabase={-1}frontend,cn=config"
	if err := consumerStore.Update(t.Context(), func(writer storage.Writer) error {
		entries := []directory.Entry{
			{
				DN: "cn=config",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcGlobal")},
					{Description: "cn", Values: stringValues("config")},
					{Description: "olcReferral", Values: stringValues("ldap://" + providerAddress)},
				},
			},
			{
				DN: "olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
				},
			},
			{
				DN: overlayDN,
				Attributes: []directory.Attribute{
					{Description: "olcOverlay", Values: stringValues("{0}chain")},
					{Description: "olcChainReturnError", Values: stringValues("TRUE")},
				},
			},
			{
				DN: "olcDatabase={0}ldap," + overlayDN,
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{0}ldap")},
					{Description: "olcDbURI", Values: stringValues("ldap://" + providerAddress)},
					{Description: "olcDbIDAssertBind", Values: stringValues(
						`bindmethod=simple binddn="` + chainTestRootDN +
							`" credentials="` + chainTestRootPassword + `" mode=anonymous`,
					)},
					{Description: "olcDbIDAssertAuthzFrom", Values: stringValues("*")},
				},
			},
			{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{1}mdb")},
					{Description: "olcSuffix", Values: stringValues("dc=local,dc=example")},
				},
			},
		}
		for _, entry := range entries {
			if err := writer.PutIn(storage.OpenLDAPConfigPartition, entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=local,dc=example"})
	}); err != nil {
		t.Fatalf("seed global referral chain: %v", err)
	}
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{})
	defer stopConsumer()
	client, err := ldap.DialURL("ldap://" + consumerAddress)
	if err != nil {
		t.Fatalf("DialURL(consumer): %v", err)
	}
	defer client.Close()
	target := "uid=remote," + chainTestReferralDN
	result, err := client.Search(ldap.NewSearchRequest(
		target,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=inetOrgPerson)",
		[]string{"uid"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("uid") != "remote" {
		t.Fatalf("chained global referral Search = %#v, %v", result, err)
	}
}

func TestLDAPGlobalDefaultReferralStartTLSDemotesIdentity(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	putDefaultReferralConfigGlobalEntry(t, store, []string{defaultReferralURI})
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer connection.Close()
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawExtendedRequest(startTLSOID, nil, false),
		nil,
	)
	response := readRawLDAPPacket(t, connection)
	assertRawLDAPEnvelope(
		t,
		response,
		2,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultReferral),
	)
	referrals := ldapResultReferrals(response)
	if len(referrals) != 1 || referrals[0] != defaultReferralURI {
		t.Fatalf("StartTLS referrals = %q", referrals)
	}

	writeRawLDAPRequest(
		t,
		connection,
		3,
		rawExtendedRequest(whoAmIOID, nil, false),
		nil,
	)
	whoAmI := readRawLDAPPacket(t, connection)
	assertRawLDAPEnvelope(
		t,
		whoAmI,
		3,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultSuccess),
	)
	if value, present := rawExtendedResponseValue(whoAmI); present && len(value) != 0 {
		t.Fatalf("Who Am I after referred StartTLS = %q", value)
	}
}

func TestLDAPGlobalDefaultReferralRejectsTransactionalUpdateBeforeQueueing(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	putDefaultReferralConfigGlobalEntry(t, store, []string{defaultReferralURI})
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer connection.Close()
	identifier := startRawLDAPTransaction(t, connection, 2)
	response := sendRawLDAPOperation(
		t,
		connection,
		3,
		rawAddRequest(directory.Entry{
			DN: defaultReferralTargetDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("outside")},
				{Description: "cn", Values: stringValues("Outside")},
				{Description: "sn", Values: stringValues("Outside")},
			},
		}),
		rawTransactionSpecificationControl(identifier, true, true),
	)
	assertRawLDAPEnvelope(
		t,
		response,
		3,
		ldapwire.ApplicationAddResponse,
		int64(ldap.LDAPResultReferral),
	)
	want := defaultReferralURI + "/" + defaultReferralTargetDN
	if referrals := ldapResultReferrals(response); len(referrals) != 1 || referrals[0] != want {
		t.Fatalf("transactional update referrals = %q, want %q", referrals, want)
	}
	end := endRawLDAPTransaction(t, connection, 4, false, identifier)
	assertRawLDAPResult(t, end, int64(ldap.LDAPResultSuccess))
}

func TestLDAPGlobalDefaultReferralOnlineConfigurationUsesExistingConnection(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial(existing connection): %v", err)
	}
	defer connection.Close()
	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}
	modify := ldap.NewModifyRequest("cn=config", nil)
	modify.Replace("olcReferral", []string{defaultReferralURI})
	if err := configClient.Modify(modify); err != nil {
		t.Fatalf("set olcReferral: %v", err)
	}

	writeRawLDAPRequest(
		t,
		connection,
		1,
		rawSyncSearchRequestFor(
			t,
			defaultReferralTargetDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			"(objectClass=*)",
		),
		nil,
	)
	response := readRawLDAPPacket(t, connection)
	assertRawLDAPEnvelope(
		t,
		response,
		1,
		ldapwire.ApplicationSearchResultDone,
		int64(ldap.LDAPResultReferral),
	)
	want := defaultReferralURI + "/" + defaultReferralTargetDN + "??base"
	if referrals := ldapResultReferrals(response); len(referrals) != 1 || referrals[0] != want {
		t.Fatalf("online default referrals = %q, want %q", referrals, want)
	}
}

func TestLDAPGlobalDefaultReferralOnlineConstraintsAndRollback(t *testing.T) {
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
		t.Fatalf("Bind(cn=config): %v", err)
	}

	add := ldap.NewModifyRequest("cn=config", nil)
	add.Add("olcReferral", []string{defaultReferralURI})
	if err := configClient.Modify(add); err != nil {
		t.Fatalf("Add(olcReferral): %v", err)
	}
	duplicate := ldap.NewModifyRequest("cn=config", nil)
	duplicate.Add("olcReferral", []string{defaultReferralURI})
	assertLDAPResultCode(
		t,
		configClient.Modify(duplicate),
		ldap.LDAPResultAttributeOrValueExists,
	)
	second := ldap.NewModifyRequest("cn=config", nil)
	second.Add("olcReferral", []string{"ldap://second.example"})
	assertLDAPResultCode(t, configClient.Modify(second), ldap.LDAPResultConstraintViolation)
	multiple := ldap.NewModifyRequest("cn=config", nil)
	multiple.Replace("olcReferral", []string{
		defaultReferralURI,
		"ldap://second.example",
	})
	assertLDAPResultCode(t, configClient.Modify(multiple), ldap.LDAPResultConstraintViolation)
	invalid := ldap.NewModifyRequest("cn=config", nil)
	invalid.Replace("olcReferral", []string{"ldap://bad.example/dc=forbidden"})
	assertLDAPResultCode(t, configClient.Modify(invalid), ldap.LDAPResultOther)

	dataClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(data): %v", err)
	}
	defer dataClient.Close()
	_, err = dataClient.Search(ldap.NewSearchRequest(
		defaultReferralTargetDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	))
	assertLDAPReferral(
		t,
		err,
		"",
		defaultReferralURI+"/"+defaultReferralTargetDN+"??base",
	)

	remove := ldap.NewModifyRequest("cn=config", nil)
	remove.Delete("olcReferral", nil)
	if err := configClient.Modify(remove); err != nil {
		t.Fatalf("Delete(olcReferral): %v", err)
	}
	_, err = dataClient.Search(ldap.NewSearchRequest(
		defaultReferralTargetDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
}
