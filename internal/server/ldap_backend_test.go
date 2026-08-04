package server

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	ldapBackendTestSuffix       = "dc=proxy,dc=test"
	ldapBackendTestPeopleDN     = "ou=people," + ldapBackendTestSuffix
	ldapBackendTestUserDN       = "uid=alice," + ldapBackendTestPeopleDN
	ldapBackendTestAdminDN      = "cn=admin," + ldapBackendTestSuffix
	ldapBackendTestLocalRootDN  = "cn=proxy-root," + ldapBackendTestSuffix
	ldapBackendTestUserPassword = "proxy-secret"
	ldapBackendTestAdminSecret  = "proxy-admin-secret"
	ldapBackendTestLocalRootPW  = "local-root-secret"
	ldapBackendTestDatabaseDN   = "olcDatabase={1}ldap,cn=config"
)

func TestLoadLDAPBackendRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	configuration, err := loadLDAPBackendRuntimeConfiguration(directory.Entry{
		DN: ldapBackendTestDatabaseDN,
		Attributes: []directory.Attribute{
			{
				Description: "olcDbURI",
				Values: stringValues(
					"ldap://127.0.0.1:1389, ldap://127.0.0.1:2389",
				),
			},
			{Description: "olcDbStartTLS", Values: stringValues("try-start")},
			{Description: "olcDbNetworkTimeout", Values: stringValues("2s")},
			{Description: "olcDbProtocolVersion", Values: stringValues("3")},
			{Description: "olcDbRebindAsUser", Values: stringValues("TRUE")},
			{Description: "olcDbChaseReferrals", Values: stringValues("FALSE")},
			{Description: "olcDbProxyWhoAmI", Values: stringValues("TRUE")},
			{Description: "olcDbTimeout", Values: stringValues("bind=1 search=3")},
			{Description: "olcDbSingleConn", Values: stringValues("TRUE")},
			{Description: "olcDbConnectionPoolMax", Values: stringValues("8")},
			{
				Description: "olcDbIDAssertBind",
				Values: stringValues(
					`bindmethod=simple binddn="` + ldapBackendTestAdminDN +
						`" credentials="` + ldapBackendTestAdminSecret + `" mode=none`,
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("loadLDAPBackendRuntimeConfiguration(): %v", err)
	}
	if len(configuration.remotes) != 2 ||
		configuration.remotes[0].uri != "ldap://127.0.0.1:1389" ||
		configuration.remotes[1].uri != "ldap://127.0.0.1:2389" {
		t.Fatalf("ldap backend remotes = %#v", configuration.remotes)
	}
	remote := configuration.remotes[0]
	if remote.uri != "ldap://127.0.0.1:1389" ||
		remote.bind.startTLS != syncConsumerStartTLSYes ||
		remote.bind.networkTimeout != 2*time.Second ||
		remote.protocolVersion != 3 || !remote.rebindAsUser ||
		remote.chaseReferrals || !remote.proxyWhoAmI ||
		remote.operationTimeouts[3] != 3*time.Second ||
		!remote.singleConnection || remote.connectionPoolMax != 8 ||
		!remote.identity.configured || remote.bind.bindMethod != "simple" {
		t.Fatalf("ldap backend configuration = %#v", configuration)
	}
}

func TestLDAPBackendConfigurationValidation(t *testing.T) {
	t.Parallel()

	invalid := []struct {
		name       string
		attributes []directory.Attribute
	}{
		{name: "missing URI"},
		{
			name: "duplicate URI values",
			attributes: []directory.Attribute{{
				Description: "olcDbURI",
				Values:      stringValues("ldap://127.0.0.1", "ldap://127.0.0.2"),
			}},
		},
		{
			name: "URI search base",
			attributes: []directory.Attribute{{
				Description: "olcDbURI",
				Values:      stringValues("ldap://127.0.0.1/dc=example,dc=com"),
			}},
		},
		{
			name: "URI scheme",
			attributes: []directory.Attribute{{
				Description: "olcDbURI",
				Values:      stringValues("https://127.0.0.1"),
			}},
		},
		{
			name: "back-ldap option",
			attributes: []directory.Attribute{
				{Description: "olcDbURI", Values: stringValues("ldap://127.0.0.1")},
				{Description: "olcDbConnectionPoolMax", Values: stringValues("0")},
			},
		},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			entry := directory.Entry{
				DN: ldapBackendTestDatabaseDN,
				Attributes: append([]directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{1}ldap")},
					{Description: "olcSuffix", Values: stringValues(ldapBackendTestSuffix)},
				}, test.attributes...),
			}
			if _, err := loadLDAPBackendRuntimeConfiguration(entry); err == nil {
				t.Fatal("invalid ldap backend configuration was accepted")
			}

			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				return writer.Put(entry, false)
			}); err != nil {
				t.Fatalf("seed invalid ldap backend: %v", err)
			}
			if _, err := ValidateConfiguration(context.Background(), Config{Store: store}); err == nil {
				t.Fatal("ValidateConfiguration accepted invalid ldap backend")
			}
			if _, err := New(Config{Store: store}); err == nil {
				t.Fatal("New accepted invalid ldap backend")
			}
		})
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range []directory.Entry{
			ldapBackendDatabaseEntry("{1}ldap", ldapBackendTestSuffix, "ldap://127.0.0.1"),
			ldapBackendDatabaseEntry("{2}ldap", ldapBackendTestSuffix, "ldap://127.0.0.2"),
		} {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed duplicate suffixes: %v", err)
	}
	if _, err := ValidateConfiguration(context.Background(), Config{Store: store}); err == nil ||
		!strings.Contains(err.Error(), "configured by both") {
		t.Fatalf("duplicate ldap backend suffix validation error = %v", err)
	}
}

func TestLDAPBackendRejectsDatabaseLocalACL(t *testing.T) {
	t.Parallel()

	entry := ldapBackendDatabaseEntry(
		"{1}ldap",
		ldapBackendTestSuffix,
		"ldap://127.0.0.1:1389",
	)
	entry.Attributes = append(entry.Attributes, directory.Attribute{
		Description: "olcAccess",
		Values:      stringValues("{0}to * by users read by * none"),
	})
	if _, err := loadLDAPBackendRuntimeConfiguration(entry); err == nil ||
		!strings.Contains(err.Error(), "database-local ACLs would be bypassed") {
		t.Fatalf("ldap backend olcAccess load error = %v", err)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed ldap backend with olcAccess: %v", err)
	}
	if _, err := ValidateConfiguration(context.Background(), Config{Store: store}); err == nil || !strings.Contains(err.Error(), "database-local ACLs would be bypassed") {
		t.Fatalf("ValidateConfiguration olcAccess error = %v", err)
	}
	if _, err := New(Config{Store: store}); err == nil ||
		!strings.Contains(err.Error(), "database-local ACLs would be bypassed") {
		t.Fatalf("New olcAccess error = %v", err)
	}
}

func TestLDAPBackendRejectsAttachedOverlays(t *testing.T) {
	t.Parallel()

	const overlayDN = "olcOverlay={0}sssvlv," + ldapBackendTestDatabaseDN
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range []directory.Entry{
			ldapBackendDatabaseEntry(
				"{1}ldap",
				ldapBackendTestSuffix,
				"ldap://127.0.0.1:1389",
			),
			{
				DN: overlayDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
					{Description: "olcOverlay", Values: stringValues("{0}sssvlv")},
				},
			},
		} {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed ldap backend with attached overlay: %v", err)
	}

	for name, validate := range map[string]func() error{
		"ValidateConfiguration": func() error {
			_, err := ValidateConfiguration(context.Background(), Config{Store: store})
			return err
		},
		"New": func() error {
			_, err := New(Config{Store: store})
			return err
		},
	} {
		err := validate()
		if err == nil || !strings.Contains(err.Error(), "local overlays would be bypassed") {
			t.Fatalf("%s attached-overlay error = %v", name, err)
		}
	}
}

func TestLDAPBackendRealTopologyIdentityAndOperations(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
	})
	defer stopProvider()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendProxy(t, proxyStore, providerAddress)
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()
	plainConnection, plainErr := dialAndBindSASLPlain(
		proxyAddress,
		"",
		"alice",
		ldapBackendTestUserPassword,
	)
	if plainConnection != nil {
		_ = plainConnection.Close()
	}
	assertLDAPResultCode(t, plainErr, ldap.LDAPResultConfidentialityRequired)

	client := dialLDAPBackendClient(t, proxyAddress)
	defer client.Close()
	assertLDAPResultCode(
		t,
		client.UnauthenticatedBind(ldapBackendTestUserDN),
		ldap.LDAPResultUnwillingToPerform,
	)
	assertLDAPResultCode(
		t,
		client.Bind(ldapBackendTestUserDN, "wrong-password"),
		ldap.LDAPResultInvalidCredentials,
	)
	if err := client.Bind(ldapBackendTestUserDN, ldapBackendTestUserPassword); err != nil {
		t.Fatalf("Bind(proxy user): %v", err)
	}
	directAuthorization := bindLDAPBackendUser(
		t,
		providerAddress,
		ldapBackendTestUserPassword,
	)
	assertProxyAuthorizationIdentity(
		t,
		directAuthorization,
		"uid=bob,"+ldapBackendTestPeopleDN,
	)
	directAuthorization.Close()
	assertProxyAuthorizationDenied(
		t,
		client,
		"uid=bob,"+ldapBackendTestPeopleDN,
	)
	identity, err := client.WhoAmI(nil)
	if err != nil || identity.AuthzID != "dn:"+ldapBackendTestUserDN {
		t.Fatalf("WhoAmI(proxy) = %#v, %v", identity, err)
	}
	localRoot := dialLDAPBackendClient(t, proxyAddress)
	defer localRoot.Close()
	if err := localRoot.Bind(
		ldapBackendTestLocalRootDN,
		ldapBackendTestLocalRootPW,
	); err != nil {
		t.Fatalf("Bind(local proxy root): %v", err)
	}
	assertProxyAuthorizationIdentity(t, localRoot, ldapBackendTestUserDN)
	rootIdentity, err := localRoot.WhoAmI(nil)
	if err != nil || rootIdentity.AuthzID != "dn:"+ldapBackendTestLocalRootDN {
		t.Fatalf("WhoAmI(local proxy root) = %#v, %v", rootIdentity, err)
	}

	search, err := client.Search(ldap.NewSearchRequest(
		ldapBackendTestUserDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=alice)",
		[]string{"uid", "cn"},
		nil,
	))
	if err != nil || len(search.Entries) != 1 ||
		search.Entries[0].GetAttributeValue("cn") != "Alice Proxy" {
		t.Fatalf("Search(proxy user) = %#v, %v", search, err)
	}
	matches, err := client.Compare(ldapBackendTestUserDN, "sn", "Proxy")
	if err != nil || !matches {
		t.Fatalf("Compare(proxy user) = %v, %v", matches, err)
	}

	createdDN := "uid=created," + ldapBackendTestPeopleDN
	add := ldap.NewAddRequest(createdDN, nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"created"})
	add.Attribute("cn", []string{"Created Through Proxy"})
	add.Attribute("sn", []string{"Proxy"})
	if err := client.Add(add); err != nil {
		t.Fatalf("Add(proxy): %v", err)
	}
	modify := ldap.NewModifyRequest(createdDN, nil)
	modify.Replace("cn", []string{"Modified Through Proxy"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify(proxy): %v", err)
	}
	if matches, err := client.Compare(createdDN, "cn", "Modified Through Proxy"); err != nil || !matches {
		t.Fatalf("Compare(modified proxy entry) = %v, %v", matches, err)
	}
	if err := client.ModifyDN(ldap.NewModifyDNRequest(
		createdDN,
		"uid=renamed",
		true,
		"",
	)); err != nil {
		t.Fatalf("ModifyDN(proxy): %v", err)
	}
	renamedDN := "uid=renamed," + ldapBackendTestPeopleDN

	leaseDN := "cn=lease," + ldapBackendTestPeopleDN
	if err := client.Add(newDynamicRoleAddRequest(leaseDN, "lease")); err != nil {
		t.Fatalf("Add(dynamicObject through proxy): %v", err)
	}
	admin := dialLDAPBackendClient(t, proxyAddress)
	defer admin.Close()
	if err := admin.Bind(ldapBackendTestAdminDN, ldapBackendTestAdminSecret); err != nil {
		t.Fatalf("Bind(proxy admin): %v", err)
	}
	if ttl, err := requestDynamicRefresh(admin, leaseDN, 45); err != nil || ttl != 45 {
		t.Fatalf("Dynamic Refresh(proxy) = %d, %v", ttl, err)
	}

	newPassword := "proxy-secret-updated"
	if _, err := client.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		ldapBackendTestUserPassword,
		newPassword,
	)); err != nil {
		t.Fatalf("PasswordModify(proxy): %v", err)
	}
	if _, err := client.Search(ldap.NewSearchRequest(
		ldapBackendTestUserDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	)); err != nil {
		t.Fatalf("Search after proxied password change: %v", err)
	}
	assertBindPassword(t, providerAddress, ldapBackendTestUserDN, ldapBackendTestUserPassword, false)
	assertBindPassword(t, providerAddress, ldapBackendTestUserDN, newPassword, true)

	for _, dn := range []string{renamedDN, leaseDN} {
		if err := client.Del(ldap.NewDelRequest(dn, nil)); err != nil {
			t.Fatalf("Delete(%s through proxy): %v", dn, err)
		}
	}
	if entryExists(t, proxyStore, renamedDN) || entryExists(t, proxyStore, leaseDN) {
		t.Fatal("proxied writes created entries in the proxy store")
	}
	assertEntryMissing(t, providerStore, renamedDN)
	assertEntryMissing(t, providerStore, leaseDN)
}

func TestLDAPBackendOrderedTransportFailover(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
	})
	defer stopProvider()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendProxyURI(
		t,
		proxyStore,
		"ldap://127.0.0.1:1, ldap://"+providerAddress,
	)
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	client := bindLDAPBackendUser(t, proxyAddress, ldapBackendTestUserPassword)
	defer client.Close()
	search, err := client.Search(ldap.NewSearchRequest(
		ldapBackendTestUserDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=alice)",
		[]string{"cn"},
		nil,
	))
	if err != nil || len(search.Entries) != 1 ||
		search.Entries[0].GetAttributeValue("cn") != "Alice Proxy" {
		t.Fatalf("Search after ordered failover = %#v, %v", search, err)
	}
}

func TestLDAPBackendAbandonAndCancelOutboundSearch(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	addLDAPBackendProviderDelayedSearch(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
	})
	defer stopProvider()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendProxy(t, proxyStore, providerAddress)
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	t.Run("Abandon", func(t *testing.T) {
		connection := dialAndBindRawLDAP(
			t,
			proxyAddress,
			ldapBackendTestUserDN,
			ldapBackendTestUserPassword,
		)
		defer connection.Close()
		writeRawLDAPRequest(
			t,
			connection,
			2,
			rawRetcodeSearchRequest(t, ldapBackendTestUserDN),
		)
		time.Sleep(100 * time.Millisecond)
		started := time.Now()
		writeRawLDAPRequest(t, connection, 3, rawAbandonRequest(2))
		writeRawLDAPRequest(
			t,
			connection,
			4,
			rawExtendedRequest(whoAmIOID, nil, false),
		)
		assertRawLDAPEnvelope(
			t,
			readRawLDAPPacket(t, connection),
			4,
			ldapwire.ApplicationExtendedResponse,
			int64(ldap.LDAPResultSuccess),
		)
		if elapsed := time.Since(started); elapsed >= time.Second {
			t.Fatalf("Abandon waited for provider response: %s", elapsed)
		}
	})

	t.Run("Cancel", func(t *testing.T) {
		connection := dialAndBindRawLDAP(
			t,
			proxyAddress,
			ldapBackendTestUserDN,
			ldapBackendTestUserPassword,
		)
		defer connection.Close()
		writeRawLDAPRequest(
			t,
			connection,
			2,
			rawRetcodeSearchRequest(t, ldapBackendTestUserDN),
		)
		time.Sleep(100 * time.Millisecond)
		started := time.Now()
		writeRawLDAPRequest(
			t,
			connection,
			3,
			rawExtendedRequest(
				cancelOID,
				ldapwire.EncodeCancelRequestValue(2),
				true,
			),
		)
		assertRawLDAPEnvelope(
			t,
			readRawLDAPPacket(t, connection),
			2,
			ldapwire.ApplicationSearchResultDone,
			int64(ldap.LDAPResultCanceled),
		)
		assertRawLDAPEnvelope(
			t,
			readRawLDAPPacket(t, connection),
			3,
			ldapwire.ApplicationExtendedResponse,
			int64(ldap.LDAPResultSuccess),
		)
		if elapsed := time.Since(started); elapsed >= time.Second {
			t.Fatalf("Cancel waited for provider response: %s", elapsed)
		}
	})
}

func TestLDAPBackendRealTopologyResponsesAvailabilityAndRollback(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	setLDAPBackendProviderReadOnlyACL(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
	})
	providerRunning := true
	t.Cleanup(func() {
		if providerRunning {
			stopProvider()
		}
	})

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendProxy(t, proxyStore, providerAddress)
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	client := bindLDAPBackendUser(t, proxyAddress, ldapBackendTestUserPassword)
	defer client.Close()
	paged, err := client.Search(ldap.NewSearchRequest(
		ldapBackendTestPeopleDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=inetOrgPerson)",
		[]string{"uid"},
		[]ldap.Control{ldap.NewControlPaging(1)},
	))
	if err != nil || len(paged.Entries) != 1 {
		t.Fatalf("paged Search(proxy) = %#v, %v", paged, err)
	}
	pagingControl, ok := ldap.FindControl(
		paged.Controls,
		pagedResultsControlOID,
	).(*ldap.ControlPaging)
	if !ok || len(pagingControl.Cookie) == 0 {
		t.Fatalf("paged response control = %#v", paged.Controls)
	}
	continuation := ldap.NewControlPaging(1)
	continuation.SetCookie(pagingControl.Cookie)
	_, continuationErr := client.Search(ldap.NewSearchRequest(
		ldapBackendTestPeopleDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=inetOrgPerson)",
		[]string{"uid"},
		[]ldap.Control{continuation},
	))
	assertLDAPResultCode(t, continuationErr, ldap.LDAPResultUnwillingToPerform)

	aclSearch, err := client.Search(ldap.NewSearchRequest(
		ldapBackendTestUserDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=alice)",
		[]string{"uid", "jpegPhoto"},
		nil,
	))
	if err != nil || len(aclSearch.Entries) != 1 ||
		aclSearch.Entries[0].GetAttributeValue("uid") != "alice" ||
		len(aclSearch.Entries[0].GetRawAttributeValue("jpegPhoto")) != 0 {
		t.Fatalf("provider attribute ACL through proxy = %#v, %v", aclSearch, err)
	}
	deniedDN := "uid=acl-denied," + ldapBackendTestPeopleDN
	deniedAdd := ldap.NewAddRequest(deniedDN, nil)
	deniedAdd.Attribute("objectClass", []string{"inetOrgPerson"})
	deniedAdd.Attribute("uid", []string{"acl-denied"})
	deniedAdd.Attribute("cn", []string{"ACL Denied"})
	deniedAdd.Attribute("sn", []string{"Denied"})
	assertLDAPResultCode(
		t,
		client.Add(deniedAdd),
		ldap.LDAPResultInsufficientAccessRights,
	)
	assertEntryMissing(t, providerStore, deniedDN)
	assertEntryMissing(t, proxyStore, deniedDN)

	_, transactionErr := client.Extended(ldap.NewExtendedRequest(
		transactionStartOID,
		nil,
	))
	assertLDAPResultCode(t, transactionErr, ldap.LDAPResultUnwillingToPerform)
	transactionDN := "uid=transaction-rejected," + ldapBackendTestPeopleDN
	transactionAdd := ldap.NewAddRequest(transactionDN, []ldap.Control{
		ldap.NewControlString(transactionSpecificationControlOID, true, ""),
	})
	transactionAdd.Attribute("objectClass", []string{"inetOrgPerson"})
	transactionAdd.Attribute("uid", []string{"transaction-rejected"})
	transactionAdd.Attribute("cn", []string{"Transaction Rejected"})
	transactionAdd.Attribute("sn", []string{"Rejected"})
	assertLDAPResultCode(
		t,
		client.Add(transactionAdd),
		ldap.LDAPResultUnwillingToPerform,
	)
	assertEntryMissing(t, providerStore, transactionDN)
	assertEntryMissing(t, proxyStore, transactionDN)

	direct := bindLDAPBackendUser(t, providerAddress, ldapBackendTestUserPassword)
	referralDN := "ou=referral," + ldapBackendTestSuffix
	directReferral := ldapBackendReferralObservation(t, direct, referralDN)
	proxyReferral := ldapBackendReferralObservation(t, client, referralDN)
	if !reflect.DeepEqual(proxyReferral, directReferral) {
		t.Fatalf("proxied referral = %#v, want provider %#v", proxyReferral, directReferral)
	}
	directMissing := ldapBackendMissingObservation(t, direct)
	direct.Close()
	proxyMissing := ldapBackendMissingObservation(t, client)
	if proxyMissing != directMissing {
		t.Fatalf("missing-base result = %#v, want provider %#v", proxyMissing, directMissing)
	}

	configClient := dialLDAPBackendClient(t, proxyAddress)
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}
	for _, values := range [][]string{
		{"https://invalid.example.test"},
		{"ldap://" + providerAddress, "ldap://127.0.0.1:1"},
	} {
		modify := ldap.NewModifyRequest(ldapBackendTestDatabaseDN, nil)
		modify.Replace("olcDbURI", values)
		assertLDAPResultCode(
			t,
			configClient.Modify(modify),
			ldap.LDAPResultConstraintViolation,
		)
	}
	localACL := ldap.NewModifyRequest(ldapBackendTestDatabaseDN, nil)
	localACL.Add("olcAccess", []string{"{0}to * by users read by * none"})
	assertLDAPResultCode(
		t,
		configClient.Modify(localACL),
		ldap.LDAPResultConstraintViolation,
	)
	if values := readStoredEntry(t, proxyStore, ldapBackendTestDatabaseDN).Values(
		"olcAccess",
	); len(values) != 0 {
		t.Fatalf("rejected ldap backend olcAccess persisted: %q", values)
	}
	const unsupportedOverlayDN = "olcOverlay={0}sssvlv," + ldapBackendTestDatabaseDN
	unsupportedOverlay := ldap.NewAddRequest(unsupportedOverlayDN, nil)
	unsupportedOverlay.Attribute("objectClass", []string{"olcOverlayConfig"})
	unsupportedOverlay.Attribute("olcOverlay", []string{"{0}sssvlv"})
	assertLDAPResultCode(
		t,
		configClient.Add(unsupportedOverlay),
		ldap.LDAPResultConstraintViolation,
	)
	assertEntryMissing(t, proxyStore, unsupportedOverlayDN)
	validFailoverURI := "ldap://127.0.0.1:1 ldap://" + providerAddress
	validFailover := ldap.NewModifyRequest(ldapBackendTestDatabaseDN, nil)
	validFailover.Replace("olcDbURI", []string{validFailoverURI})
	if err := configClient.Modify(validFailover); err != nil {
		t.Fatalf("online olcDbURI failover list: %v", err)
	}
	storedURI := readStoredEntry(t, proxyStore, ldapBackendTestDatabaseDN).Values("olcDbURI")
	if len(storedURI) != 1 || string(storedURI[0]) != validFailoverURI {
		t.Fatalf("olcDbURI after rollback = %q", storedURI)
	}
	if _, err := client.Search(ldap.NewSearchRequest(
		ldapBackendTestUserDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=alice)",
		[]string{"uid"},
		nil,
	)); err != nil {
		t.Fatalf("Search after online rollback: %v", err)
	}

	stopProvider()
	providerRunning = false
	downClient := dialLDAPBackendClient(t, proxyAddress)
	defer downClient.Close()
	bindErr := downClient.Bind(ldapBackendTestUserDN, ldapBackendTestUserPassword)
	assertLDAPResultCode(t, bindErr, ldap.LDAPResultUnavailable)
	var unavailable *ldap.Error
	if !errors.As(bindErr, &unavailable) ||
		unavailable.Err.Error() != ldapBackendUnavailableDiagnostic {
		t.Fatalf("provider-down Bind diagnostic = %v", bindErr)
	}
	_, searchErr := client.Search(ldap.NewSearchRequest(
		ldapBackendTestSuffix,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dc"},
		nil,
	))
	assertLDAPResultCode(t, searchErr, ldap.LDAPResultUnavailable)
}

func TestOpenLDAPReferenceLDAPBackend(t *testing.T) {
	tools := requireOpenLDAPLDAPBackendReferenceTools(t)

	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
	})
	providerRunning := true
	t.Cleanup(func() {
		if providerRunning {
			stopProvider()
		}
	})

	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		fmt.Sprintf(
			`access to * by * read

database ldap
suffix "%s"
rootdn "%s"
rootpw %s
uri ldap://%s
network-timeout 1
chase-referrals FALSE
proxy-whoami TRUE
idassert-bind bindmethod=simple binddn="%s" credentials="%s" mode=none`,
			ldapBackendTestSuffix,
			ldapBackendTestLocalRootDN,
			ldapBackendTestLocalRootPW,
			providerAddress,
			ldapBackendTestAdminDN,
			ldapBackendTestAdminSecret,
		),
		"",
	)
	defer stopOpenLDAP()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendProxy(t, proxyStore, providerAddress)
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	openLDAPResult := observeLDAPBackendReference(t, openLDAPURI)
	ldapGoResult := observeLDAPBackendReference(t, "ldap://"+proxyAddress)
	if ldapGoResult != openLDAPResult {
		t.Fatalf("ldap-go back-ldap = %#v, want OpenLDAP %#v", ldapGoResult, openLDAPResult)
	}

	stopProvider()
	providerRunning = false
	openLDAPDown := ldapBackendBindError(t, openLDAPURI, ldapBackendTestUserPassword)
	ldapGoDown := ldapBackendBindError(t, "ldap://"+proxyAddress, ldapBackendTestUserPassword)
	wantDown := ldapBackendMissingResult{
		code:       ldap.LDAPResultUnavailable,
		diagnostic: ldapBackendUnavailableDiagnostic,
	}
	if openLDAPDown != wantDown || ldapGoDown != openLDAPDown {
		t.Fatalf("provider-down: ldap-go=%#v OpenLDAP=%#v", ldapGoDown, openLDAPDown)
	}
}

type ldapBackendMissingResult struct {
	code       uint16
	matchedDN  string
	diagnostic string
}

type ldapBackendReferralResult struct {
	code      uint16
	matchedDN string
	referrals string
}

func ldapBackendReferralObservation(
	t *testing.T,
	client *ldap.Conn,
	dn string,
) ldapBackendReferralResult {
	t.Helper()
	_, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"*"},
		nil,
	))
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		t.Fatalf("referral Search error = %v", err)
	}
	return ldapBackendReferralResult{
		code:      ldapError.ResultCode,
		matchedDN: ldapError.MatchedDN,
		referrals: strings.Join(ldapResultReferrals(ldapError.Packet), "\n"),
	}
}

func ldapBackendMissingObservation(
	t *testing.T,
	client *ldap.Conn,
) ldapBackendMissingResult {
	t.Helper()
	_, err := client.Search(ldap.NewSearchRequest(
		"uid=missing,"+ldapBackendTestPeopleDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	))
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		t.Fatalf("missing-base Search error = %v", err)
	}
	return ldapBackendMissingResult{
		code:       ldapError.ResultCode,
		matchedDN:  ldapError.MatchedDN,
		diagnostic: ldapError.Err.Error(),
	}
}

func seedLDAPBackendProvider(t *testing.T, store storage.Store) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcAuthzPolicy", Values: stringValues("to")},
			},
		},
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues(ldapBackendTestSuffix)},
				{
					Description: "olcAccess",
					Values: stringValues(
						"{0}to attrs=userPassword by self write by anonymous auth by * none",
						"{1}to * by users write by * read",
					),
				},
			},
		},
		{
			DN: "olcOverlay={0}dds,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("{0}dds")},
			},
		},
		{
			DN: ldapBackendTestSuffix,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("domain")},
				{Description: "dc", Values: stringValues("proxy")},
			},
		},
		{
			DN: ldapBackendTestPeopleDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit")},
				{Description: "ou", Values: stringValues("people")},
			},
		},
		{
			DN: ldapBackendTestUserDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("alice")},
				{Description: "cn", Values: stringValues("Alice Proxy")},
				{Description: "sn", Values: stringValues("Proxy")},
				{Description: "jpegPhoto", Values: [][]byte{{0x01, 0x02, 0x03}}},
				{Description: "userPassword", Values: stringValues(ldapBackendTestUserPassword)},
				{
					Description: "authzTo",
					Values: stringValues(
						"dn:uid=bob," + ldapBackendTestPeopleDN,
					),
				},
			},
		},
		{
			DN: "uid=bob," + ldapBackendTestPeopleDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("bob")},
				{Description: "cn", Values: stringValues("Bob Proxy")},
				{Description: "sn", Values: stringValues("Proxy")},
			},
		},
		{
			DN: "ou=referral," + ldapBackendTestSuffix,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("referral", "extensibleObject")},
				{Description: "ou", Values: stringValues("referral")},
				{Description: "ref", Values: stringValues("ldap://127.0.0.1:9/dc=elsewhere,dc=test")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{ldapBackendTestSuffix})
	}); err != nil {
		t.Fatalf("seed ldap backend provider: %v", err)
	}
}

func setLDAPBackendProviderReadOnlyACL(t *testing.T, store storage.Store) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccess", stringValues(
			"{0}to attrs=userPassword by self write by anonymous auth by * none",
			"{1}to attrs=jpegPhoto by * none",
			"{2}to * by users read by * read",
		))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("set provider ACL: %v", err)
	}
}

func addLDAPBackendProviderDelayedSearch(t *testing.T, store storage.Store) {
	t.Helper()
	entry := directory.Entry{
		DN: "olcOverlay={1}retcode,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcOverlay", Values: stringValues("{1}retcode")},
			{Description: "olcRetcodeParent", Values: stringValues(ldapBackendTestPeopleDN)},
			{
				Description: "olcRetcodeItem",
				Values: stringValues(
					`{0}"uid=alice" "0" "op=search" "sleeptime=2"`,
				),
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("add delayed provider Search: %v", err)
	}
}

func seedLDAPBackendProxy(
	t *testing.T,
	store storage.Store,
	providerAddress string,
) {
	t.Helper()
	seedLDAPBackendProxyURI(t, store, "ldap://"+providerAddress)
}

func seedLDAPBackendProxyURI(
	t *testing.T,
	store storage.Store,
	uri string,
) {
	t.Helper()
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
				{Description: "olcAccess", Values: stringValues("{0}to * by * none")},
			},
		},
		ldapBackendDatabaseEntry(
			"{1}ldap",
			ldapBackendTestSuffix,
			uri,
		),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{ldapBackendTestSuffix, "cn=config"})
	}); err != nil {
		t.Fatalf("seed ldap backend proxy: %v", err)
	}
}

func ldapBackendDatabaseEntry(name, suffix, uri string) directory.Entry {
	return directory.Entry{
		DN: "olcDatabase=" + name + ",cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
			{Description: "olcDatabase", Values: stringValues(name)},
			{Description: "olcSuffix", Values: stringValues(suffix)},
			{Description: "olcRootDN", Values: stringValues(ldapBackendTestLocalRootDN)},
			{Description: "olcRootPW", Values: stringValues(ldapBackendTestLocalRootPW)},
			{Description: "olcDbURI", Values: stringValues(uri)},
			{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
			{Description: "olcDbChaseReferrals", Values: stringValues("FALSE")},
			{Description: "olcDbProxyWhoAmI", Values: stringValues("TRUE")},
			{
				Description: "olcDbIDAssertBind",
				Values: stringValues(
					`bindmethod=simple binddn="` + ldapBackendTestAdminDN +
						`" credentials="` + ldapBackendTestAdminSecret + `" mode=none`,
				),
			},
		},
	}
}

func dialLDAPBackendClient(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", address, err)
	}
	client.SetTimeout(3 * time.Second)
	return client
}

func bindLDAPBackendUser(t *testing.T, address, password string) *ldap.Conn {
	t.Helper()
	client := dialLDAPBackendClient(t, address)
	if err := client.Bind(ldapBackendTestUserDN, password); err != nil {
		client.Close()
		t.Fatalf("Bind(%s): %v", address, err)
	}
	return client
}

func requireOpenLDAPLDAPBackendReferenceTools(
	t *testing.T,
) openLDAPReferenceTools {
	t.Helper()
	tools := requireOpenLDAPReferenceTools(t)
	output, err := exec.Command(tools.slapd, "-VVV").CombinedOutput()
	if err != nil && len(output) == 0 {
		t.Skipf("inspect OpenLDAP backends: %v", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.EqualFold(strings.TrimSpace(line), "ldap") {
			return tools
		}
	}
	t.Skip("the selected OpenLDAP slapd was not built with the ldap backend")
	return openLDAPReferenceTools{}
}

type ldapBackendReferenceResult struct {
	correctPassword uint16
	wrongPassword   uint16
	whoAmI          string
	searchDN        string
	compare         bool
	rootWhoAmI      string
	rootSearch      bool
}

func observeLDAPBackendReference(
	t *testing.T,
	uri string,
) ldapBackendReferenceResult {
	t.Helper()
	result := ldapBackendReferenceResult{
		wrongPassword: ldapBackendBindCode(t, uri, "wrong-password"),
	}
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	client.SetTimeout(3 * time.Second)
	defer client.Close()
	bindErr := client.Bind(ldapBackendTestUserDN, ldapBackendTestUserPassword)
	result.correctPassword = ldapBackendResultCode(bindErr)
	if bindErr != nil {
		return result
	}
	identity, err := client.WhoAmI(nil)
	if err == nil {
		result.whoAmI = identity.AuthzID
	}
	search, err := client.Search(ldap.NewSearchRequest(
		ldapBackendTestUserDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=alice)",
		[]string{"uid"},
		nil,
	))
	if err == nil && len(search.Entries) == 1 {
		result.searchDN = search.Entries[0].DN
	}
	result.compare, _ = client.Compare(ldapBackendTestUserDN, "sn", "Proxy")
	root, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(root, %s): %v", uri, err)
	}
	root.SetTimeout(3 * time.Second)
	defer root.Close()
	if err := root.Bind(ldapBackendTestLocalRootDN, ldapBackendTestLocalRootPW); err == nil {
		if identity, whoErr := root.WhoAmI(nil); whoErr == nil {
			result.rootWhoAmI = identity.AuthzID
		}
		rootSearch, searchErr := root.Search(ldap.NewSearchRequest(
			ldapBackendTestUserDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(uid=alice)",
			[]string{"uid"},
			nil,
		))
		result.rootSearch = searchErr == nil && len(rootSearch.Entries) == 1
	}
	return result
}

func ldapBackendBindCode(t *testing.T, uri, password string) uint16 {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	client.SetTimeout(3 * time.Second)
	defer client.Close()
	return ldapBackendResultCode(client.Bind(ldapBackendTestUserDN, password))
}

func ldapBackendBindError(
	t *testing.T,
	uri,
	password string,
) ldapBackendMissingResult {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	client.SetTimeout(3 * time.Second)
	defer client.Close()
	err = client.Bind(ldapBackendTestUserDN, password)
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		t.Fatalf("Bind(%s) error = %v", uri, err)
	}
	return ldapBackendMissingResult{
		code:       ldapError.ResultCode,
		matchedDN:  ldapError.MatchedDN,
		diagnostic: ldapError.Err.Error(),
	}
}

func ldapBackendResultCode(err error) uint16 {
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var ldapError *ldap.Error
	if errors.As(err, &ldapError) {
		return ldapError.ResultCode
	}
	return ldap.ErrorNetwork
}
