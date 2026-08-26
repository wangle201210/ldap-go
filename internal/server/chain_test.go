package server

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	chainTestRootDN       = "cn=admin,dc=example,dc=com"
	chainTestRootPassword = "chain-admin-secret"
	chainTestReferralDN   = "ou=remote,dc=example,dc=com"
)

func TestLDAPClientChainsReferralOperations(t *testing.T) {
	t.Parallel()

	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedDirectory(t, providerStore)
	seedChainProviderEntries(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       chainTestRootDN,
		RootPassword: []byte(chainTestRootPassword),
	})
	defer stopProvider()

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedDirectory(t, consumerStore)
	seedChainConsumerConfiguration(t, consumerStore, providerAddress)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
		RootDN:       chainTestRootDN,
		RootPassword: []byte(chainTestRootPassword),
	})
	defer stopConsumer()

	client, err := ldap.DialURL("ldap://" + consumerAddress)
	if err != nil {
		t.Fatalf("DialURL(consumer): %v", err)
	}
	defer client.Close()
	if err := client.Bind(chainTestRootDN, chainTestRootPassword); err != nil {
		t.Fatalf("Bind(consumer root): %v", err)
	}

	result, err := client.Search(ldap.NewSearchRequest(
		"uid=remote,"+chainTestReferralDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=inetOrgPerson)(uid=remote))",
		[]string{"uid", "cn", "entryDN"},
		nil,
	))
	if err != nil {
		t.Fatalf("chained Search(descendant): %v", err)
	}
	if len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("uid") != "remote" ||
		result.Entries[0].GetAttributeValue("entryDN") != "" {
		t.Fatalf("chained Search(descendant) entries = %#v", result.Entries)
	}

	result, err = client.Search(ldap.NewSearchRequest(
		chainTestReferralDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=organizationalUnit)",
		[]string{"ou"},
		nil,
	))
	if err != nil {
		t.Fatalf("chained Search(referral base): %v", err)
	}
	if len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("ou") != "remote" {
		t.Fatalf("chained Search(referral base) entries = %#v", result.Entries)
	}

	result, err = client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=remote)",
		[]string{"uid"},
		nil,
	))
	if err != nil {
		t.Fatalf("chained Search(subtree continuation): %v", err)
	}
	if len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("uid") != "remote" ||
		len(result.Referrals) != 0 {
		t.Fatalf("chained Search(subtree continuation) = %#v", result)
	}

	result, err = client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(ou=remote)",
		[]string{"ou"},
		nil,
	))
	if err != nil {
		t.Fatalf("chained Search(one-level continuation): %v", err)
	}
	if len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("ou") != "remote" ||
		len(result.Referrals) != 0 {
		t.Fatalf("chained Search(one-level continuation) = %#v", result)
	}

	matches, err := client.Compare(
		"uid=remote,"+chainTestReferralDN,
		"sn",
		"User",
	)
	if err != nil || !matches {
		t.Fatalf("chained Compare() = %v, %v", matches, err)
	}

	newDN := "uid=chained," + chainTestReferralDN
	add := ldap.NewAddRequest(newDN, nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"chained"})
	add.Attribute("cn", []string{"Chained User"})
	add.Attribute("sn", []string{"User"})
	add.Attribute("userPassword", []string{"initial-secret"})
	if err := client.Add(add); err != nil {
		t.Fatalf("chained Add(): %v", err)
	}

	modify := ldap.NewModifyRequest(newDN, nil)
	modify.Replace("cn", []string{"Updated Through Chain"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("chained Modify(): %v", err)
	}
	if got := readStoredEntry(t, providerStore, newDN).Values("cn"); len(got) != 1 || string(got[0]) != "Updated Through Chain" {
		t.Fatalf("provider cn after Modify = %q", got)
	}

	rename := ldap.NewModifyDNRequest(newDN, "uid=renamed", true, "")
	if err := client.ModifyDN(rename); err != nil {
		t.Fatalf("chained ModifyDN(): %v", err)
	}
	renamedDN := "uid=renamed," + chainTestReferralDN
	if got := readStoredEntry(t, providerStore, renamedDN).Values("uid"); len(got) != 1 || string(got[0]) != "renamed" {
		t.Fatalf("provider uid after ModifyDN = %q", got)
	}

	if _, err := client.PasswordModify(ldap.NewPasswordModifyRequest(
		renamedDN,
		"",
		"updated-secret",
	)); err != nil {
		t.Fatalf("chained PasswordModify(): %v", err)
	}
	assertBindPassword(t, providerAddress, renamedDN, "updated-secret", true)

	if err := client.Del(ldap.NewDelRequest(renamedDN, nil)); err != nil {
		t.Fatalf("chained Delete(): %v", err)
	}
	assertEntryMissing(t, providerStore, renamedDN)
}

func TestLDAPClientChainingBehaviorControl(t *testing.T) {
	t.Parallel()

	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedDirectory(t, providerStore)
	seedChainProviderEntries(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       chainTestRootDN,
		RootPassword: []byte(chainTestRootPassword),
	})

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedDirectory(t, consumerStore)
	seedChainConsumerConfiguration(t, consumerStore, providerAddress)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
		RootDN:       chainTestRootDN,
		RootPassword: []byte(chainTestRootPassword),
	})
	defer stopConsumer()

	client, err := ldap.DialURL("ldap://" + consumerAddress)
	if err != nil {
		stopProvider()
		t.Fatalf("DialURL(consumer): %v", err)
	}
	defer client.Close()
	if err := client.Bind(chainTestRootDN, chainTestRootPassword); err != nil {
		stopProvider()
		t.Fatalf("Bind(consumer root): %v", err)
	}

	request := func(control ldap.Control) *ldap.SearchRequest {
		return ldap.NewSearchRequest(
			"uid=remote,"+chainTestReferralDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(uid=remote)",
			[]string{"uid"},
			[]ldap.Control{control},
		)
	}
	referralsRequired := ldapChainingBehaviorControl(
		t,
		chainBehaviorReferralsRequired,
		chainBehaviorReferralsRequired,
	)
	_, err = client.Search(request(referralsRequired))
	assertLDAPResultCode(t, err, ldap.LDAPResultReferral)

	chainingRequired := ldapChainingBehaviorControl(
		t,
		chainBehaviorChainingRequired,
		chainBehaviorChainingRequired,
	)
	result, err := client.Search(request(chainingRequired))
	if err != nil || len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("uid") != "remote" {
		stopProvider()
		t.Fatalf("required chained search = %#v, %v", result, err)
	}

	stopProvider()
	_, err = client.Search(request(chainingRequired))
	assertLDAPResultCode(t, err, uint16(chainCannotChainResultCode))
}

func TestChainingBehaviorControlValidation(t *testing.T) {
	t.Parallel()

	valid, err := parseConfiguredChainingBehavior(
		"resolve=chainingPreferred continuation=referralsRequired",
	)
	if err != nil {
		t.Fatalf("parse valid control: %v", err)
	}
	_, failure := parseChainingBehaviorControls([]ldapwire.Control{valid, valid})
	if failure == nil || failure.Code != ldapwire.ResultProtocolError {
		t.Fatalf("duplicate chaining controls failure = %#v", failure)
	}
	_, failure = parseChainingBehaviorControls([]ldapwire.Control{
		valid,
		{OID: pagedResultsControlOID, HasValue: true},
	})
	if failure == nil || failure.Code != ldapwire.ResultProtocolError {
		t.Fatalf("paged chaining controls failure = %#v", failure)
	}
	invalid := valid
	invalid.Value = []byte{0x30, 0x03, 0x0a, 0x01, 0x04}
	_, failure = parseChainingBehaviorControls([]ldapwire.Control{invalid})
	if failure == nil || failure.Code != ldapwire.ResultProtocolError {
		t.Fatalf("invalid chaining behavior failure = %#v", failure)
	}
}

func TestApplyChainIdentityAssertionPolicies(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	server := &Server{config: Config{Store: store}}
	message := ldapwire.Message{
		ID: 1,
		Request: ldapwire.SearchRequest{
			BaseDN: "dc=example,dc=com",
			Scope:  directory.ScopeBase,
		},
	}
	alice := "uid=alice,ou=people,dc=example,dc=com"
	state := &connectionState{
		boundDN:          alice,
		authMechanism:    "SIMPLE",
		bindCredentialDN: alice,
		bindCredentials:  []byte("secret"),
		runtime:          &runtimeState{},
	}
	configured := func() chainRemoteConfiguration {
		remote := defaultChainRemoteConfiguration()
		remote.identity.configured = true
		remote.identity.mode = chainIdentitySelf
		remote.bind.bindMethod = "simple"
		remote.bind.bindDN = chainTestRootDN
		remote.bind.credentials = []byte(chainTestRootPassword)
		remote.bind.credentialsSet = true
		return remote
	}

	t.Run("authorized", func(t *testing.T) {
		remote := configured()
		remote.identity.authzFrom = []string{"{0}dn.exact:" + alice}
		gotRemote, gotMessage, failure := server.applyChainIdentity(
			context.Background(),
			state,
			remote,
			message,
		)
		if failure != nil || gotRemote.bind.bindDN != chainTestRootDN {
			t.Fatalf("applyChainIdentity() = %#v, %#v", gotRemote, failure)
		}
		control := chainedProxyAuthorizationControl(gotMessage.Controls)
		if control == nil || string(control.Value) != "dn:"+alice {
			t.Fatalf("ProxyAuthz control = %#v", control)
		}
	})

	t.Run("prescriptive denial", func(t *testing.T) {
		remote := configured()
		remote.identity.authzFrom = []string{
			"dn.exact:uid=bob,ou=people,dc=example,dc=com",
		}
		_, _, failure := server.applyChainIdentity(
			context.Background(),
			state,
			remote,
			message,
		)
		if failure == nil ||
			failure.Code != ldapwire.ResultInappropriateAuthentication {
			t.Fatalf("identity failure = %#v", failure)
		}
	})

	t.Run("non-prescriptive anonymous fallback", func(t *testing.T) {
		remote := configured()
		remote.identity.prescriptive = false
		remote.identity.authzFrom = []string{
			"dn.exact:uid=bob,ou=people,dc=example,dc=com",
		}
		gotRemote, gotMessage, failure := server.applyChainIdentity(
			context.Background(),
			state,
			remote,
			message,
		)
		if failure != nil || gotRemote.bind.bindMethod != "" ||
			chainedProxyAuthorizationControl(gotMessage.Controls) != nil {
			t.Fatalf(
				"anonymous fallback = remote %#v, controls %#v, failure %#v",
				gotRemote,
				gotMessage.Controls,
				failure,
			)
		}
	})

	t.Run("simple pass-through", func(t *testing.T) {
		remote := configured()
		remote.identity.passThru = []string{"dn.exact:" + alice}
		gotRemote, gotMessage, failure := server.applyChainIdentity(
			context.Background(),
			state,
			remote,
			message,
		)
		if failure != nil || gotRemote.bind.bindMethod != "simple" ||
			gotRemote.bind.bindDN != alice ||
			string(gotRemote.bind.credentials) != "secret" ||
			chainedProxyAuthorizationControl(gotMessage.Controls) != nil {
			t.Fatalf(
				"pass-through = remote %#v, controls %#v, failure %#v",
				gotRemote,
				gotMessage.Controls,
				failure,
			)
		}
	})

	t.Run("legacy anonymous", func(t *testing.T) {
		remote := configured()
		remote.identity.mode = chainIdentityLegacy
		anonymous := *state
		anonymous.boundDN = ""
		anonymous.authMechanism = "SIMPLE"
		anonymous.bindCredentialDN = ""
		anonymous.bindCredentials = nil
		gotRemote, gotMessage, failure := server.applyChainIdentity(
			context.Background(),
			&anonymous,
			remote,
			message,
		)
		if failure != nil || gotRemote.bind.bindMethod != "" ||
			chainedProxyAuthorizationControl(gotMessage.Controls) != nil {
			t.Fatalf(
				"legacy anonymous = remote %#v, controls %#v, failure %#v",
				gotRemote,
				gotMessage.Controls,
				failure,
			)
		}
	})
}

func TestParseChainIdentityAssertionFixedAuthorizationID(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		authzID    string
		wantMode   chainIdentityMode
		wantAssert string
	}{
		{
			name:       "user",
			authzID:    "u:directory-service",
			wantMode:   chainIdentityOtherID,
			wantAssert: "u:directory-service",
		},
		{
			name:       "DN",
			authzID:    "dn:cn=Directory Service,dc=example,dc=com",
			wantMode:   chainIdentityOtherDN,
			wantAssert: "dn:cn=Directory Service,dc=example,dc=com",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			configuration := defaultChainRemoteConfiguration()
			err := parseChainIdentityAssertion(
				`bindmethod=simple binddn="cn=proxy,dc=example,dc=com" `+
					`credentials=secret authzid="`+test.authzID+`"`,
				&configuration,
			)
			if err != nil || configuration.identity.mode != test.wantMode ||
				configuration.identity.assertedID != test.wantAssert {
				t.Fatalf(
					"parseChainIdentityAssertion() = identity %#v, %v",
					configuration.identity,
					err,
				)
			}
		})
	}
}

func TestPasswordPolicyForwardsBindStateThroughChain(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name           string
		password       string
		initialFailure bool
		wantFailure    bool
	}{
		{
			name:        "record failed bind",
			password:    "wrong-secret",
			wantFailure: true,
		},
		{
			name:           "clear failures after successful bind",
			password:       "secret",
			initialFailure: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			providerStore := storage.NewMemory()
			t.Cleanup(func() { _ = providerStore.Close() })
			seedPasswordPolicyDirectory(
				t,
				providerStore,
				[]directory.Attribute{
					{Description: "pwdLockout", Values: stringValues("TRUE")},
					{Description: "pwdMaxFailure", Values: stringValues("3")},
				},
				nil,
			)
			if test.initialFailure {
				seedChainPasswordFailure(t, providerStore)
			}
			providerAddress, stopProvider := startServer(t, providerStore, Config{
				RootDN:       chainTestRootDN,
				RootPassword: []byte(chainTestRootPassword),
			})
			defer stopProvider()

			consumerStore := storage.NewMemory()
			t.Cleanup(func() { _ = consumerStore.Close() })
			seedPasswordPolicyDirectory(
				t,
				consumerStore,
				[]directory.Attribute{
					{Description: "pwdLockout", Values: stringValues("TRUE")},
					{Description: "pwdMaxFailure", Values: stringValues("3")},
				},
				[]directory.Attribute{{
					Description: "olcPPolicyForwardUpdates",
					Values:      stringValues("TRUE"),
				}},
			)
			if test.initialFailure {
				seedChainPasswordFailure(t, consumerStore)
			}
			configureChainPasswordPolicyShadow(
				t,
				consumerStore,
				providerAddress,
			)
			consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
				RootDN:       chainTestRootDN,
				RootPassword: []byte(chainTestRootPassword),
			})
			defer stopConsumer()

			client, err := ldap.DialURL("ldap://" + consumerAddress)
			if err != nil {
				t.Fatalf("DialURL(consumer): %v", err)
			}
			defer client.Close()
			err = client.Bind(aliceDN, test.password)
			if test.password == "secret" {
				if err != nil {
					t.Fatalf("successful Bind(): %v", err)
				}
			} else {
				assertLDAPResultCode(t, err, ldap.LDAPResultInvalidCredentials)
			}

			providerEntry := readStoredEntry(t, providerStore, aliceDN)
			if got := providerEntry.HasAttribute("pwdFailureTime"); got != test.wantFailure {
				t.Fatalf("provider pwdFailureTime present = %t, want %t", got, test.wantFailure)
			}
			consumerEntry := readStoredEntry(t, consumerStore, aliceDN)
			if got := consumerEntry.HasAttribute("pwdFailureTime"); got != test.initialFailure {
				t.Fatalf(
					"consumer pwdFailureTime present = %t, want unchanged %t",
					got,
					test.initialFailure,
				)
			}
		})
	}
}

func chainedProxyAuthorizationControl(
	controls []ldapwire.Control,
) *ldapwire.Control {
	for index := range controls {
		if controls[index].OID == proxyAuthorizationControlOID {
			return &controls[index]
		}
	}
	return nil
}

func seedChainPasswordFailure(t *testing.T, store storage.Store) {
	t.Helper()
	setPasswordPolicyEntryValues(t, store, aliceDN, map[string][][]byte{
		"pwdFailureTime": stringValues(
			formatPasswordPolicyFailureTime(time.Now().Add(-time.Minute)),
		),
	})
}

func configureChainPasswordPolicyShadow(
	t *testing.T,
	store storage.Store,
	providerAddress string,
) {
	t.Helper()
	seedChainConsumerConfiguration(t, store, providerAddress)
	databaseDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
	if err != nil {
		t.Fatalf("ParseDN(database): %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		database, err := writer.Get(databaseDN)
		if err != nil {
			return err
		}
		database.ReplaceValues("olcUpdateDN", stringValues(chainTestRootDN))
		database.ReplaceValues(
			"olcUpdateRef",
			stringValues("ldap://"+providerAddress),
		)
		return writer.Put(database, true)
	}); err != nil {
		t.Fatalf("configure ppolicy shadow: %v", err)
	}
}

func seedChainProviderEntries(t *testing.T, store storage.Store) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: chainTestReferralDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit")},
				{Description: "ou", Values: stringValues("remote")},
			},
		},
		{
			DN: "uid=remote," + chainTestReferralDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("remote")},
				{Description: "cn", Values: stringValues("Remote User")},
				{Description: "sn", Values: stringValues("User")},
				{Description: "userPassword", Values: stringValues("remote-secret")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed chain provider: %v", err)
	}
}

func seedChainConsumerConfiguration(
	t *testing.T,
	store storage.Store,
	providerAddress string,
) {
	t.Helper()
	overlayDN := "olcOverlay={0}chain,olcDatabase={-1}frontend,cn=config"
	entries := []directory.Entry{
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
				{
					Description: "olcDbIDAssertBind",
					Values: stringValues(
						`bindmethod=simple binddn="` + chainTestRootDN +
							`" credentials="` + chainTestRootPassword + `" mode=none`,
					),
				},
			},
		},
		{
			DN: chainTestReferralDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("referral", "extensibleObject")},
				{Description: "ou", Values: stringValues("remote")},
				{Description: "ref", Values: stringValues(
					"ldap://" + providerAddress + "/" + chainTestReferralDN,
				)},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed chain consumer: %v", err)
	}
}

func assertEntryMissing(t *testing.T, store storage.Store, rawDN string) {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", rawDN, err)
	}
	err = store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Get(dn)
		return err
	})
	if err != storage.ErrEntryNotFound {
		t.Fatalf("entry %q still exists: %v", rawDN, err)
	}
}

func TestParseChainLDAPIReferralTarget(t *testing.T) {
	t.Parallel()

	request := ldapwire.SearchRequest{
		BaseDN: "dc=local,dc=example",
		Scope:  directory.ScopeWholeSubtree,
	}
	target, err := parseChainReferralTarget(
		"ldapi://%2Ftmp%2Fldap.sock/dc%3Dremote%2Cdc%3Dexample??sub",
		request,
		false,
	)
	if err != nil {
		t.Fatalf("parse encoded-host referral: %v", err)
	}
	if target.uri != "ldapi://%2Ftmp%2Fldap.sock" ||
		target.endpointKey != "ldapi:///tmp/ldap.sock" ||
		target.dn == nil || target.dn.String() != "dc=remote,dc=example" {
		t.Fatalf("encoded-host target = %#v", target)
	}

	target, err = parseChainReferralTarget(
		"ldapi:///tmp/ldap.sock",
		request,
		false,
	)
	if err != nil {
		t.Fatalf("parse path referral: %v", err)
	}
	if target.uri != "ldapi://%2Ftmp%2Fldap.sock" ||
		target.endpointKey != "ldapi:///tmp/ldap.sock" || target.dn != nil {
		t.Fatalf("path target = %#v", target)
	}
}

func TestChainFilterCompatibilityPolicies(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	filter := directory.Filter{
		Kind: directory.FilterAnd,
		Children: []directory.Filter{
			{Kind: directory.FilterPresent, Attribute: "cn"},
			{Kind: directory.FilterEquality, Attribute: "unknownAttribute"},
		},
	}
	if !chainFilterHasUndefined(registry, filter) {
		t.Fatal("undefined filter was not detected")
	}
	filter.Children[1].Attribute = "uid"
	if chainFilterHasUndefined(registry, filter) {
		t.Fatal("known filter was classified as undefined")
	}

	trueFilter := rewriteChainAbsoluteFilters(directory.Filter{Kind: directory.FilterAnd})
	if trueFilter.Kind != directory.FilterPresent || trueFilter.Attribute != "objectClass" {
		t.Fatalf("absolute TRUE rewrite = %#v", trueFilter)
	}
	falseFilter := rewriteChainAbsoluteFilters(directory.Filter{Kind: directory.FilterOr})
	if falseFilter.Kind != directory.FilterNot || len(falseFilter.Children) != 1 ||
		falseFilter.Children[0].Kind != directory.FilterPresent ||
		falseFilter.Children[0].Attribute != "objectClass" {
		t.Fatalf("absolute FALSE rewrite = %#v", falseFilter)
	}
}

func TestSanitizeChainedSearchEntryRemovesUnknownSchema(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	encoded := ldapwire.EncodeSearchResultEntry(7, directory.Entry{
		DN: "uid=remote,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("top", "unknownClass")},
			{Description: "cn", Values: stringValues("Remote User")},
			{Description: "entryDN", Values: stringValues("uid=remote,dc=example,dc=com")},
			{Description: "unknownAttribute", Values: stringValues("hidden")},
		},
	}, nil)
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil {
		t.Fatalf("DecodePacketErr(): %v", err)
	}
	if err := sanitizeChainedSearchEntry(packet, registry, true); err != nil {
		t.Fatalf("sanitizeChainedSearchEntry(): %v", err)
	}
	if !chainedEntryHasValue(packet, "objectClass", "top") ||
		chainedEntryHasValue(packet, "objectClass", "unknownClass") ||
		!chainedEntryHasValue(packet, "cn", "Remote User") ||
		chainedEntryHasValue(packet, "entryDN", "uid=remote,dc=example,dc=com") ||
		chainedEntryHasValue(packet, "unknownAttribute", "hidden") {
		t.Fatalf("sanitized chained entry = %#v", packet.Children[1])
	}
}

func TestChainSessionTrackingControl(t *testing.T) {
	t.Parallel()

	client, remote := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = remote.Close()
	})
	control, ok := chainSessionTrackingControl(&connectionState{
		boundDN:    "uid=alice,dc=example,dc=com",
		connection: remote,
	})
	if !ok || control.OID != sessionTrackingControlOID ||
		control.Critical || !control.HasValue {
		t.Fatalf("session tracking control = %#v, %t", control, ok)
	}
	value, err := ber.DecodePacketErr(control.Value)
	if err != nil || len(value.Children) != 4 {
		t.Fatalf("session tracking value = %#v, %v", value, err)
	}
	want := []string{"", "", sessionTrackingUsernameFormatOID, "uid=alice,dc=example,dc=com"}
	for index, child := range value.Children {
		raw, err := syncConsumerPacketBytes(child)
		if err != nil || string(raw) != want[index] {
			t.Fatalf("session tracking field %d = %q, %v", index, raw, err)
		}
	}
	clientControl := ldapwire.Control{
		OID:      sessionTrackingControlOID,
		HasValue: true,
		Value:    ldapwire.EncodeSessionTrackingValue(ldapwire.SessionTrackingValue{FormatOID: []byte("1.2")}),
	}
	controls := appendChainSessionTrackingControl(
		[]ldapwire.Control{clientControl},
		&connectionState{
			boundDN:    "uid=alice,dc=example,dc=com",
			connection: remote,
		},
	)
	if len(controls) != 2 || controls[0].OID != sessionTrackingControlOID ||
		controls[1].OID != sessionTrackingControlOID ||
		!bytes.Equal(controls[0].Value, clientControl.Value) {
		t.Fatalf("client plus generated session tracking controls = %#v", controls)
	}
}

func TestChainNestedReferralRebindPolicy(t *testing.T) {
	t.Parallel()

	parent := defaultChainRemoteConfiguration()
	parent.uri = "ldap://first.example"
	parent.bind.bindMethod = "simple"
	parent.bind.bindDN = "uid=alice,dc=example,dc=com"
	parent.bind.credentials = []byte("secret")
	parent.bind.credentialsSet = true
	target := chainReferralTarget{
		uri:         "ldaps://second.example",
		endpointKey: "ldaps://second.example",
	}

	parent.rebindAsUser = true
	rebound := chainNestedReferralRemote(parent, target)
	if rebound.uri != target.uri || rebound.endpointKey != target.endpointKey ||
		rebound.bind.bindMethod != "simple" ||
		rebound.bind.bindDN != parent.bind.bindDN ||
		string(rebound.bind.credentials) != "secret" {
		t.Fatalf("rebound remote = %#v", rebound)
	}
	rebound.bind.credentials[0] = 'S'
	if string(parent.bind.credentials) != "secret" {
		t.Fatal("nested credentials alias parent credentials")
	}

	parent.rebindAsUser = false
	anonymous := chainNestedReferralRemote(parent, target)
	if anonymous.bind.bindMethod != "" || anonymous.bind.bindDN != "" ||
		len(anonymous.bind.credentials) != 0 {
		t.Fatalf("anonymous nested remote = %#v", anonymous)
	}
}

func ldapChainingBehaviorControl(
	t *testing.T,
	resolve,
	continuation chainBehavior,
) ldap.Control {
	t.Helper()
	value := ber.NewSequence("ChainingBehavior")
	for _, behavior := range []chainBehavior{resolve, continuation} {
		value.AppendChild(ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagEnumerated,
			int64(behavior),
			"behavior",
		))
	}
	return ldap.NewControlString(
		chainingBehaviorControlOID,
		true,
		string(value.Bytes()),
	)
}
