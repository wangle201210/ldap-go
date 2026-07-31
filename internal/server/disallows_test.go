package server

import (
	"context"
	"crypto/tls"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadOpenLDAPGlobalFeatureConfiguration(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{
					Description: "olcAllows",
					Values: stringValues(
						"bind_v2 bind_anon_cred",
						"BIND_ANON_DN update_anon proxy_authz_anon",
					),
				},
				{
					Description: "olcDisallows",
					Values: stringValues(
						"bind_anon bind_simple tls_2_anon",
						"TLS_AUTHC proxy_authz_non_critical",
						"dontusecopy_non_critical",
					),
				},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed global configuration: %v", err)
	}

	var (
		allows    allowsRuntimeConfiguration
		disallows disallowsRuntimeConfiguration
	)
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		allows, err = loadAllowsRuntimeConfiguration(reader)
		if err != nil {
			return err
		}
		disallows, err = loadDisallowsRuntimeConfiguration(reader)
		return err
	}); err != nil {
		t.Fatalf("load global feature configuration: %v", err)
	}
	wantAllows := allowsRuntimeConfiguration{
		bindV2:                   true,
		bindAnonymousCredentials: true,
		bindAnonymousDN:          true,
		anonymousUpdates:         true,
		anonymousProxyAuthz:      true,
	}
	if allows != wantAllows {
		t.Fatalf("olcAllows = %#v, want %#v", allows, wantAllows)
	}
	wantDisallows := disallowsRuntimeConfiguration{
		anonymousBind:                 true,
		simpleBind:                    true,
		tlsToAnonymous:                true,
		tlsAuthenticated:              true,
		noncriticalProxyAuthorization: true,
		noncriticalDontUseCopy:        true,
	}
	if disallows != wantDisallows {
		t.Fatalf("olcDisallows = %#v, want %#v", disallows, wantDisallows)
	}
}

func TestLoadOpenLDAPGlobalFeatureConfigurationRejectsUnknownValues(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		attribute string
		value     string
		load      func(storage.Reader) error
	}{
		{
			attribute: "olcAllows",
			value:     "unknown_allow",
			load: func(reader storage.Reader) error {
				_, err := loadAllowsRuntimeConfiguration(reader)
				return err
			},
		},
		{
			attribute: "olcDisallows",
			value:     "unknown_disallow",
			load: func(reader storage.Reader) error {
				_, err := loadDisallowsRuntimeConfiguration(reader)
				return err
			},
		},
	} {
		t.Run(test.attribute, func(t *testing.T) {
			t.Parallel()

			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				return writer.Put(directory.Entry{
					DN: "cn=config",
					Attributes: []directory.Attribute{{
						Description: test.attribute,
						Values:      stringValues(test.value),
					}},
				}, false)
			}); err != nil {
				t.Fatalf("seed global configuration: %v", err)
			}
			err := store.View(context.Background(), test.load)
			if err == nil || !strings.Contains(err.Error(), test.value) {
				t.Fatalf("load error = %v, want unknown feature", err)
			}
		})
	}
}

func TestLDAPOpenLDAPBindPoliciesReloadAndRollback(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)

	const rootDN = "cn=admin,dc=example,dc=com"
	const rootPassword = "admin-secret"
	address, stop := startServer(t, store, Config{
		RootDN:       rootDN,
		RootPassword: []byte(rootPassword),
	})
	defer stop()

	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("config Bind(): %v", err)
	}

	allows := ldap.NewModifyRequest("cn=config", nil)
	allows.Replace(
		"olcAllows",
		[]string{"bind_anon_cred bind_anon_dn"},
	)
	if err := configClient.Modify(allows); err != nil {
		t.Fatalf("enable anonymous Bind forms: %v", err)
	}
	disallowAnonymous := ldap.NewModifyRequest("cn=config", nil)
	disallowAnonymous.Replace("olcDisallows", []string{"bind_anon"})
	if err := configClient.Modify(disallowAnonymous); err != nil {
		t.Fatalf("enable bind_anon disallow: %v", err)
	}

	for _, credentials := range []struct {
		name     string
		dn       string
		password string
	}{
		{name: "empty", dn: "", password: ""},
		{name: "credentials", dn: "", password: "ignored"},
		{name: "DN", dn: aliceDN, password: ""},
	} {
		t.Run(credentials.name, func(t *testing.T) {
			observation := observeSimpleBind(
				t,
				address,
				credentials.dn,
				credentials.password,
			)
			if observation.code != int64(ldap.LDAPResultInappropriateAuthentication) ||
				observation.diagnostic != "anonymous bind disallowed" {
				t.Fatalf("anonymous Bind = %#v", observation)
			}
		})
	}
	if observation := observeSimpleBind(
		t,
		address,
		rootDN,
		rootPassword,
	); observation.code != int64(ldap.LDAPResultSuccess) {
		t.Fatalf("authenticated Bind = %#v", observation)
	}

	disallowSimple := ldap.NewModifyRequest("cn=config", nil)
	disallowSimple.Replace("olcDisallows", []string{"bind_simple"})
	if err := configClient.Modify(disallowSimple); err != nil {
		t.Fatalf("enable bind_simple disallow: %v", err)
	}
	if observation := observeSimpleBind(t, address, "", ""); observation.code !=
		int64(ldap.LDAPResultSuccess) {
		t.Fatalf("anonymous Bind with bind_simple = %#v", observation)
	}
	observation := observeSimpleBind(t, address, rootDN, rootPassword)
	if observation.code != int64(ldap.LDAPResultUnwillingToPerform) ||
		observation.diagnostic != "unwilling to perform simple authentication" {
		t.Fatalf("simple Bind = %#v", observation)
	}

	invalid := ldap.NewModifyRequest("cn=config", nil)
	invalid.Replace("olcDisallows", []string{"unknown_feature"})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	observation = observeSimpleBind(t, address, rootDN, rootPassword)
	if observation.code != int64(ldap.LDAPResultUnwillingToPerform) {
		t.Fatalf("simple Bind after invalid reload = %#v", observation)
	}

	enableSimple := ldap.NewModifyRequest("cn=config", nil)
	enableSimple.Delete("olcDisallows", []string{})
	if err := configClient.Modify(enableSimple); err != nil {
		t.Fatalf("remove Bind disallows: %v", err)
	}
	if observation := observeSimpleBind(
		t,
		address,
		rootDN,
		rootPassword,
	); observation.code != int64(ldap.LDAPResultSuccess) {
		t.Fatalf("re-enabled simple Bind = %#v", observation)
	}
	for _, credentials := range []struct {
		dn       string
		password string
	}{
		{dn: "", password: "ignored"},
		{dn: aliceDN, password: ""},
	} {
		if observation := observeSimpleBind(
			t,
			address,
			credentials.dn,
			credentials.password,
		); observation.code != int64(ldap.LDAPResultSuccess) {
			t.Fatalf("allowed anonymous Bind = %#v", observation)
		}
	}
}

func TestLDAPOpenLDAPBindPolicyPrecedence(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	replaceGlobalConfigurationValues(
		t,
		store,
		"olcDisallows",
		"bind_anon",
	)

	address, stop := startServer(t, store, Config{})
	defer stop()

	credentialBind := observeSimpleBind(t, address, "", "not-empty")
	if credentialBind.code != int64(ldap.LDAPResultInvalidCredentials) ||
		credentialBind.diagnostic != "" {
		t.Fatalf("anonymous credential Bind = %#v", credentialBind)
	}
	dnBind := observeSimpleBind(t, address, aliceDN, "")
	if dnBind.code != int64(ldap.LDAPResultUnwillingToPerform) ||
		dnBind.diagnostic !=
			"unauthenticated bind (DN with no password) disallowed" {
		t.Fatalf("unauthenticated DN Bind = %#v", dnBind)
	}
}

func TestLDAPOpenLDAPBindVersionAndDNSyntaxPolicies(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()

	observation := observeSimpleBindVersion(t, address, 2, "", "")
	if observation.code != int64(ldap.LDAPResultProtocolError) ||
		observation.diagnostic !=
			"historical protocol version requested, use LDAPv3 instead" {
		t.Fatalf("LDAPv2 Bind = %#v", observation)
	}
	observation = observeSimpleBindVersion(t, address, 4, "", "")
	if observation.code != int64(ldap.LDAPResultProtocolError) ||
		observation.diagnostic != "requested protocol version not supported" {
		t.Fatalf("LDAPv4 Bind = %#v", observation)
	}
	observation = observeSimpleBindVersion(t, address, 3, "not-a-dn", "")
	if observation.code != int64(ldap.LDAPResultInvalidDNSyntax) ||
		observation.diagnostic != "invalid DN" {
		t.Fatalf("malformed-DN Bind = %#v", observation)
	}

	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("config Bind(): %v", err)
	}
	allowV2 := ldap.NewModifyRequest("cn=config", nil)
	allowV2.Replace("olcAllows", []string{"bind_v2"})
	if err := configClient.Modify(allowV2); err != nil {
		t.Fatalf("enable bind_v2: %v", err)
	}
	observation = observeSimpleBindVersion(t, address, 2, "", "")
	if observation.code != int64(ldap.LDAPResultSuccess) {
		t.Fatalf("allowed LDAPv2 Bind = %#v", observation)
	}
}

func TestLDAPOpenLDAPDisallowsSurviveRestart(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	replaceGlobalConfigurationValues(
		t,
		store,
		"olcDisallows",
		"bind_anon",
	)

	for attempt := 0; attempt < 2; attempt++ {
		address, stop := startServer(t, store, Config{})
		observation := observeSimpleBind(t, address, "", "")
		stop()
		if observation.code != int64(ldap.LDAPResultInappropriateAuthentication) ||
			observation.diagnostic != "anonymous bind disallowed" {
			t.Fatalf("attempt %d anonymous Bind = %#v", attempt, observation)
		}
	}
}

func TestLDAPOpenLDAPStartTLSPolicies(t *testing.T) {
	t.Parallel()

	const rootDN = "cn=admin,dc=example,dc=com"
	const rootPassword = "admin-secret"
	for _, test := range []struct {
		name      string
		disallows string
		wantCode  uint16
		wantAuthz string
	}{
		{
			name:      "default resets identity",
			wantCode:  ldap.LDAPResultSuccess,
			wantAuthz: "",
		},
		{
			name:      "tls_2_anon retains identity",
			disallows: "tls_2_anon",
			wantCode:  ldap.LDAPResultSuccess,
			wantAuthz: "dn:" + rootDN,
		},
		{
			name:      "tls_authc resets before policy check",
			disallows: "tls_authc",
			wantCode:  ldap.LDAPResultSuccess,
			wantAuthz: "",
		},
		{
			name:      "combined flags reject authenticated StartTLS",
			disallows: "tls_2_anon tls_authc",
			wantCode:  ldap.LDAPResultOperationsError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedOnlineConfiguration(t, store)
			if test.disallows != "" {
				replaceGlobalConfigurationValues(
					t,
					store,
					"olcDisallows",
					test.disallows,
				)
			}

			address, stop := startServer(t, store, Config{
				RootDN:       rootDN,
				RootPassword: []byte(rootPassword),
				TLSConfig:    testServerTLSConfig(t),
			})
			defer stop()

			client, err := ldap.DialURL("ldap://" + address)
			if err != nil {
				t.Fatalf("DialURL(): %v", err)
			}
			defer client.Close()
			if err := client.Bind(rootDN, rootPassword); err != nil {
				t.Fatalf("root Bind(): %v", err)
			}
			err = client.StartTLS(&tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			})
			if test.wantCode != ldap.LDAPResultSuccess {
				assertLDAPResultCode(t, err, test.wantCode)
				return
			}
			if err != nil {
				t.Fatalf("StartTLS(): %v", err)
			}
			identity, err := client.WhoAmI(nil)
			if err != nil || identity.AuthzID != test.wantAuthz {
				t.Fatalf("post-StartTLS WhoAmI = %#v, %v", identity, err)
			}
		})
	}
}

func TestLDAPOpenLDAPStartTLSRejectsWithoutDroppingIdentity(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	replaceGlobalConfigurationValues(
		t,
		store,
		"olcDisallows",
		"tls_2_anon tls_authc",
	)

	const rootDN = "cn=admin,dc=example,dc=com"
	const rootPassword = "admin-secret"
	address, stop := startServer(t, store, Config{
		RootDN:       rootDN,
		RootPassword: []byte(rootPassword),
		TLSConfig:    testServerTLSConfig(t),
	})
	defer stop()

	connection := dialAndBindRawLDAP(t, address, rootDN, rootPassword)
	defer connection.Close()
	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawExtendedRequest(startTLSOID, nil, false),
	)
	if code := rawLDAPResultCode(t, response.Children[1]); code !=
		int64(ldap.LDAPResultOperationsError) ||
		rawLDAPDiagnostic(response) != "cannot start TLS after authentication" {
		t.Fatalf("StartTLS response = %#v", response)
	}

	response = sendRawLDAPOperation(
		t,
		connection,
		3,
		rawExtendedRequest(whoAmIOID, nil, false),
	)
	if code := rawLDAPResultCode(t, response.Children[1]); code !=
		int64(ldap.LDAPResultSuccess) {
		t.Fatalf("WhoAmI result code = %d", code)
	}
	value, present := rawExtendedResponseValue(response)
	if !present || string(value) != "dn:"+rootDN {
		t.Fatalf("WhoAmI response value = %q, %t", value, present)
	}
}

func TestLDAPOpenLDAPStartTLSPolicyRunsBeforeTLSAvailability(t *testing.T) {
	t.Parallel()

	const rootDN = "cn=admin,dc=example,dc=com"
	const rootPassword = "admin-secret"
	for _, test := range []struct {
		name      string
		disallows string
		wantAuthz string
	}{
		{
			name:      "default resets identity",
			wantAuthz: "",
		},
		{
			name:      "tls_2_anon retains identity",
			disallows: "tls_2_anon",
			wantAuthz: "dn:" + rootDN,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedOnlineConfiguration(t, store)
			if test.disallows != "" {
				replaceGlobalConfigurationValues(
					t,
					store,
					"olcDisallows",
					test.disallows,
				)
			}
			address, stop := startServer(t, store, Config{
				RootDN:       rootDN,
				RootPassword: []byte(rootPassword),
			})
			defer stop()

			connection := dialAndBindRawLDAP(
				t,
				address,
				rootDN,
				rootPassword,
			)
			defer connection.Close()
			response := sendRawLDAPOperation(
				t,
				connection,
				2,
				rawExtendedRequest(startTLSOID, nil, false),
			)
			if code := rawLDAPResultCode(t, response.Children[1]); code !=
				int64(ldap.LDAPResultUnavailable) {
				t.Fatalf("StartTLS result code = %d", code)
			}

			response = sendRawLDAPOperation(
				t,
				connection,
				3,
				rawExtendedRequest(whoAmIOID, nil, false),
			)
			value, present := rawExtendedResponseValue(response)
			if !present || string(value) != test.wantAuthz {
				t.Fatalf("WhoAmI response value = %q, %t", value, present)
			}
		})
	}
}

func TestLDAPOpenLDAPDontUseCopyCriticalityPolicyReload(t *testing.T) {
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
		t.Fatalf("config Bind(): %v", err)
	}
	enable := ldap.NewModifyRequest("cn=config", nil)
	enable.Replace(
		"olcDisallows",
		[]string{"dontusecopy_non_critical"},
	)
	if err := configClient.Modify(enable); err != nil {
		t.Fatalf("enable dontUseCopy criticality policy: %v", err)
	}

	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline(): %v", err)
	}
	request := rawDontUseCopyCompareRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		"uid",
		"alice",
	)
	response := sendRawLDAPOperation(
		t,
		connection,
		1,
		request,
		rawDontUseCopyControl(false, false),
	)
	observation := observeDontUseCopyResult(t, response)
	if observation.code != int64(ldap.LDAPResultProtocolError) ||
		observation.diagnostic !=
			"dontUseCopy criticality of FALSE not allowed" {
		t.Fatalf("noncritical dontUseCopy = %#v", observation)
	}

	disable := ldap.NewModifyRequest("cn=config", nil)
	disable.Delete("olcDisallows", []string{})
	if err := configClient.Modify(disable); err != nil {
		t.Fatalf("disable dontUseCopy criticality policy: %v", err)
	}
	response = sendRawLDAPOperation(
		t,
		connection,
		2,
		request,
		rawDontUseCopyControl(false, false),
	)
	observation = observeDontUseCopyResult(t, response)
	if observation.code != int64(ldap.LDAPResultCompareTrue) {
		t.Fatalf("re-enabled noncritical dontUseCopy = %#v", observation)
	}
}

func TestOpenLDAPReferenceGlobalDisallows(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)

	ldapGoStore := storage.NewMemory()
	t.Cleanup(func() { _ = ldapGoStore.Close() })
	seedOnlineConfiguration(t, ldapGoStore)
	replaceGlobalConfigurationValues(
		t,
		ldapGoStore,
		"olcAllows",
		"bind_v2 bind_anon_cred bind_anon_dn",
	)
	replaceGlobalConfigurationValues(
		t,
		ldapGoStore,
		"olcDisallows",
		"bind_anon bind_simple dontusecopy_non_critical",
	)
	ldapGoAddress, stopLDAPGo := startServer(t, ldapGoStore, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stopLDAPGo()
	want := collectGlobalDisallowObservations(
		t,
		ldapGoAddress,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)

	uri, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"allow bind_v2 bind_anon_cred bind_anon_dn\n"+
			"disallow bind_anon bind_simple dontusecopy_non_critical",
		"",
		"",
	)
	defer stopOpenLDAP()
	got := collectGlobalDisallowObservations(
		t,
		strings.TrimPrefix(uri, "ldap://"),
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"OpenLDAP observations = %#v, want ldap-go %#v",
			got,
			want,
		)
	}
}

type simpleBindObservation struct {
	code       int64
	diagnostic string
}

func collectGlobalDisallowObservations(
	t *testing.T,
	address, rootDN, rootPassword string,
) []simpleBindObservation {
	t.Helper()

	observations := []simpleBindObservation{
		observeSimpleBind(t, address, "", ""),
		observeSimpleBind(t, address, "", "ignored"),
		observeSimpleBind(t, address, aliceDN, ""),
		observeSimpleBind(t, address, rootDN, rootPassword),
		observeSimpleBindVersion(t, address, 2, rootDN, rootPassword),
		observeSimpleBind(t, address, "not-a-dn", ""),
	}

	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline(): %v", err)
	}
	request := rawDontUseCopyCompareRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		"uid",
		"alice",
	)
	for messageID, critical := range []bool{false, true} {
		response := sendRawLDAPOperation(
			t,
			connection,
			int64(messageID+1),
			request,
			rawDontUseCopyControl(critical, false),
		)
		observations = append(observations, simpleBindObservation{
			code:       rawLDAPResultCode(t, response.Children[1]),
			diagnostic: rawLDAPDiagnostic(response),
		})
	}
	return observations
}

func observeSimpleBind(
	t *testing.T,
	address, dn, password string,
) simpleBindObservation {
	t.Helper()
	return observeSimpleBindVersion(t, address, 3, dn, password)
}

func observeSimpleBindVersion(
	t *testing.T,
	address string,
	version int64,
	dn, password string,
) simpleBindObservation {
	t.Helper()

	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline(): %v", err)
	}
	response := sendRawLDAPOperation(
		t,
		connection,
		1,
		rawSimpleBindRequestVersion(version, dn, password),
	)
	if response == nil || len(response.Children) < 2 {
		t.Fatalf("malformed Bind response: %#v", response)
	}
	return simpleBindObservation{
		code:       rawLDAPResultCode(t, response.Children[1]),
		diagnostic: rawLDAPDiagnostic(response),
	}
}

func replaceGlobalConfigurationValues(
	t *testing.T,
	store storage.Store,
	attribute string,
	values ...string,
) {
	t.Helper()

	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(configurationSuffix)
		if err != nil {
			return err
		}
		entry.ReplaceValues(attribute, stringValues(values...))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("replace %s: %v", attribute, err)
	}
}
