package server

import (
	"reflect"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestParseSecurityStrengthRequirements(t *testing.T) {
	got, err := parseSecurityStrengthRequirements([][]byte{
		[]byte("SsF=1 TRANSPORT=2 tls=3 SaSl=4"),
		[]byte("UPDATE_SSF=5 update_transport=6 UPDATE_TLS=7"),
		[]byte("Update_Sasl=8 SIMPLE_BIND=9"),
	})
	if err != nil {
		t.Fatalf("parse security requirements: %v", err)
	}
	want := securityStrengthRequirements{
		overall:         1,
		transport:       2,
		tls:             3,
		sasl:            4,
		updateOverall:   5,
		updateTransport: 6,
		updateTLS:       7,
		updateSASL:      8,
		simpleBind:      9,
		configured: securityFactorOverall | securityFactorTransport |
			securityFactorTLS | securityFactorSASL | securityFactorUpdateOverall |
			securityFactorUpdateTransport | securityFactorUpdateTLS |
			securityFactorUpdateSASL | securityFactorSimpleBind,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("security requirements = %#v, want %#v", got, want)
	}

	got, err = parseSecurityStrengthRequirements([][]byte{
		[]byte("ssf=1 tls=2"),
		[]byte("SSF=03 +invalid=1"),
	})
	if err == nil || !strings.Contains(err.Error(), "unknown factor") {
		t.Fatalf("unknown factor error = %v", err)
	}

	got, err = parseSecurityStrengthRequirements([][]byte{
		[]byte("ssf=1 ssf=01"),
		[]byte("ssf=+2"),
	})
	if err != nil {
		t.Fatalf("parse duplicate security factors: %v", err)
	}
	if got.overall != 2 {
		t.Fatalf("last ssf = %d, want 2", got.overall)
	}
}

func TestParseSecurityStrengthRequirementsRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantError string
	}{
		{name: "empty value", value: "", wantError: "no factors"},
		{name: "missing equals", value: "ssf", wantError: "unknown factor"},
		{name: "unknown factor", value: "privacy=1", wantError: "unknown factor"},
		{name: "empty strength", value: "ssf=", wantError: "unable to parse factor"},
		{name: "negative", value: "ssf=-1", wantError: "unable to parse factor"},
		{name: "hexadecimal", value: "ssf=0x10", wantError: "unable to parse factor"},
		{name: "trailing data", value: "ssf=1x", wantError: "unable to parse factor"},
		{name: "overflow", value: "ssf=4294967296", wantError: "unable to parse factor"},
		{name: "ordered prefix is unsupported", value: "{0}ssf=1", wantError: "unknown factor"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseSecurityStrengthRequirements([][]byte{[]byte(test.value)})
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("parse %q error = %v, want substring %q", test.value, err, test.wantError)
			}
		})
	}
}

func TestParseOperationRequirements(t *testing.T) {
	got, err := parseOperationRequirements([][]byte{
		[]byte("NoNe AuThC BIND"),
		[]byte("LDAPv3 sasl STRONG"),
	})
	if err != nil {
		t.Fatalf("parse operation requirements: %v", err)
	}
	want := requireAuthentication | requireBind | requireLDAPv3 |
		requireSASL | requireStrongAuthentication
	if got != want {
		t.Fatalf("operation requirements = %#x, want %#x", got, want)
	}

	got, err = parseOperationRequirements([][]byte{
		[]byte("authc bind"),
		[]byte("none LDAPv3"),
	})
	if err != nil {
		t.Fatalf("parse resetting none requirement: %v", err)
	}
	if got != requireLDAPv3 {
		t.Fatalf("requirements after none = %#x, want LDAPv3 only", got)
	}

	tests := []struct {
		name      string
		value     string
		wantError string
	}{
		{name: "empty", value: "", wantError: "no requirements"},
		{name: "none not first", value: "authc none", wantError: "none must be listed first"},
		{name: "unknown", value: "integrity", wantError: "unknown feature"},
		{name: "ordered prefix is unsupported", value: "{0}bind", wantError: "unknown feature"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseOperationRequirements([][]byte{[]byte(test.value)})
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("parse %q error = %v, want substring %q", test.value, err, test.wantError)
			}
		})
	}
}

func TestEffectiveSecurityPolicyInheritance(t *testing.T) {
	frontendSecurity := securityStrengthRequirements{
		overall:         10,
		transport:       20,
		tls:             30,
		sasl:            40,
		updateOverall:   50,
		updateTransport: 60,
		updateTLS:       70,
		updateSASL:      80,
		simpleBind:      90,
	}
	runtime := &runtimeState{
		security: frontendSecurity,
		requires: requireBind | requireLDAPv3,
	}
	database := &runtimeDatabase{
		name: "{1}mdb",
		security: securityStrengthRequirements{
			overall:         1,
			tls:             3,
			updateTransport: 6,
			simpleBind:      9,
		},
		requires: requireAuthentication | requireSASL,
	}

	security, requires := effectiveSecurityPolicy(runtime, database)
	wantSecurity := frontendSecurity
	wantSecurity.overall = 1
	wantSecurity.tls = 3
	wantSecurity.updateTransport = 6
	wantSecurity.simpleBind = 9
	if !reflect.DeepEqual(security, wantSecurity) {
		t.Fatalf("effective security = %#v, want %#v", security, wantSecurity)
	}
	wantRequires := requireBind | requireLDAPv3 | requireAuthentication | requireSASL
	if requires != wantRequires {
		t.Fatalf("effective requires = %#x, want %#x", requires, wantRequires)
	}

	frontendDatabase := &runtimeDatabase{
		name:     "{-1}frontend",
		security: securityStrengthRequirements{overall: 999},
		requires: requireStrongAuthentication,
	}
	security, requires = effectiveSecurityPolicy(runtime, frontendDatabase)
	if !reflect.DeepEqual(security, frontendSecurity) ||
		requires != runtime.requires {
		t.Fatalf("frontend target reapplied database policy: security=%#v requires=%#x", security, requires)
	}
}

func TestFrontendAndDatabaseConfigurationFolding(t *testing.T) {
	global, err := parseSecurityStrengthRequirements([][]byte{[]byte("ssf=10 tls=20")})
	if err != nil {
		t.Fatal(err)
	}
	frontend, err := parseSecurityStrengthRequirements([][]byte{[]byte("ssf=0")})
	if err != nil {
		t.Fatal(err)
	}
	effective := applyConfiguredSecurityStrengthRequirements(global, frontend)
	if effective.overall != 0 || effective.tls != 20 {
		t.Fatalf("frontend zero override = %#v", effective)
	}

	requires, err := applyOperationRequirementValues(
		requireAuthentication,
		[][]byte{[]byte("none")},
		false,
	)
	if err != nil || requires != 0 {
		t.Fatalf("frontend none = %#x, %v", requires, err)
	}
	requires, err = applyOperationRequirementValues(
		requireAuthentication,
		[][]byte{[]byte("bind"), []byte("LDAPv3")},
		true,
	)
	if err != nil || requires != requireAuthentication|requireLDAPv3 {
		t.Fatalf("database last-value requirements = %#x, %v", requires, err)
	}
}

func TestOperationSecurityResultStrictCheckOrder(t *testing.T) {
	security := securityStrengthRequirements{
		transport:       10,
		tls:             10,
		sasl:            10,
		overall:         25,
		updateTransport: 30,
		updateTLS:       30,
		updateSASL:      30,
		updateOverall:   40,
	}
	requirements := requireStrongAuthentication | requireSASL |
		requireAuthentication | requireBind | requireLDAPv3
	state := &connectionState{
		runtime: &runtimeState{
			security: security,
			requires: requirements,
			allows:   allowsRuntimeConfiguration{anonymousUpdates: true},
		},
	}

	assertSecurityResult(t, operationSecurityResult(state, nil, policyUpdate),
		ldapwire.ResultConfidentialityRequired, "transport confidentiality required")
	state.transportSSF = 5
	assertSecurityResult(t, operationSecurityResult(state, nil, policyUpdate),
		ldapwire.ResultConfidentialityRequired, "stronger transport confidentiality required")
	state.transportSSF = 20
	assertSecurityResult(t, operationSecurityResult(state, nil, policyUpdate),
		ldapwire.ResultConfidentialityRequired, "TLS confidentiality required")
	state.tlsSSF = 20
	assertSecurityResult(t, operationSecurityResult(state, nil, policyUpdate),
		ldapwire.ResultConfidentialityRequired, "SASL confidentiality required")
	state.saslSSF = 10
	assertSecurityResult(t, operationSecurityResult(state, nil, policyUpdate),
		ldapwire.ResultConfidentialityRequired, "stronger confidentiality required")
	state.transportSSF = 25
	assertSecurityResult(t, operationSecurityResult(state, nil, policyUpdate),
		ldapwire.ResultConfidentialityRequired, "stronger transport confidentiality required for update")
	state.transportSSF = 30
	assertSecurityResult(t, operationSecurityResult(state, nil, policyUpdate),
		ldapwire.ResultConfidentialityRequired, "stronger TLS confidentiality required for update")
	state.tlsSSF = 30
	assertSecurityResult(t, operationSecurityResult(state, nil, policyUpdate),
		ldapwire.ResultConfidentialityRequired, "stronger SASL confidentiality required for update")
	state.saslSSF = 30
	assertSecurityResult(t, operationSecurityResult(state, nil, policyUpdate),
		ldapwire.ResultConfidentialityRequired, "stronger confidentiality required for update")
	state.saslSSF = 40
	assertSecurityResult(t, operationSecurityResult(state, nil, policyUpdate),
		ldapwire.ResultStrongerAuthRequired, "strong(er) authentication required")
	state.boundDN = "uid=user,dc=example,dc=com"
	state.authMechanism = "SIMPLE"
	assertSecurityResult(t, operationSecurityResult(state, nil, policyUpdate),
		ldapwire.ResultStrongerAuthRequired, "SASL authentication required")
	state.authMechanism = "GSSAPI"
	assertSecurityResult(t, operationSecurityResult(state, nil, policyUpdate),
		ldapwire.ResultOperationsError, "BIND required")
	state.protocolVersion = 2
	assertSecurityResult(t, operationSecurityResult(state, nil, policyUpdate),
		ldapwire.ResultOperationsError, "operation restricted to LDAPv3 clients")
	state.protocolVersion = 3
	assertNoSecurityResult(t, operationSecurityResult(state, nil, policyUpdate))
}

func TestOperationRequirementsAuthenticationOrder(t *testing.T) {
	tests := []struct {
		name         string
		requirements operationRequirements
		state        connectionState
		wantCode     ldapwire.ResultCode
		wantMessage  string
	}{
		{
			name:         "strong precedes sasl authc and bind",
			requirements: requireStrongAuthentication | requireSASL | requireAuthentication | requireBind,
			wantCode:     ldapwire.ResultStrongerAuthRequired,
			wantMessage:  "strong(er) authentication required",
		},
		{
			name:         "sasl precedes authc and bind",
			requirements: requireSASL | requireAuthentication | requireBind,
			wantCode:     ldapwire.ResultStrongerAuthRequired,
			wantMessage:  "SASL authentication required",
		},
		{
			name:         "authc precedes bind",
			requirements: requireAuthentication | requireBind,
			wantCode:     ldapwire.ResultUnwillingToPerform,
			wantMessage:  "authentication required",
		},
		{
			name:         "bind precedes LDAPv3",
			requirements: requireBind | requireLDAPv3,
			wantCode:     ldapwire.ResultOperationsError,
			wantMessage:  "BIND required",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := test.state
			state.runtime = &runtimeState{requires: test.requirements}
			assertSecurityResult(t, operationSecurityResult(&state, nil, policyRead),
				test.wantCode, test.wantMessage)
		})
	}
}

func TestOperationSecurityBindAndAuthenticationStates(t *testing.T) {
	t.Run("simple Bind checks security but skips requires", func(t *testing.T) {
		state := &connectionState{
			runtime: &runtimeState{
				security: securityStrengthRequirements{
					simpleBind: 10,
					sasl:       100,
					overall:    100,
				},
				requires: requireAuthentication | requireBind,
			},
		}
		assertSecurityResult(t, operationSecurityResult(state, nil, policySimpleBind),
			ldapwire.ResultConfidentialityRequired, "confidentiality required")
		state.tlsSSF = 10
		assertSecurityResult(t, operationSecurityResult(state, nil, policySimpleBind),
			ldapwire.ResultConfidentialityRequired, "SASL confidentiality required")
	})

	t.Run("SASL Bind only checks transport and TLS", func(t *testing.T) {
		state := &connectionState{
			runtime: &runtimeState{
				security: securityStrengthRequirements{
					sasl:       100,
					overall:    100,
					simpleBind: 100,
				},
				requires: requireAuthentication | requireBind | requireSASL,
			},
		}
		assertNoSecurityResult(t, operationSecurityResult(state, nil, policySASLBind))
	})

	t.Run("anonymous Bind only checks transport and TLS", func(t *testing.T) {
		state := &connectionState{
			runtime: &runtimeState{
				security: securityStrengthRequirements{
					sasl:       100,
					overall:    100,
					simpleBind: 100,
				},
				requires: requireAuthentication | requireBind,
			},
		}
		assertNoSecurityResult(t, operationSecurityResult(state, nil, policyAnonymousBind))
		state.runtime.security.transport = 1
		assertSecurityResult(t, operationSecurityResult(state, nil, policyAnonymousBind),
			ldapwire.ResultConfidentialityRequired, "transport confidentiality required")
	})

	t.Run("unbound connection defaults to LDAPv3", func(t *testing.T) {
		state := &connectionState{runtime: &runtimeState{requires: requireLDAPv3}}
		assertNoSecurityResult(t, operationSecurityResult(state, nil, policyRead))
	})

	t.Run("unbound connection has not performed Bind", func(t *testing.T) {
		state := &connectionState{runtime: &runtimeState{requires: requireBind}}
		assertSecurityResult(t, operationSecurityResult(state, nil, policyRead),
			ldapwire.ResultOperationsError, "BIND required")
	})

	t.Run("anonymous or failed Bind satisfies bind requirement", func(t *testing.T) {
		state := &connectionState{
			protocolVersion: 3,
			runtime:         &runtimeState{requires: requireBind},
		}
		assertNoSecurityResult(t, operationSecurityResult(state, nil, policyRead))
	})

	t.Run("LDAPv2 Bind fails LDAPv3 requirement", func(t *testing.T) {
		state := &connectionState{
			protocolVersion: 2,
			runtime:         &runtimeState{requires: requireLDAPv3},
		}
		assertSecurityResult(t, operationSecurityResult(state, nil, policyRead),
			ldapwire.ResultOperationsError, "operation restricted to LDAPv3 clients")
	})

	t.Run("SASL authentication satisfies sasl requirement", func(t *testing.T) {
		state := &connectionState{
			boundDN:       "uid=user,dc=example,dc=com",
			authMechanism: "GSSAPI",
			runtime:       &runtimeState{requires: requireSASL},
		}
		assertNoSecurityResult(t, operationSecurityResult(state, nil, policyRead))
		state.authMechanism = "sImPlE"
		assertSecurityResult(t, operationSecurityResult(state, nil, policyRead),
			ldapwire.ResultStrongerAuthRequired, "SASL authentication required")
	})
}

func TestOperationSecurityAnonymousUpdate(t *testing.T) {
	state := &connectionState{runtime: &runtimeState{}}
	assertSecurityResult(t, testUpdateSecurityResult(state),
		ldapwire.ResultStrongerAuthRequired, "modifications require authentication")

	state.runtime.allows.anonymousUpdates = true
	assertNoSecurityResult(t, testUpdateSecurityResult(state))

	state.runtime.requires = requireAuthentication
	assertSecurityResult(t, testUpdateSecurityResult(state),
		ldapwire.ResultUnwillingToPerform, "authentication required")

	state.runtime.allows.anonymousUpdates = false
	assertSecurityResult(t, testUpdateSecurityResult(state),
		ldapwire.ResultStrongerAuthRequired, "modifications require authentication")

	state.boundDN = "uid=user,dc=example,dc=com"
	assertNoSecurityResult(t, testUpdateSecurityResult(state))
}

func TestBindPreDelegationEnforcesDatabaseSecurity(t *testing.T) {
	state := &connectionState{runtime: &runtimeState{
		databases: []runtimeDatabase{{
			name:     "{1}mdb",
			suffixes: []directory.DN{staticRuntimeDN("dc=example,dc=com")},
			security: securityStrengthRequirements{simpleBind: 1},
		}},
	}}
	result, controlsFirst := bindPreDelegationResult(state, ldapwire.BindRequest{
		Version: 3,
		Name:    "uid=alice,dc=example,dc=com",
		Authentication: ldapwire.Authentication{
			Simple: []byte("secret"),
		},
	})
	assertSecurityResult(
		t,
		result,
		ldapwire.ResultConfidentialityRequired,
		"confidentiality required",
	)
	if !controlsFirst {
		t.Fatal("security failure did not request control validation")
	}
	if state.protocolVersion != 3 {
		t.Fatalf("protocol version = %d, want 3", state.protocolVersion)
	}
}

func TestTransactionSecurityPrecedesStateAndValueDecoding(t *testing.T) {
	state := &connectionState{
		runtime: &runtimeState{
			security: securityStrengthRequirements{overall: 1},
			allows:   allowsRuntimeConfiguration{anonymousUpdates: true},
		},
		transaction: &ldapTransaction{identifier: []byte("active")},
	}
	for _, request := range []ldapwire.ExtendedRequest{
		{Name: transactionStartOID},
		{Name: transactionEndOID, HasValue: true, Value: []byte{0xff}},
	} {
		assertSecurityResult(
			t,
			extendedRequestSecurityResult(state, request),
			ldapwire.ResultConfidentialityRequired,
			"confidentiality required",
		)
	}
}

func TestOperationRequirementsOnlineReloadAndRollback(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)

	configuration, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial configuration connection: %v", err)
	}
	t.Cleanup(func() { configuration.Close() })
	if err := configuration.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("bind configuration connection: %v", err)
	}
	anonymous, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial anonymous connection: %v", err)
	}
	t.Cleanup(func() { anonymous.Close() })

	search := func() securityRequirementsResult {
		_, searchErr := anonymous.Search(ldap.NewSearchRequest(
			"",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"1.1"},
			nil,
		))
		return securityRequirementsResultFromError(searchErr)
	}
	assertSecurityObservation := func(want securityRequirementsResult) {
		t.Helper()
		if got := search(); got != want {
			t.Fatalf("Search result = %#v, want %#v", got, want)
		}
	}

	assertSecurityObservation(securityRequirementsResult{})
	modify := ldap.NewModifyRequest("cn=config", nil)
	modify.Add("olcRequires", []string{"bind"})
	if err := configuration.Modify(modify); err != nil {
		t.Fatalf("add olcRequires: %v", err)
	}
	assertSecurityObservation(securityRequirementsResult{
		code:       ldap.LDAPResultOperationsError,
		diagnostic: "BIND required",
	})

	if err := anonymous.UnauthenticatedBind(""); err != nil {
		t.Fatalf("anonymous Bind: %v", err)
	}
	assertSecurityObservation(securityRequirementsResult{})

	modify = ldap.NewModifyRequest("cn=config", nil)
	modify.Replace("olcRequires", []string{"authc"})
	if err := configuration.Modify(modify); err != nil {
		t.Fatalf("replace olcRequires: %v", err)
	}
	authenticationRequired := securityRequirementsResult{
		code:       ldap.LDAPResultUnwillingToPerform,
		diagnostic: "authentication required",
	}
	assertSecurityObservation(authenticationRequired)

	invalid := ldap.NewModifyRequest("cn=config", nil)
	invalid.Replace("olcRequires", []string{"authc none"})
	assertLDAPResultCode(
		t,
		configuration.Modify(invalid),
		ldap.LDAPResultOther,
	)
	assertSecurityObservation(authenticationRequired)

	invalidSecurity := ldap.NewModifyRequest("cn=config", nil)
	invalidSecurity.Add("olcSecurity", []string{"unknown=1"})
	assertLDAPResultCode(
		t,
		configuration.Modify(invalidSecurity),
		ldap.LDAPResultOther,
	)
	assertSecurityObservation(authenticationRequired)

	security := ldap.NewModifyRequest("cn=config", nil)
	security.Add("olcSecurity", []string{"ssf=1"})
	if err := configuration.Modify(security); err != nil {
		t.Fatalf("add olcSecurity: %v", err)
	}
	assertSecurityObservation(securityRequirementsResult{
		code:       ldap.LDAPResultConfidentialityRequired,
		diagnostic: "confidentiality required",
	})

	unsupported := ldap.NewAddRequest(
		"uid=unsupported,dc=example,dc=com",
		[]ldap.Control{ldap.NewControlString("1.2.3.4.5.6.7", true, "")},
	)
	assertLDAPResultCode(
		t,
		anonymous.Add(unsupported),
		ldap.LDAPResultUnavailableCriticalExtension,
	)
}

func testUpdateSecurityResult(state *connectionState) *ldapwire.Result {
	if result := operationSecurityResult(state, nil, policyUpdate); result != nil {
		return result
	}
	return updateOperationPrecondition(
		state.runtime,
		state.boundDN,
		staticRuntimeDN("dc=example,dc=com"),
	)
}

func assertSecurityResult(
	t *testing.T,
	result *ldapwire.Result,
	wantCode ldapwire.ResultCode,
	wantDiagnostic string,
) {
	t.Helper()
	if result == nil {
		t.Fatalf("security result = nil, want code %d diagnostic %q", wantCode, wantDiagnostic)
	}
	if result.Code != wantCode || result.DiagnosticMessage != wantDiagnostic {
		t.Fatalf(
			"security result = code %d diagnostic %q, want code %d diagnostic %q",
			result.Code,
			result.DiagnosticMessage,
			wantCode,
			wantDiagnostic,
		)
	}
}

func assertNoSecurityResult(t *testing.T, result *ldapwire.Result) {
	t.Helper()
	if result != nil {
		t.Fatalf("security result = %#v, want success", result)
	}
}
