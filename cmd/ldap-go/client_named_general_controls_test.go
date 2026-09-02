package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPNamedGeneralControlsEncodeOpenLDAPValues(t *testing.T) {
	t.Parallel()

	assertion := "(&(uid=alice)(objectClass=person))"
	specs := []string{
		"assert=" + assertion,
		"!authzid=dn:uid=alice,dc=example,dc=com",
		"!!manageDSAit",
		"!noop",
		"ppolicy",
		"preread=cn,,sn,",
		"!postread",
		"manageDIT",
		"sessiontracking=alice",
	}
	controls, err := parseLDAPGeneralControlSpecs(specs)
	if err != nil {
		t.Fatalf("parseLDAPGeneralControlSpecs(): %v", err)
	}
	defer clearLDAPControls(controls)
	if len(controls) != len(specs) {
		t.Fatalf("controls = %d, want %d", len(controls), len(specs))
	}

	assertionPacket, err := ldap.CompileFilter(assertion)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		oid         string
		critical    bool
		hasValue    bool
		value       []byte
		bindRequest bool
	}{
		{oid: ldapAssertionControlOID, hasValue: true, value: assertionPacket.Bytes()},
		{
			oid: ldapProxyAuthorizationControlOID, critical: true, hasValue: true,
			value: []byte("dn:uid=alice,dc=example,dc=com"),
		},
		{oid: ldap.ControlTypeManageDsaIT, critical: true},
		{oid: ldapNoOpControlOID, critical: true},
		{oid: ldap.ControlTypeBeheraPasswordPolicy, bindRequest: true},
		{
			oid: ldapControlPreRead, hasValue: true,
			value: []byte{0x30, 0x08, 0x04, 0x02, 'c', 'n', 0x04, 0x02, 's', 'n'},
		},
		{oid: ldapControlPostRead, critical: true, hasValue: true, value: []byte{0x30, 0x00}},
		{oid: ldapRelaxControlOID},
		{oid: ldapwire.SessionTrackingControlOID, hasValue: true, bindRequest: true},
	}
	for index, expected := range want {
		control := ldapNamedGeneralRawControl(t, controls[index])
		if control.oid != expected.oid || control.critical != expected.critical ||
			control.hasValue != expected.hasValue || control.bindRequest != expected.bindRequest {
			t.Errorf("control %d = %#v, want %#v", index, control, expected)
		}
		if expected.value != nil && !bytes.Equal(control.value, expected.value) {
			t.Errorf("control %s value = %x, want %x", control.oid, control.value, expected.value)
		}
	}

	session := ldapNamedGeneralRawControl(t, controls[len(controls)-1])
	decoded, formatOIDValid, err := ldapwire.DecodeSessionTrackingValue(session.value)
	if err != nil || !formatOIDValid {
		t.Fatalf("decode sessiontracking value: valid=%v err=%v", formatOIDValid, err)
	}
	if string(decoded.FormatOID) != ldapSessionTrackingUsernameFormatID ||
		string(decoded.SessionTrackingIdentifier) != "alice" {
		t.Fatalf("sessiontracking value = %#v", decoded)
	}
	if session.sessionTrackingDefault {
		t.Fatal("explicit sessiontracking username marked as default")
	}
}

func TestLDAPNamedGeneralControlCriticalityMatchesOpenLDAP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		spec     string
		critical bool
	}{
		{spec: "assert=(uid=alice)"},
		{spec: "!assert=(uid=alice)", critical: true},
		{spec: "!!assert=(uid=alice)", critical: true},
		{spec: "!authzid=u:alice", critical: true},
		{spec: "!!authzid=u:alice"},
		{spec: "!!!authzid=u:alice"},
		{spec: "manageDSAit"},
		{spec: "!!manageDSAit", critical: true},
		{spec: "noop"},
		{spec: "!noop", critical: true},
		{spec: "preread"},
		{spec: "!postread=cn", critical: true},
		{spec: "relax"},
		{spec: "!!manageDIT", critical: true},
	}
	for _, test := range tests {
		t.Run(test.spec, func(t *testing.T) {
			controls, err := parseLDAPGeneralControlSpecs([]string{test.spec})
			if err != nil {
				t.Fatalf("parseLDAPGeneralControlSpecs(): %v", err)
			}
			defer clearLDAPControls(controls)
			if control := ldapNamedGeneralRawControl(t, controls[0]); control.critical != test.critical {
				t.Fatalf("critical = %v, want %v", control.critical, test.critical)
			}
		})
	}
}

func TestLDAPNamedGeneralControlBindAndSessionDefaultMetadata(t *testing.T) {
	t.Parallel()

	controls, err := parseLDAPGeneralControlSpecs([]string{"sessiontracking"})
	if err != nil {
		t.Fatal(err)
	}
	defer clearLDAPControls(controls)
	control := ldapNamedGeneralRawControl(t, controls[0])
	if !control.bindRequest || !control.sessionTrackingDefault || !control.hasValue {
		t.Fatalf("default sessiontracking metadata = %#v", control)
	}
	value, valid, err := ldapwire.DecodeSessionTrackingValue(control.value)
	if err != nil || !valid || len(value.SessionTrackingIdentifier) != 0 ||
		string(value.FormatOID) != ldapSessionTrackingUsernameFormatID {
		t.Fatalf("default sessiontracking value = %#v, valid=%v err=%v", value, valid, err)
	}

	cloned := cloneLDAPControls(controls)
	defer clearLDAPControls(cloned)
	clone := ldapNamedGeneralRawControl(t, cloned[0])
	if !clone.bindRequest || !clone.sessionTrackingDefault || !bytes.Equal(clone.value, control.value) {
		t.Fatalf("cloned sessiontracking control = %#v", clone)
	}

	explicit, err := parseLDAPGeneralControlSpecs([]string{"sessiontracking="})
	if err != nil {
		t.Fatal(err)
	}
	defer clearLDAPControls(explicit)
	if raw := ldapNamedGeneralRawControl(t, explicit[0]); !raw.bindRequest || raw.sessionTrackingDefault {
		t.Fatalf("explicit empty sessiontracking metadata = %#v", raw)
	}

	for _, oid := range []string{
		ldap.ControlTypeBeheraPasswordPolicy,
		ldapwire.SessionTrackingControlOID,
	} {
		numeric, parseErr := parseLDAPGeneralControlSpecs([]string{oid})
		if parseErr != nil {
			t.Fatalf("parse numeric %s: %v", oid, parseErr)
		}
		raw := ldapNamedGeneralRawControl(t, numeric[0])
		if raw.bindRequest || raw.sessionTrackingDefault {
			t.Errorf("numeric control %s has named metadata: %#v", oid, raw)
		}
		clearLDAPControls(numeric)
	}
}

func TestLDAPNamedGeneralControlResolvesDefaultSessionIdentity(t *testing.T) {
	t.Parallel()

	controls, err := parseLDAPGeneralControlSpecs([]string{
		"sessiontracking",
		"ppolicy",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clearLDAPControls(controls)
	if err := resolveLDAPSessionTrackingDefaults(controls, "u:alice"); err != nil {
		t.Fatal(err)
	}
	value, valid, err := ldapwire.DecodeSessionTrackingValue(
		ldapNamedGeneralRawControl(t, controls[0]).value,
	)
	if err != nil || !valid || string(value.SessionTrackingIdentifier) != "u:alice" {
		t.Fatalf("resolved sessiontracking value = %#v, valid=%v err=%v", value, valid, err)
	}

	explicit, err := parseLDAPGeneralControlSpecs([]string{"sessiontracking=operator"})
	if err != nil {
		t.Fatal(err)
	}
	defer clearLDAPControls(explicit)
	if err := resolveLDAPSessionTrackingDefaults(explicit, "u:ignored"); err != nil {
		t.Fatal(err)
	}
	value, valid, err = ldapwire.DecodeSessionTrackingValue(
		ldapNamedGeneralRawControl(t, explicit[0]).value,
	)
	if err != nil || !valid || string(value.SessionTrackingIdentifier) != "operator" {
		t.Fatalf("explicit sessiontracking value = %#v, valid=%v err=%v", value, valid, err)
	}
}

func TestLDAPNamedGeneralControlDefaultSessionIdentityPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, bindDN, authentication, authorization, want string
	}{
		{name: "anonymous"},
		{name: "simple Bind DN", bindDN: "cn=admin", want: "cn=admin"},
		{
			name: "SASL authentication identity", bindDN: "cn=ignored",
			authentication: "alice", want: "alice",
		},
		{
			name: "SASL authorization identity", bindDN: "cn=ignored",
			authentication: "alice", authorization: "u:operator", want: "u:operator",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := &ldapClientOptions{
				bindDN:             test.bindDN,
				saslAuthentication: test.authentication,
				saslAuthorization:  test.authorization,
			}
			if got := options.sessionTrackingIdentifier(); got != test.want {
				t.Fatalf("sessionTrackingIdentifier() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestLDAPNamedGeneralControlsApplyToSASLBind(t *testing.T) {
	t.Parallel()

	messages := make(chan ldapwire.Message, 1)
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, bind := message.Request.(ldapwire.BindRequest); bind {
			messages <- message
			return nil, nil
		}
		return nil, fmt.Errorf("unexpected request %T", message.Request)
	})
	connection, err := net.Dial("tcp", strings.TrimPrefix(fixture.uri, "ldap://"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	options := ldapClientOptions{}
	options.generalControls, err = parseLDAPGeneralControlSpecs([]string{
		"ppolicy",
		"sessiontracking=alice",
		"assert=(uid=alice)",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer options.clear()
	result, err := options.exchangeLDAPClientSASLBind(
		connection,
		1,
		"PLAIN",
		[]byte("\x00alice\x00secret"),
		true,
	)
	if err != nil || result.code != ldap.LDAPResultSuccess {
		t.Fatalf("SASL Bind = %#v, %v", result, err)
	}
	message := awaitLDAPClientWireMessage(t, messages)
	want, err := ldapRawControlsToWire(ldapBindRequestControls(options.generalControls))
	if err != nil {
		t.Fatal(err)
	}
	if gotSignatures, wantSignatures := ldapNamedGeneralWireSignatures(message.Controls),
		ldapNamedGeneralWireSignatures(want); !slices.Equal(gotSignatures, wantSignatures) {
		t.Fatalf("SASL Bind controls = %q, want %q", gotSignatures, wantSignatures)
	}
}

func TestLDAPNamedGeneralControlsRejectDuplicatesByOID(t *testing.T) {
	t.Parallel()

	tests := [][]string{
		{"relax", "manageDIT"},
		{"NOOP", "noop"},
		{"noop", ldapNoOpControlOID},
		{"ppolicy", ldap.ControlTypeBeheraPasswordPolicy},
		{"sessiontracking=alice", ldapwire.SessionTrackingControlOID},
		{"manageDSAit", ldap.ControlTypeManageDsaIT},
	}
	for _, specs := range tests {
		t.Run(strings.Join(specs, "+"), func(t *testing.T) {
			controls, err := parseLDAPGeneralControlSpecs(specs)
			clearLDAPControls(controls)
			if err == nil || !strings.Contains(err.Error(), "more than once") {
				t.Fatalf("parseLDAPGeneralControlSpecs(%q) error = %v", specs, err)
			}
		})
	}
}

func TestLDAPNamedGeneralControlsValidateParameters(t *testing.T) {
	t.Parallel()

	invalid := []string{
		"assert",
		"assert=",
		"assert=(uid=alice",
		"authzid=u:alice",
		"!authzid",
		"manageDSAit=",
		"noop=value",
		"ppolicy=",
		"!ppolicy",
		"relax=",
		"manageDIT=value",
		"!sessiontracking",
		"unknownControl",
	}
	for _, spec := range invalid {
		t.Run(spec, func(t *testing.T) {
			controls, err := parseLDAPGeneralControlSpecs([]string{spec})
			clearLDAPControls(controls)
			if err == nil {
				t.Fatalf("parseLDAPGeneralControlSpecs(%q) succeeded", spec)
			}
		})
	}

	controls, err := parseLDAPGeneralControlSpecs([]string{"preread=,cn,, sn ,"})
	if err != nil {
		t.Fatal(err)
	}
	defer clearLDAPControls(controls)
	want := []byte{0x30, 0x0a, 0x04, 0x02, 'c', 'n', 0x04, 0x04, ' ', 's', 'n', ' '}
	if got := ldapNamedGeneralRawControl(t, controls[0]).value; !bytes.Equal(got, want) {
		t.Fatalf("preread value = %x, want %x", got, want)
	}
}

func TestOpenLDAPReferenceNamedGeneralControls(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") == "" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 to run OpenLDAP control differential")
	}
	referenceTool, err := exec.LookPath("ldapsearch")
	if err != nil {
		t.Fatal(err)
	}
	version, err := exec.Command(referenceTool, "-VV").CombinedOutput()
	if err != nil || !bytes.Contains(version, []byte("ldapsearch 2.6.13")) {
		t.Fatalf("OpenLDAP reference must be ldapsearch 2.6.13: %v\n%s", err, version)
	}

	messages := make(chan ldapwire.Message, 4)
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		switch message.Request.(type) {
		case ldapwire.BindRequest:
			messages <- message
			return nil, nil
		case ldapwire.SearchRequest:
			messages <- message
			return [][]byte{ldapwire.EncodeSearchResultDone(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			)}, nil
		default:
			return nil, nil
		}
	})
	specs := []string{
		"assert=(uid=alice)",
		"!authzid=u:alice",
		"manageDSAit",
		"!noop",
		"ppolicy",
		"preread=cn,,sn,",
		"!postread",
		"relax",
		"sessiontracking=alice",
	}
	arguments := []string{"-H", fixture.uri, "-x"}
	for _, spec := range specs {
		arguments = append(arguments, "-e", spec)
	}
	arguments = append(arguments, "-LLL", "-b", "", "-s", "base", "(objectClass=*)", "1.1")
	if output, commandErr := exec.Command(referenceTool, arguments...).CombinedOutput(); commandErr != nil {
		t.Fatalf("OpenLDAP ldapsearch: %v\n%s", commandErr, output)
	}
	readRequests := func() (ldapwire.Message, ldapwire.Message) {
		var bindMessage, searchMessage ldapwire.Message
		for range 2 {
			message := awaitLDAPClientWireMessage(t, messages)
			switch message.Request.(type) {
			case ldapwire.BindRequest:
				bindMessage = message
			case ldapwire.SearchRequest:
				searchMessage = message
			}
		}
		return bindMessage, searchMessage
	}
	referenceBind, referenceSearch := readRequests()
	stdout, stderr, code := runLDAPClientCommand(
		append([]string{"ldapsearch"}, arguments...),
		"",
	)
	if code != 0 || stdout != "" || stderr != "" {
		t.Fatalf("ldap-go ldapsearch=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	implementationBind, implementationSearch := readRequests()

	for name, pair := range map[string][2]ldapwire.Message{
		"bind":   {implementationBind, referenceBind},
		"search": {implementationSearch, referenceSearch},
	} {
		got := ldapNamedGeneralWireSignatures(pair[0].Controls)
		want := ldapNamedGeneralWireSignatures(pair[1].Controls)
		if !slices.Equal(got, want) {
			t.Fatalf("%s controls:\nldap-go:  %q\nOpenLDAP: %q", name, got, want)
		}
	}

	for _, message := range []ldapwire.Message{
		referenceBind,
		referenceSearch,
		implementationBind,
		implementationSearch,
	} {
		if message.Request == nil {
			t.Fatal("named control differential did not observe every Bind/Search request")
		}
	}
}

func ldapNamedGeneralRawControl(t *testing.T, control ldap.Control) *ldapRawControl {
	t.Helper()
	raw, ok := control.(*ldapRawControl)
	if !ok {
		t.Fatalf("control has type %T", control)
	}
	return raw
}

func ldapNamedGeneralWireSignatures(controls []ldapwire.Control) []string {
	signatures := make([]string, 0, len(controls))
	for _, control := range controls {
		signatures = append(signatures, fmt.Sprintf(
			"%s|%t|%t|%s",
			control.OID,
			control.Critical,
			control.HasValue,
			hex.EncodeToString(control.Value),
		))
	}
	sort.Strings(signatures)
	return signatures
}
