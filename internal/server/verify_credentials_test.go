package server

import (
	"bytes"
	"context"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const vcTestAliceDN = "uid=alice,ou=people,dc=example,dc=com"

// Keep the independently observed native corpus in ordinary CI too; the
// opt-in differential additionally builds and executes the actual C server.
func TestVerifyCredentialsNativeCorpus(t *testing.T) {
	for _, config := range []vcReferenceOptions{
		{name: "without-authzid"}, {name: "with-authzid", authzid: true},
		{name: "simple-bind-ssf", authzid: true, requireTLS: true},
	} {
		t.Run(config.name, func(t *testing.T) {
			address, tlsConfig := vcReferenceGoServer(t, config, vcReferenceSeed(time.Now()))
			vcReferenceCheckServer(t, address, tlsConfig, config)
		})
	}
}

func vcTestStore(t *testing.T, enabled bool) storage.Store {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if enabled {
		if err := store.Update(t.Context(), func(writer storage.Writer) error {
			return writer.Put(directory.Entry{DN: "cn=module{0},cn=config", Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcModuleList")},
				{Description: "cn", Values: stringValues("module{0}")},
				{Description: "olcModuleLoad", Values: stringValues("vc.la")},
			}}, false)
		}); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func vcTestRequest(dn, password string) []byte {
	value := ber.NewSequence("VC")
	value.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "DN"))
	value.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, password, "simple"))
	return value.Bytes()
}

func TestVerifyCredentialsModuleAndConnectionIdentity(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			store := vcTestStore(t, enabled)
			address, stop := startServer(t, store, Config{})
			defer stop()
			client, err := ldap.DialURL("ldap://" + address)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.SetTimeout(3 * time.Second)
			if err := client.Bind(vcTestAliceDN, "secret"); err != nil {
				t.Fatal(err)
			}
			root, err := client.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
				0, 0, false, "(objectClass=*)", []string{"supportedExtension"}, nil))
			if err != nil {
				t.Fatal(err)
			}
			for _, oid := range root.Entries[0].GetAttributeValues("supportedExtension") {
				if oid == ldapwire.VerifyCredentialsOID {
					t.Fatal("VC must remain hidden like SLAP_EXOP_HIDE")
				}
			}
			for _, test := range []struct {
				name, dn, password string
				code               uint16
			}{
				{"correct", vcTestAliceDN, "secret", 0},
				{"wrong", vcTestAliceDN, "wrong", 49},
				{"missing", "uid=missing,ou=people,dc=example,dc=com", "secret", 49},
				{"anonymous", "", "", 0},
				{"empty password", vcTestAliceDN, "", 53},
			} {
				t.Run(test.name, func(t *testing.T) {
					value := ber.NewString(ber.ClassContext, ber.TypePrimitive, 1,
						string(vcTestRequest(test.dn, test.password)), "requestValue")
					response, err := client.Extended(ldap.NewExtendedRequest(ldapwire.VerifyCredentialsOID, value))
					if !enabled {
						if !ldap.IsErrorWithCode(err, ldap.LDAPResultProtocolError) {
							t.Fatalf("disabled VC: %v", err)
						}
					} else if test.code != 0 {
						if !ldap.IsErrorWithCode(err, test.code) {
							t.Fatalf("VC result: %v, want %d", err, test.code)
						}
					} else {
						if err != nil || response == nil || response.Value == nil {
							t.Fatalf("VC response: %+v %v", response, err)
						}
					}
					identity, err := client.WhoAmI(nil)
					if err != nil || identity.AuthzID != "dn:"+vcTestAliceDN {
						t.Fatalf("VC changed caller: %+v %v", identity, err)
					}
				})
			}
		})
	}
}

func TestVerifyCredentialsPreservesOuterStateAndRejectsMalformed(t *testing.T) {
	store := vcTestStore(t, true)
	server, err := New(Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	defer server.closeSQLBackends()
	state := &connectionState{runtime: server.runtime.Load(), boundDN: vcTestAliceDN,
		protocolVersion: 3, secure: true, externalSSF: 256, tlsSSF: 256,
		bindCredentialDN: vcTestAliceDN, bindCredentials: []byte("outer-password")}
	for _, value := range [][]byte{nil, {0x30, 0}, {0x30, 2, 4, 0}, vcTestRequest("invalid=dn,", "secret")} {
		capture := &verifyCredentialsResponseCapture{}
		request := ldapwire.ExtendedRequest{Name: ldapwire.VerifyCredentialsOID, Value: value, HasValue: value != nil}
		message := ldapwire.Message{ID: 1, Request: request}
		if err := server.handleVerifyCredentials(context.Background(), capture, state, message, request); err != nil {
			t.Fatal(err)
		}
		packet, err := ber.DecodePacketErr(capture.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		response, err := parseSyncConsumerLDAPResult(packet, 1, ldapwire.ApplicationExtendedResponse)
		if err != nil || response.code != ldap.LDAPResultProtocolError {
			t.Fatalf("malformed VC: %+v %v", response, err)
		}
		if state.boundDN != vcTestAliceDN || state.externalSSF != 256 || !state.secure ||
			!bytes.Equal(state.bindCredentials, []byte("outer-password")) {
			t.Fatal("VC mutated caller state")
		}
	}
}

func TestVerifyCredentialsPasswordPolicyLockout(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(t, store, []directory.Attribute{
		{Description: "pwdLockout", Values: stringValues("TRUE")},
		{Description: "pwdLockoutDuration", Values: stringValues("0")},
		{Description: "pwdMaxFailure", Values: stringValues("2")},
	}, []directory.Attribute{{Description: "olcPPolicyUseLockout", Values: stringValues("TRUE")}})
	server, err := New(Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	defer server.closeSQLBackends()
	state := &connectionState{runtime: server.runtime.Load(), boundDN: "cn=caller,dc=example,dc=com", protocolVersion: 3}
	for _, password := range []string{"wrong-one", "wrong-two", "secret"} {
		value, err := ber.DecodePacketErr(vcTestRequest(vcTestAliceDN, password))
		if err != nil {
			t.Fatal(err)
		}
		wrapper := ber.Encode(ber.ClassContext, ber.TypeConstructed, 2, nil, "controls")
		control := ber.NewSequence("control")
		control.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, passwordPolicyControlOID, "oid"))
		wrapper.AppendChild(control)
		value.AppendChild(wrapper)
		request := ldapwire.ExtendedRequest{Name: ldapwire.VerifyCredentialsOID, Value: value.Bytes(), HasValue: true}
		capture := &verifyCredentialsResponseCapture{}
		if err := server.handleVerifyCredentials(t.Context(), capture, state, ldapwire.Message{ID: 1, Request: request}, request); err != nil {
			t.Fatal(err)
		}
		packet, err := ber.DecodePacketErr(capture.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		result, err := parseSyncConsumerLDAPResult(packet, 1, ldapwire.ApplicationExtendedResponse)
		if err != nil || result.code != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("policy result: %+v %v", result, err)
		}
		if state.boundDN != "cn=caller,dc=example,dc=com" || state.passwordPolicyRestrictedDN != "" {
			t.Fatal("policy state leaked to caller")
		}
		if password == "secret" {
			inner, err := ber.DecodePacketErr(result.responseValue)
			if err != nil || len(inner.Children) != 3 || inner.Children[2].Tag != 2 {
				t.Fatalf("missing nested ppolicy response: %v", err)
			}
			policyBytes := inner.Children[2].Children[0].Children[1].Data.Bytes()
			decoded, err := ldap.DecodeControl(inner.Children[2].Children[0])
			if err != nil || len(policyBytes) == 0 {
				t.Fatalf("invalid ppolicy control: %v", err)
			}
			policy, ok := decoded.(*ldap.ControlBeheraPasswordPolicy)
			if !ok || policy.Error != ldap.BeheraAccountLocked {
				t.Fatalf("lockout control: %#v", decoded)
			}
		}
	}
	if !readStoredEntry(t, store, vcTestAliceDN).HasAttribute("pwdAccountLockedTime") {
		t.Fatal("VC did not persist account lockout")
	}
}

func TestVerifyCredentialsDoesNotInheritTransportSecurity(t *testing.T) {
	store := vcTestStore(t, true)
	server, err := New(Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	defer server.closeSQLBackends()
	runtime := server.runtime.Load()
	// A synthetic VC connection has zero SSF even when the outer client uses TLS.
	runtime.security.simpleBind = 128
	state := &connectionState{runtime: runtime, protocolVersion: 3, boundDN: vcTestAliceDN,
		secure: true, externalSSF: 256, tlsSSF: 256}
	request := ldapwire.ExtendedRequest{Name: ldapwire.VerifyCredentialsOID, Value: vcTestRequest(vcTestAliceDN, "secret"), HasValue: true}
	capture := &verifyCredentialsResponseCapture{}
	if err := server.handleVerifyCredentials(t.Context(), capture, state, ldapwire.Message{ID: 1, Request: request}, request); err != nil {
		t.Fatal(err)
	}
	packet, err := ber.DecodePacketErr(capture.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	result, err := parseSyncConsumerLDAPResult(packet, 1, ldapwire.ApplicationExtendedResponse)
	if err != nil || result.code != ldap.LDAPResultConfidentialityRequired {
		t.Fatalf("transport security bypass: %+v %v", result, err)
	}
	if state.boundDN != vcTestAliceDN || state.externalSSF != 256 {
		t.Fatal("outer TLS state changed")
	}
}

func TestVerifyCredentialsAccesslogExcludesPassword(t *testing.T) {
	server := &Server{}
	entry := directory.Entry{DN: "reqStart=20260912000000Z,cn=log"}
	request := ldapwire.ExtendedRequest{Name: ldapwire.VerifyCredentialsOID,
		Value: vcTestRequest(vcTestAliceDN, "must-not-be-logged"), HasValue: true}
	err := server.populateObservedAccesslogRequest(nil, &runtimeState{}, runtimeDatabase{},
		&accesslogRuntimeConfiguration{}, &operationAuditObservation{message: ldapwire.Message{Request: request}},
		accesslogExtended, directory.DN{}, &entry)
	if err != nil {
		t.Fatal(err)
	}
	if entry.HasAttribute("reqData") {
		t.Fatal("accesslog captured credential-bearing VC request data")
	}
}
