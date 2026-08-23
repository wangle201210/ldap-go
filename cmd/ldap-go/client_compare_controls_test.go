package main

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPCompareGenericAndManageDsaITControls(t *testing.T) {
	const dn = "uid=alice,dc=example,dc=com"
	for _, test := range []struct {
		name     string
		options  []string
		oid      string
		critical bool
		hasValue bool
		value    []byte
	}{
		{
			name:     "generic",
			options:  []string{"-e", "!1.2.3=:compare-control"},
			oid:      "1.2.3",
			critical: true,
			hasValue: true,
			value:    []byte("compare-control"),
		},
		{
			name:    "noncritical ManageDsaIT",
			options: []string{"-M"},
			oid:     ldapManageDsaITOID,
		},
		{
			name:     "critical ManageDsaIT",
			options:  []string{"-MM"},
			oid:      ldapManageDsaITOID,
			critical: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := make(chan ldapwire.Message, 1)
			fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
				if _, ok := message.Request.(ldapwire.CompareRequest); !ok {
					return nil, nil
				}
				requests <- message
				return [][]byte{ldapwire.EncodeResultResponse(
					message.ID,
					ldapwire.ApplicationCompareResponse,
					ldapwire.Result{Code: ldapwire.ResultCompareTrue},
					nil,
				)}, nil
			})

			args := []string{"ldapcompare", "-H", fixture.uri, "-x"}
			args = append(args, test.options...)
			args = append(args, dn, "uid:alice")
			stdout, stderr, exitCode := runLDAPClientCommand(args, "")
			if exitCode != ldap.LDAPResultCompareTrue || stdout != "TRUE\n" || stderr != "" {
				t.Fatalf("ldapcompare exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
			}
			message := awaitLDAPClientWireMessage(t, requests)
			request := message.Request.(ldapwire.CompareRequest)
			if request.DN != dn || request.Attribute != "uid" ||
				!bytes.Equal(request.Assertion, []byte("alice")) {
				t.Fatalf("Compare request = %#v", request)
			}
			if len(message.Controls) != 1 {
				t.Fatalf("Compare controls = %#v", message.Controls)
			}
			assertLDAPWireControl(
				t,
				message.Controls,
				test.oid,
				test.critical,
				test.hasValue,
				test.value,
			)
		})
	}

	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapcompare", "-n", "-M", "-MM", dn, "uid:alice",
	}, "")
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "cannot be combined") {
		t.Fatalf("duplicate ManageDsaIT exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	stdout, stderr, exitCode = runLDAPClientCommand([]string{
		"ldapcompare", "-n", "-M", "-e", ldapManageDsaITOID, dn, "uid:alice",
	}, "")
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "more than once") {
		t.Fatalf("duplicate control exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPCompareCriticalControlResultAndReferral(t *testing.T) {
	const (
		sourceDN = "uid=source,dc=example,dc=com"
		targetDN = "uid=target,dc=example,dc=com"
	)
	unsupported := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.CompareRequest); !ok {
			return nil, nil
		}
		return [][]byte{ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationCompareResponse,
			ldapwire.Result{
				Code:              ldapwire.ResultUnavailableCriticalExtension,
				DiagnosticMessage: "critical compare control is unavailable",
			},
			nil,
		)}, nil
	})
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapcompare", "-H", unsupported.uri, "-x",
		"-e", "!1.2.3", sourceDN, "uid:source",
	}, "")
	if exitCode != ldap.LDAPResultUnavailableCriticalExtension || stdout != "" ||
		!strings.Contains(stderr, "critical compare control is unavailable") {
		t.Fatalf("critical control exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	providerRequests := make(chan ldapwire.Message, 1)
	provider := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.CompareRequest); !ok {
			return nil, nil
		}
		providerRequests <- message
		return [][]byte{ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationCompareResponse,
			ldapwire.Result{Code: ldapwire.ResultCompareTrue},
			nil,
		)}, nil
	})
	referralURL := provider.uri + "/" + url.PathEscape(targetDN)
	source := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.CompareRequest); !ok {
			return nil, nil
		}
		return [][]byte{ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationCompareResponse,
			ldapwire.Result{
				Code:      ldapwire.ResultReferral,
				Referrals: []string{referralURL},
			},
			nil,
		)}, nil
	})
	stdout, stderr, exitCode = runLDAPClientCommand([]string{
		"ldapcompare", "-H", source.uri, "-x", "-C",
		"-e", "1.2.3=:referred", sourceDN, "uid:target",
	}, "")
	if exitCode != ldap.LDAPResultCompareTrue || stdout != "TRUE\n" || stderr != "" {
		t.Fatalf("referred compare exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	message := awaitLDAPClientWireMessage(t, providerRequests)
	request := message.Request.(ldapwire.CompareRequest)
	if request.DN != targetDN || request.Attribute != "uid" ||
		!bytes.Equal(request.Assertion, []byte("target")) {
		t.Fatalf("referred Compare request = %#v", request)
	}
	assertLDAPWireControl(
		t,
		message.Controls,
		"1.2.3",
		false,
		true,
		[]byte("referred"),
	)
}

func TestLDAPCompareControlsPreserveSASLPlain(t *testing.T) {
	const password = "compare-sasl-secret"
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		switch request := message.Request.(type) {
		case ldapwire.BindRequest:
			if !request.Authentication.IsSASL || request.Authentication.SASLMechanism != "PLAIN" ||
				!bytes.Equal(
					request.Authentication.SASLCredentials,
					[]byte("\x00alice\x00"+password),
				) {
				return nil, fmt.Errorf("unexpected PLAIN bind request: %#v", request)
			}
			return [][]byte{ldapwire.EncodeBindResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			)}, nil
		case ldapwire.CompareRequest:
			if len(message.Controls) != 1 || message.Controls[0].OID != ldapManageDsaITOID {
				return nil, fmt.Errorf("unexpected Compare controls: %#v", message.Controls)
			}
			return [][]byte{ldapwire.EncodeResultResponse(
				message.ID,
				ldapwire.ApplicationCompareResponse,
				ldapwire.Result{Code: ldapwire.ResultCompareFalse},
				nil,
			)}, nil
		default:
			return nil, fmt.Errorf("unexpected request %T", message.Request)
		}
	})
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapcompare", "-H", fixture.uri,
		"-Y", "PLAIN", "-U", "alice", "-w", password,
		"-MM", "uid=alice,dc=example,dc=com", "uid:bob",
	}, "")
	if exitCode != ldap.LDAPResultCompareFalse || stdout != "FALSE\n" || stderr != "" {
		t.Fatalf("SASL Compare exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if strings.Contains(stdout, password) || strings.Contains(stderr, password) {
		t.Fatalf("SASL Compare leaked its password: stdout=%q stderr=%q", stdout, stderr)
	}
}
