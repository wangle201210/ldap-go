package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPClientURIListSimpleBindFailover(t *testing.T) {
	goodURI := startLDAPClientToolServer(t, nil)
	uriList := unavailableLDAPClientURI(t) + " " + goodURI

	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapwhoami", "-H", uriList, "-x",
		"-D", clientToolRootDN, "-w", clientToolRootPassword,
	}, "")
	if exitCode != 0 || stdout != "dn:"+clientToolRootDN+"\n" || stderr != "" {
		t.Fatalf("failover ldapwhoami exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	stdout, stderr, exitCode = runLDAPClientCommand([]string{
		"ldapwhoami", "-H", unavailableLDAPClientURI(t) + "," + goodURI, "-x",
	}, "")
	if exitCode != 0 || stdout != "anonymous\n" || stderr != "" {
		t.Fatalf("comma failover exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}

	stdout, stderr, exitCode = runLDAPClientCommand([]string{
		"ldapsearch", "-H", uriList, "-x", "-b", "", "-s", "base", "-LLL",
		"(objectClass=*)", "namingContexts",
	}, "")
	if exitCode != 0 || stderr != "" ||
		!strings.Contains(stdout, "namingContexts: "+clientToolBaseDN) {
		t.Fatalf("observed search failover exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPClientURIListStopsAfterUnavailableBind(t *testing.T) {
	var fallbackBinds atomic.Int32
	first := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.BindRequest); !ok {
			return nil, fmt.Errorf("unexpected request before failover: %T", message.Request)
		}
		return [][]byte{ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultUnavailable},
			nil,
		)}, nil
	})
	fallback := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.BindRequest); ok {
			fallbackBinds.Add(1)
		}
		return nil, fmt.Errorf("unexpected request after unavailable result: %T", message.Request)
	})

	_, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapwhoami", "-H", first.uri + " " + fallback.uri, "-x",
	}, "")
	if exitCode == 0 || !strings.Contains(stderr, "Unavailable") {
		t.Fatalf("unavailable bind exit=%d stderr=%q", exitCode, stderr)
	}
	if got := fallbackBinds.Load(); got != 0 {
		t.Fatalf("fallback received %d binds after LDAP unavailable result", got)
	}
}

func TestLDAPClientURIListStopsAfterInvalidCredentials(t *testing.T) {
	second := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.BindRequest); !ok {
			return nil, fmt.Errorf("unexpected request: %T", message.Request)
		}
		return [][]byte{ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultInvalidCredentials},
			nil,
		)}, nil
	})
	var thirdBinds atomic.Int32
	third := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.BindRequest); ok {
			thirdBinds.Add(1)
			return [][]byte{ldapwire.EncodeBindResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			)}, nil
		}
		return nil, fmt.Errorf("unexpected request: %T", message.Request)
	})

	_, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapwhoami", "-H", unavailableLDAPClientURI(t) + " " + second.uri + " " + third.uri, "-x",
		"-D", clientToolRootDN, "-w", "wrong-password",
	}, "")
	if exitCode == 0 || !strings.Contains(stderr, "Invalid Credentials") {
		t.Fatalf("invalid bind exit=%d stderr=%q", exitCode, stderr)
	}
	if got := thirdBinds.Load(); got != 0 {
		t.Fatalf("third endpoint received %d binds after deterministic rejection", got)
	}
}

func TestLDAPClientURIListCompareAndSASLFailover(t *testing.T) {
	t.Run("raw compare", func(t *testing.T) {
		goodURI := startLDAPClientToolServer(t, nil)
		stdout, stderr, exitCode := runLDAPClientCommand([]string{
			"ldapcompare", "-H", unavailableLDAPClientURI(t) + " " + goodURI,
			"-x", "uid=alice," + clientToolPeopleDN, "uid:alice",
		}, "")
		if exitCode != int(ldap.LDAPResultCompareTrue) || stdout != "TRUE\n" || stderr != "" {
			t.Fatalf("compare failover exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
		}
	})

	t.Run("SASL PLAIN", func(t *testing.T) {
		const password = "uri-list-password"
		fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
			switch request := message.Request.(type) {
			case ldapwire.BindRequest:
				if !request.Authentication.IsSASL ||
					request.Authentication.SASLMechanism != "PLAIN" {
					return nil, fmt.Errorf("unexpected SASL bind: %#v", request)
				}
				return [][]byte{ldapwire.EncodeBindResponse(
					message.ID,
					ldapwire.Result{Code: ldapwire.ResultSuccess},
					nil,
				)}, nil
			case ldapwire.ExtendedRequest:
				return [][]byte{ldapwire.EncodeExtendedResponse(
					message.ID,
					ldapwire.Result{Code: ldapwire.ResultSuccess},
					ldapWhoAmIOID,
					[]byte("dn:uid=plain,dc=example,dc=com"),
					nil,
				)}, nil
			default:
				return nil, fmt.Errorf("unexpected request: %T", message.Request)
			}
		})
		stdout, stderr, exitCode := runLDAPClientCommand([]string{
			"ldapwhoami", "-H", unavailableLDAPClientURI(t) + " " + fixture.uri,
			"-Y", "PLAIN", "-U", "plain", "-w", password,
		}, "")
		if exitCode != 0 || stdout != "dn:uid=plain,dc=example,dc=com\n" || stderr != "" {
			t.Fatalf("SASL failover exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
		}
	})
}

func TestLDAPClientURIListTLSFailover(t *testing.T) {
	serverTLS, certificatePEM := newLDAPClientToolTLSConfig(t)
	startTLSURI := startLDAPClientToolServer(t, serverTLS)
	startLDAPS := func(t *testing.T) string {
		return startLDAPClientTLSWireFixture(t, serverTLS.Clone(), func(message ldapwire.Message) ([][]byte, error) {
			switch message.Request.(type) {
			case ldapwire.BindRequest:
				return [][]byte{ldapwire.EncodeBindResponse(
					message.ID,
					ldapwire.Result{Code: ldapwire.ResultSuccess},
					nil,
				)}, nil
			case ldapwire.ExtendedRequest:
				return [][]byte{ldapwire.EncodeExtendedResponse(
					message.ID,
					ldapwire.Result{Code: ldapwire.ResultSuccess},
					ldapWhoAmIOID,
					[]byte(""),
					nil,
				)}, nil
			case ldapwire.UnbindRequest:
				return nil, nil
			default:
				return nil, fmt.Errorf("unexpected LDAPS request: %T", message.Request)
			}
		})
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, certificatePEM, 0o600); err != nil {
		t.Fatalf("write test CA: %v", err)
	}

	tests := []struct {
		name    string
		uriList func(*testing.T) string
		extra   []string
	}{
		{
			name: "LDAPS",
			uriList: func(t *testing.T) string {
				return strings.Replace(unavailableLDAPClientURI(t), "ldap://", "ldaps://", 1) +
					" " + startLDAPS(t)
			},
		},
		{
			name: "required StartTLS",
			uriList: func(t *testing.T) string {
				return unavailableLDAPClientURI(t) + " " + startTLSURI
			},
			extra: []string{"-ZZ"},
		},
		{
			name: "mixed LDAP and LDAPS",
			uriList: func(t *testing.T) string {
				return unavailableLDAPClientURI(t) + " " + startLDAPS(t)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := []string{
				"ldapwhoami", "-H", test.uriList(t), "-x", "-tls-ca", caPath,
			}
			args = append(args, test.extra...)
			stdout, stderr, exitCode := runLDAPClientCommand(args, "")
			if exitCode != 0 || stdout != "anonymous\n" || stderr != "" {
				t.Fatalf("TLS failover exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
			}
		})
	}
}

func TestLDAPClientURIListIsValidatedBeforeConnecting(t *testing.T) {
	var binds atomic.Int32
	first := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.BindRequest); ok {
			binds.Add(1)
		}
		return nil, fmt.Errorf("unexpected request: %T", message.Request)
	})

	_, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapwhoami", "-H", first.uri + " not-an-ldap-uri", "-x",
	}, "")
	if exitCode == 0 || !strings.Contains(stderr, "URI 2") {
		t.Fatalf("invalid URI list exit=%d stderr=%q", exitCode, stderr)
	}
	if got := binds.Load(); got != 0 {
		t.Fatalf("first endpoint received %d binds before full URI validation", got)
	}
}

func TestLDAPClientURIListValidationAndSearchURL(t *testing.T) {
	flags := flag.NewFlagSet("ldapwhoami", flag.ContinueOnError)
	var options ldapClientOptions
	options.register(flags)
	if err := flags.Parse([]string{"-H", "ldap://first.example ldap://second.example", "-x"}); err != nil {
		t.Fatal(err)
	}
	endpoints, err := options.connectionConfigurations(flags)
	if err != nil || len(endpoints) != 2 ||
		endpoints[0].dialURI != "ldap://first.example" ||
		endpoints[1].dialURI != "ldap://second.example" {
		t.Fatalf("connectionConfigurations() = %#v, %v", endpoints, err)
	}
	options.uri = "ldap://first.example,ldap://second.example ldap://third.example"
	endpoints, err = options.connectionConfigurations(flags)
	if err != nil || len(endpoints) != 3 ||
		endpoints[0].dialURI != "ldap://first.example" ||
		endpoints[1].dialURI != "ldap://second.example" ||
		endpoints[2].dialURI != "ldap://third.example" {
		t.Fatalf("comma connectionConfigurations() = %#v, %v", endpoints, err)
	}
	direct, err := parseLDAPSearchDirectURL(
		"ldap:///dc=example,dc=com??sub?(objectClass=*)",
	)
	if err != nil || !direct.direct || direct.baseDN != "dc=example,dc=com" {
		t.Fatalf("direct URL with DN comma = %#v, %v", direct, err)
	}
	if direct, err := parseLDAPSearchDirectURL(
		"ldap://first.example,ldap://second.example",
	); err != nil || direct.direct {
		t.Fatalf("comma URI list direct detection = %#v, %v", direct, err)
	}
	if _, err := parseLDAPSearchDirectURL(
		"ldap://first.example/dc=example,dc=com ldap://second.example",
	); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("multi-URI search URL error = %v", err)
	}

	tooMany := strings.TrimSpace(strings.Repeat("ldap://example.test ", maxLDAPClientURIs+1))
	if _, err := parseLDAPClientURIList(tooMany); err == nil {
		t.Fatal("URI list above the endpoint bound was accepted")
	}
}

func TestLDAPHealthURIListReportsSelectedEndpoint(t *testing.T) {
	goodURI := startLDAPHealthTestServer(t)
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"health", "-H", unavailableLDAPClientURI(t) + " " + goodURI,
		"-x", "-D", clientToolRootDN, "-w", clientToolRootPassword, "-json",
	}, "")
	if exitCode != 0 || stderr != "" || !strings.Contains(stdout, `"endpoint":"`+goodURI+`"`) {
		t.Fatalf("health failover exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func unavailableLDAPClientURI(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve unavailable LDAP address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close unavailable LDAP address: %v", err)
	}
	return "ldap://" + address
}
