package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
	"github.com/xdg-go/scram"
)

func TestLDAPClientSASLPlainWireExchange(t *testing.T) {
	t.Parallel()

	const password = "plain-client-secret"
	var mutex sync.Mutex
	binds := 0
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		switch request := message.Request.(type) {
		case ldapwire.BindRequest:
			mutex.Lock()
			binds++
			mutex.Unlock()
			if request.Name != "" || !request.Authentication.IsSASL ||
				request.Authentication.SASLMechanism != "PLAIN" ||
				!request.Authentication.HasSASLCredentials {
				return nil, fmt.Errorf("unexpected PLAIN bind request: %#v", request)
			}
			if got, want := string(request.Authentication.SASLCredentials),
				"u:target\x00alice\x00"+password; got != want {
				return [][]byte{ldapwire.EncodeBindResponse(
					message.ID,
					ldapwire.Result{Code: ldapwire.ResultInvalidCredentials},
					nil,
				)}, nil
			}
			return [][]byte{ldapwire.EncodeBindResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			)}, nil
		case ldapwire.ExtendedRequest:
			if request.Name != ldapWhoAmIOID {
				return nil, fmt.Errorf("unexpected extended request %q", request.Name)
			}
			return [][]byte{ldapwire.EncodeExtendedResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				ldapWhoAmIOID,
				[]byte("dn:uid=target,dc=example,dc=com"),
				nil,
			)}, nil
		default:
			return nil, fmt.Errorf("unexpected request %T", message.Request)
		}
	})

	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", fixture.uri,
			"-Y", "plain", "-U", "alice", "-X", "u:target", "-W",
		},
		password+"\n",
	)
	if exitCode != 0 || stdout != "dn:uid=target,dc=example,dc=com\n" ||
		stderr != "Enter LDAP Password: " {
		t.Fatalf("PLAIN command exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if strings.Contains(stdout, password) || strings.Contains(stderr, password) {
		t.Fatalf("PLAIN command exposed its password: stdout=%q stderr=%q", stdout, stderr)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if binds != 1 {
		t.Fatalf("PLAIN bind request count = %d, want 1", binds)
	}
}

func TestLDAPClientSASLDigestMD5WireExchange(t *testing.T) {
	t.Parallel()

	const (
		password = "digest-client-secret"
		nonce    = "fixed-server-nonce"
	)
	challenge := []byte(
		`realm="other.example",realm="example.com",nonce="` + nonce +
			`",qop="auth,auth-int",charset=utf-8,algorithm=md5-sess`,
	)
	var mutex sync.Mutex
	step := 0
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		request, ok := message.Request.(ldapwire.BindRequest)
		if !ok {
			extended, extendedOK := message.Request.(ldapwire.ExtendedRequest)
			if !extendedOK || extended.Name != ldapWhoAmIOID {
				return nil, fmt.Errorf("unexpected request %T", message.Request)
			}
			return [][]byte{ldapwire.EncodeExtendedResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				ldapWhoAmIOID,
				[]byte("dn:uid=alice,dc=example,dc=com"),
				nil,
			)}, nil
		}
		if !request.Authentication.IsSASL ||
			request.Authentication.SASLMechanism != "DIGEST-MD5" {
			return nil, fmt.Errorf("unexpected DIGEST-MD5 bind request: %#v", request)
		}
		mutex.Lock()
		defer mutex.Unlock()
		switch step {
		case 0:
			step++
			if request.Authentication.HasSASLCredentials {
				return nil, errors.New("DIGEST-MD5 initial response must be omitted")
			}
			return [][]byte{ldapwire.EncodeSASLBindResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSASLBindInProgress},
				challenge,
				true,
				nil,
			)}, nil
		case 1:
			step++
			if !request.Authentication.HasSASLCredentials {
				return nil, errors.New("DIGEST-MD5 response is missing")
			}
			directives, _, err := parseLDAPClientDigestMD5Directives(
				request.Authentication.SASLCredentials,
				false,
			)
			if err != nil {
				return nil, fmt.Errorf("parse client DIGEST-MD5 response: %w", err)
			}
			values := ldapClientDigestMD5Values{
				username:      directives["username"],
				realm:         directives["realm"],
				nonce:         directives["nonce"],
				cnonce:        directives["cnonce"],
				digestURI:     directives["digest-uri"],
				authorization: directives["authzid"],
			}
			wantResponse, rspauth := ldapClientDigestMD5Exchange(values, []byte(password))
			if directives["response"] != wantResponse || values.username != "alice" ||
				values.realm != "example.com" || values.nonce != nonce ||
				values.authorization != "u:target" || directives["qop"] != "auth" {
				return nil, errors.New("DIGEST-MD5 client response did not authenticate")
			}
			return [][]byte{ldapwire.EncodeSASLBindResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSASLBindInProgress},
				[]byte("rspauth="+rspauth),
				true,
				nil,
			)}, nil
		case 2:
			step++
			if !request.Authentication.HasSASLCredentials ||
				len(request.Authentication.SASLCredentials) != 0 {
				return nil, errors.New("DIGEST-MD5 final response must be present and empty")
			}
			return [][]byte{ldapwire.EncodeBindResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			)}, nil
		default:
			return nil, errors.New("unexpected extra DIGEST-MD5 bind round")
		}
	})

	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", fixture.uri,
			"-Y", "DIGEST-MD5", "-U", "alice", "-X", "u:target",
			"-R", "example.com", "-w", password,
		},
		"",
	)
	if exitCode != 0 || stdout != "dn:uid=alice,dc=example,dc=com\n" || stderr != "" {
		t.Fatalf("DIGEST-MD5 command exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if strings.Contains(stdout, password) || strings.Contains(stderr, password) {
		t.Fatalf("DIGEST-MD5 command exposed its password: stdout=%q stderr=%q", stdout, stderr)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if step != 3 {
		t.Fatalf("DIGEST-MD5 bind step = %d, want 3", step)
	}
}

func TestLDAPClientSASLDigestMD5RejectsInvalidServerProof(t *testing.T) {
	t.Parallel()

	const password = "proof-client-secret"
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		request, ok := message.Request.(ldapwire.BindRequest)
		if !ok {
			return nil, fmt.Errorf("unexpected request %T", message.Request)
		}
		if !request.Authentication.HasSASLCredentials {
			return [][]byte{ldapwire.EncodeSASLBindResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSASLBindInProgress},
				[]byte(`realm="example.com",nonce="nonce",qop="auth",charset=utf-8,algorithm=md5-sess`),
				true,
				nil,
			)}, nil
		}
		return [][]byte{ldapwire.EncodeSASLBindResponse(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			[]byte("rspauth=00000000000000000000000000000000"),
			true,
			nil,
		)}, nil
	})

	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", fixture.uri,
			"-Y", "DIGEST-MD5", "-U", "alice", "-w", password,
		},
		"",
	)
	if exitCode != 1 || stdout != "" ||
		!strings.Contains(stderr, "server proof is invalid") {
		t.Fatalf("invalid rspauth exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if strings.Contains(stderr, password) {
		t.Fatalf("invalid rspauth exposed password: %q", stderr)
	}
}

func TestLDAPClientSASLErrorDoesNotEchoServerDiagnostic(t *testing.T) {
	t.Parallel()

	const password = "server-echoed-client-secret"
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.BindRequest); !ok {
			return nil, fmt.Errorf("unexpected request %T", message.Request)
		}
		return [][]byte{ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.Result{
				Code:              ldapwire.ResultInvalidCredentials,
				DiagnosticMessage: "rejected password " + password,
			},
			nil,
		)}, nil
	})

	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", fixture.uri,
			"-Y", "PLAIN", "-U", "alice", "-w", password,
		},
		"",
	)
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "Invalid Credentials") {
		t.Fatalf("rejected PLAIN exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if strings.Contains(stderr, password) {
		t.Fatalf("rejected PLAIN exposed server diagnostic: %q", stderr)
	}
}

func TestLDAPClientSASLPlainOverRequiredStartTLS(t *testing.T) {
	t.Parallel()

	serverTLS, certificatePEM := newLDAPClientToolTLSConfig(t)
	uri := startLDAPClientToolSASLServer(t, serverTLS)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, certificatePEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", uri, "-ZZ", "-tls-ca", caPath,
			"-tls-server-name", "localhost", "-Y", "PLAIN", "-U", "alice",
			"-w", "sasl-client-secret",
		},
		"",
	)
	if exitCode != 0 || stdout != "dn:uid=alice,"+clientToolPeopleDN+"\n" || stderr != "" {
		t.Fatalf("StartTLS PLAIN exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPClientSASLDigestMD5ProjectServer(t *testing.T) {
	t.Parallel()

	uri := startLDAPClientToolSASLServer(t, nil)
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", uri, "-Y", "DIGEST-MD5", "-U", "alice",
			"-R", "example.com", "-w", "sasl-client-secret",
		},
		"",
	)
	if exitCode != 0 || stdout != "dn:uid=alice,"+clientToolPeopleDN+"\n" || stderr != "" {
		t.Fatalf("DIGEST-MD5 project server exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPClientSASLCRAMMD5ProjectServer(t *testing.T) {
	t.Parallel()

	uri := startLDAPClientToolSASLServer(t, nil)
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", uri, "-Y", "CRAM-MD5", "-U", "alice",
			"-w", "sasl-client-secret",
		},
		"",
	)
	if exitCode != 0 || stdout != "dn:uid=alice,"+clientToolPeopleDN+"\n" || stderr != "" {
		t.Fatalf("CRAM-MD5 project server exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPClientSASLSCRAMProjectServer(t *testing.T) {
	for _, mechanism := range []string{
		"SCRAM-SHA-1",
		"SCRAM-SHA-256",
		"SCRAM-SHA-512",
	} {
		mechanism := mechanism
		t.Run(mechanism, func(t *testing.T) {
			t.Parallel()

			uri := startLDAPClientToolSASLServer(t, nil)
			args := []string{
				"ldapwhoami", "-H", uri, "-Y", mechanism, "-U", "alice",
				"-X", "u:alice",
			}
			stdin := ""
			wantStderr := ""
			switch mechanism {
			case "SCRAM-SHA-256":
				args = append(args, "-W")
				stdin = "sasl-client-secret\n"
				wantStderr = "Enter LDAP Password: "
			case "SCRAM-SHA-512":
				passwordPath := filepath.Join(t.TempDir(), "scram-password")
				if err := os.WriteFile(passwordPath, []byte("sasl-client-secret"), 0o600); err != nil {
					t.Fatalf("write SCRAM password file: %v", err)
				}
				args = append(args, "-y", passwordPath)
			default:
				args = append(args, "-w", "sasl-client-secret")
			}
			stdout, stderr, exitCode := runLDAPClientCommand(
				args,
				stdin,
			)
			if exitCode != 0 || stdout != "dn:uid=alice,"+clientToolPeopleDN+"\n" ||
				stderr != wantStderr {
				t.Fatalf("%s project server exit=%d stdout=%q stderr=%q", mechanism, exitCode, stdout, stderr)
			}
		})
	}
}

func TestLDAPClientSASLSCRAMRejectsInvalidServerSignature(t *testing.T) {
	t.Parallel()

	const password = "scram-proof-client-secret"
	credentialClient, err := scram.SHA256.NewClient("alice", password, "")
	if err != nil {
		t.Fatalf("create SCRAM credential client: %v", err)
	}
	credentials, err := credentialClient.GetStoredCredentialsWithError(scram.KeyFactors{
		Salt:  "fixed-client-test-salt",
		Iters: ldapClientSCRAMMinIterations,
	})
	if err != nil {
		t.Fatalf("derive SCRAM credentials: %v", err)
	}
	scramServer, err := scram.SHA256.NewServer(func(username string) (scram.StoredCredentials, error) {
		if username != "alice" {
			return scram.StoredCredentials{}, errors.New("unknown SCRAM test user")
		}
		return credentials, nil
	})
	if err != nil {
		t.Fatalf("create SCRAM proof server: %v", err)
	}
	conversation := scramServer.NewConversation()
	step := 0
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		request, ok := message.Request.(ldapwire.BindRequest)
		if !ok || request.Authentication.SASLMechanism != "SCRAM-SHA-256" ||
			!request.Authentication.HasSASLCredentials {
			return nil, fmt.Errorf("unexpected SCRAM request: %#v", message.Request)
		}
		response, err := conversation.Step(string(request.Authentication.SASLCredentials))
		if err != nil {
			return nil, fmt.Errorf("SCRAM fixture step: %w", err)
		}
		step++
		if step == 1 {
			return [][]byte{ldapwire.EncodeSASLBindResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSASLBindInProgress},
				[]byte(response),
				true,
				nil,
			)}, nil
		}
		if step != 2 || !strings.HasPrefix(response, "v=") {
			return nil, errors.New("SCRAM fixture did not produce server-final")
		}
		proof, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(response, "v="))
		if err != nil || len(proof) == 0 {
			return nil, errors.New("SCRAM fixture produced malformed server proof")
		}
		proof[0] ^= 0xff
		malformedProof := []byte("v=" + base64.StdEncoding.EncodeToString(proof))
		clear(proof)
		return [][]byte{ldapwire.EncodeSASLBindResponse(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			malformedProof,
			true,
			nil,
		)}, nil
	})

	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", fixture.uri, "-Y", "SCRAM-SHA-256",
			"-U", "alice", "-w", password,
		},
		"",
	)
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "server signature is invalid") {
		t.Fatalf("invalid SCRAM signature exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if strings.Contains(stderr, password) {
		t.Fatalf("invalid SCRAM signature exposed password: %q", stderr)
	}
}

func TestLDAPClientSASLSCRAMRejectsUnsafeServerFirst(t *testing.T) {
	t.Parallel()

	const password = "scram-parameter-client-secret"
	tests := []struct {
		name      string
		challenge func(string) string
		message   string
	}{
		{
			name: "nonce not extended",
			challenge: func(nonce string) string {
				return "r=" + nonce + ",s=c2FsdA==,i=4096"
			},
			message: "strictly extend",
		},
		{
			name: "iteration below minimum",
			challenge: func(nonce string) string {
				return "r=" + nonce + "server,s=c2FsdA==,i=4095"
			},
			message: "between 4096 and 10000000",
		},
		{
			name: "iteration above maximum",
			challenge: func(nonce string) string {
				return "r=" + nonce + "server,s=c2FsdA==,i=10000001"
			},
			message: "between 4096 and 10000000",
		},
		{
			name: "noncanonical iteration",
			challenge: func(nonce string) string {
				return "r=" + nonce + "server,s=c2FsdA==,i=04096"
			},
			message: "not canonical",
		},
		{
			name: "malformed salt",
			challenge: func(nonce string) string {
				return "r=" + nonce + "server,s=***,i=4096"
			},
			message: "salt is malformed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
				request, ok := message.Request.(ldapwire.BindRequest)
				if !ok || !request.Authentication.HasSASLCredentials {
					return nil, fmt.Errorf("unexpected SCRAM request: %#v", message.Request)
				}
				nonce, err := ldapClientSCRAMClientNonce(
					string(request.Authentication.SASLCredentials),
				)
				if err != nil {
					return nil, err
				}
				return [][]byte{ldapwire.EncodeSASLBindResponse(
					message.ID,
					ldapwire.Result{Code: ldapwire.ResultSASLBindInProgress},
					[]byte(test.challenge(nonce)),
					true,
					nil,
				)}, nil
			})
			stdout, stderr, exitCode := runLDAPClientCommand(
				[]string{
					"ldapwhoami", "-H", fixture.uri, "-Y", "SCRAM-SHA-256",
					"-U", "alice", "-w", password,
				},
				"",
			)
			if exitCode != 1 || stdout != "" || !strings.Contains(stderr, test.message) {
				t.Fatalf("unsafe SCRAM parameters exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
			}
			if strings.Contains(stderr, password) {
				t.Fatalf("unsafe SCRAM parameters exposed password: %q", stderr)
			}
		})
	}
}

func TestLDAPClientSASLCRAMMD5RejectsMalformedChallenge(t *testing.T) {
	t.Parallel()

	const password = "cram-challenge-client-secret"
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.BindRequest); !ok {
			return nil, fmt.Errorf("unexpected CRAM-MD5 request: %#v", message.Request)
		}
		return [][]byte{ldapwire.EncodeSASLBindResponse(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSASLBindInProgress},
			[]byte("predictable-challenge"),
			true,
			nil,
		)}, nil
	})
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", fixture.uri, "-Y", "CRAM-MD5",
			"-U", "alice", "-w", password,
		},
		"",
	)
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "malformed challenge") {
		t.Fatalf("malformed CRAM challenge exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if strings.Contains(stderr, password) {
		t.Fatalf("malformed CRAM challenge exposed password: %q", stderr)
	}
}

func TestLDAPClientSASLExternalMutualTLS(t *testing.T) {
	t.Parallel()

	files, serverTLS := newLDAPClientMutualTLSFiles(t)
	uri := startLDAPClientTLSWireFixture(t, serverTLS, func(message ldapwire.Message) ([][]byte, error) {
		switch request := message.Request.(type) {
		case ldapwire.BindRequest:
			if request.Authentication.SASLMechanism != "EXTERNAL" ||
				!request.Authentication.HasSASLCredentials ||
				string(request.Authentication.SASLCredentials) != "dn:uid=target,dc=example" {
				return nil, fmt.Errorf("unexpected EXTERNAL request: %#v", request)
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
				[]byte("dn:uid=target,dc=example"),
				nil,
			)}, nil
		default:
			return nil, fmt.Errorf("unexpected request %T", message.Request)
		}
	})

	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapwhoami", "-H", uri, "-Y", "EXTERNAL",
			"-X", "dn:uid=target,dc=example", "-tls-ca", files.ca,
			"-tls-cert", files.certificate, "-tls-key", files.key,
			"-tls-server-name", "localhost",
		},
		"",
	)
	if exitCode != 0 || stdout != "dn:uid=target,dc=example\n" || stderr != "" {
		t.Fatalf("EXTERNAL command exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPClientSASLValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    []string
		message string
	}{
		{name: "explicit mechanism", args: nil, message: "requires -Y"},
		{name: "simple conflict", args: []string{"-x", "-Y", "PLAIN"}, message: "cannot be combined"},
		{name: "unsupported mechanism", args: []string{"-Y", "GSSAPI"}, message: "unsupported SASL mechanism"},
		{name: "plain authcid", args: []string{"-Y", "PLAIN", "-w", "hidden"}, message: "requires a non-empty -U"},
		{name: "plain realm", args: []string{"-Y", "PLAIN", "-U", "alice", "-R", "example", "-w", "hidden"}, message: "only supported with SASL DIGEST-MD5"},
		{name: "digest password", args: []string{"-Y", "DIGEST-MD5", "-U", "alice"}, message: "requires one of -w"},
		{name: "cram authzid", args: []string{"-Y", "CRAM-MD5", "-U", "alice", "-X", "u:alice", "-w", "hidden"}, message: "does not support -X"},
		{name: "cram whitespace", args: []string{"-Y", "CRAM-MD5", "-U", "alice smith", "-w", "hidden"}, message: "must not contain whitespace"},
		{name: "scram realm", args: []string{"-Y", "SCRAM-SHA-256", "-U", "alice", "-R", "example", "-w", "hidden"}, message: "only supported with SASL DIGEST-MD5"},
		{name: "scram plus", args: []string{"-Y", "SCRAM-SHA-256-PLUS", "-U", "alice", "-w", "hidden"}, message: "SCRAM-PLUS mechanisms are not supported"},
		{name: "security layer", args: []string{"-Y", "SCRAM-SHA-256", "-U", "alice", "-w", "hidden", "-O", "auth-int"}, message: "option -O is not supported"},
		{name: "external password", args: []string{"-Y", "EXTERNAL", "-w", "hidden"}, message: "does not use"},
		{name: "external certificate", args: []string{"-Y", "EXTERNAL"}, message: "requires -tls-cert and -tls-key"},
		{name: "bind DN", args: []string{"-Y", "PLAIN", "-D", clientToolRootDN, "-U", "alice", "-w", "hidden"}, message: "-D requires -x"},
		{name: "empty authzid", args: []string{"-Y", "PLAIN", "-U", "alice", "-X", "", "-w", "hidden"}, message: "-X requires a non-empty"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"ldapwhoami"}, test.args...)
			stdout, stderr, exitCode := runLDAPClientCommand(args, "")
			if exitCode != 1 || stdout != "" || !strings.Contains(stderr, test.message) {
				t.Fatalf("run(%v) exit=%d stdout=%q stderr=%q", args, exitCode, stdout, stderr)
			}
			if strings.Contains(stdout, "hidden") || strings.Contains(stderr, "hidden") {
				t.Fatalf("run(%v) exposed password: stdout=%q stderr=%q", args, stdout, stderr)
			}
		})
	}
}

func startLDAPClientToolSASLServer(t *testing.T, tlsConfig *tls.Config) string {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPClientToolDirectory(t, store)
	userDN, err := directory.ParseDN("uid=alice," + clientToolPeopleDN)
	if err != nil {
		t.Fatalf("parse SASL user DN: %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(userDN)
		if err != nil {
			return err
		}
		entry.ReplaceValues("userPassword", clientToolValues("sasl-client-secret"))
		if err := writer.Put(entry, true); err != nil {
			return err
		}
		return writer.Put(directory.Entry{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcSaslHost", Values: clientToolValues("ldap.example.test")},
				{Description: "olcSaslRealm", Values: clientToolValues("example.com")},
				{Description: "olcSaslSecProps", Values: clientToolValues("none")},
				{Description: "olcAuthzRegexp", Values: clientToolValues(
					`{0}^uid=([^,]+),cn=example\.com,cn=plain,cn=auth$ uid=$1,ou=people,dc=example,dc=com`,
					`{1}^uid=([^,]+),cn=example\.com,cn=digest-md5,cn=auth$ uid=$1,ou=people,dc=example,dc=com`,
					`{2}^uid=([^,]+),cn=example\.com,cn=cram-md5,cn=auth$ uid=$1,ou=people,dc=example,dc=com`,
					`{3}^uid=([^,]+),cn=example\.com,cn=scram-sha-1,cn=auth$ uid=$1,ou=people,dc=example,dc=com`,
					`{4}^uid=([^,]+),cn=example\.com,cn=scram-sha-256,cn=auth$ uid=$1,ou=people,dc=example,dc=com`,
					`{5}^uid=([^,]+),cn=example\.com,cn=scram-sha-512,cn=auth$ uid=$1,ou=people,dc=example,dc=com`,
				)},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed client SASL configuration: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	instance, err := server.New(server.Config{
		Store:        store,
		RootDN:       clientToolRootDN,
		RootPassword: []byte(clientToolRootPassword),
		AccessPolicy: clientToolAccessPolicy(t),
		TLSConfig:    tlsConfig,
	})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("server.New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve(): %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("SASL test server did not stop")
		}
	})
	return "ldap://" + listener.Addr().String()
}

type ldapClientMutualTLSFiles struct {
	ca          string
	certificate string
	key         string
}

func newLDAPClientMutualTLSFiles(t *testing.T) (ldapClientMutualTLSFiles, *tls.Config) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "LDAP client test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	issue := func(serial int64, commonName string, usage x509.ExtKeyUsage) ([]byte, *ecdsa.PrivateKey) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate certificate key: %v", err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: commonName},
			NotBefore:    now.Add(-time.Minute),
			NotAfter:     now.Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		}
		if usage == x509.ExtKeyUsageServerAuth {
			template.DNSNames = []string{"localhost"}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("issue certificate: %v", err)
		}
		return der, key
	}
	serverDER, serverKey := issue(2, "localhost", x509.ExtKeyUsageServerAuth)
	clientDER, clientKey := issue(3, "external-client", x509.ExtKeyUsageClientAuth)
	marshalKey := func(key *ecdsa.PrivateKey) []byte {
		encoded, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatalf("marshal EC key: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})
	}
	directory := t.TempDir()
	files := ldapClientMutualTLSFiles{
		ca:          filepath.Join(directory, "ca.pem"),
		certificate: filepath.Join(directory, "client.pem"),
		key:         filepath.Join(directory, "client-key.pem"),
	}
	for path, data := range map[string][]byte{
		files.ca:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		files.certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}),
		files.key:         marshalKey(clientKey),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write TLS fixture file: %v", err)
		}
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(ca)
	return files, &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverDER},
			PrivateKey:  serverKey,
		}},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAs,
		MinVersion: tls.VersionTLS12,
	}
}

func startLDAPClientTLSWireFixture(
	t *testing.T,
	config *tls.Config,
	handler ldapClientWireHandler,
) string {
	t.Helper()
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for TLS LDAP fixture: %v", err)
	}
	listener := tls.NewListener(rawListener, config)
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
		for {
			message, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
			if err != nil {
				if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "EOF") {
					done <- nil
					return
				}
				done <- err
				return
			}
			responses, err := handler(message)
			if err != nil {
				done <- err
				return
			}
			for _, response := range responses {
				if err := ldapwire.Write(connection, response); err != nil {
					done <- err
					return
				}
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("TLS LDAP fixture: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("TLS LDAP fixture did not stop")
		}
	})
	return "ldaps://" + rawListener.Addr().String()
}
