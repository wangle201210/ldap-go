package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func uriListReviewArgs(command, uri string, sasl bool) []string {
	args := []string{command, "-H", uri}
	if sasl {
		args = append(args, "-Y", "PLAIN", "-U", "review", "-w", "review-password")
	} else {
		args = append(args, "-x", "-D", "cn=review", "-w", "review-password")
	}
	switch command {
	case "ldapsearch":
		args = append(args, "-b", "", "-s", "base", "-LLL")
	case "ldapcompare":
		args = append(args, "cn=review", "cn:review")
	}
	return args
}

func uriListReviewHandler(binds *atomic.Int32, code ldapwire.ResultCode) ldapClientWireHandler {
	return func(message ldapwire.Message) ([][]byte, error) {
		switch message.Request.(type) {
		case ldapwire.BindRequest:
			binds.Add(1)
			return [][]byte{ldapwire.EncodeBindResponse(message.ID, ldapwire.Result{Code: code}, nil)}, nil
		case ldapwire.ExtendedRequest:
			return [][]byte{ldapwire.EncodeExtendedResponse(message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess}, ldapWhoAmIOID, []byte("dn:cn=review"), nil)}, nil
		case ldapwire.SearchRequest:
			return [][]byte{ldapwire.EncodeResultResponse(message.ID, ldap.ApplicationSearchResultDone,
				ldapwire.Result{Code: ldapwire.ResultSuccess}, nil)}, nil
		case ldapwire.CompareRequest:
			return [][]byte{ldapwire.EncodeResultResponse(message.ID, ldap.ApplicationCompareResponse,
				ldapwire.Result{Code: ldapwire.ResultCompareTrue}, nil)}, nil
		case ldapwire.UnbindRequest:
			return nil, nil
		default:
			return nil, fmt.Errorf("unexpected review request %T", message.Request)
		}
	}
}

func TestLDAPURIListReviewAtomicValidation(t *testing.T) {
	for _, command := range []string{"ldapwhoami", "ldapsearch", "ldapcompare"} {
		for _, invalid := range []string{"not-an-ldap-uri", "ldap://127.0.0.1:", "ldap://127.0.0.1:65536", "ldap://::1"} {
			t.Run(command+"/"+invalid, func(t *testing.T) {
				var binds atomic.Int32
				first := startLDAPClientWireFixture(t, uriListReviewHandler(&binds, ldapwire.ResultSuccess))
				_, stderr, code := runLDAPClientCommand(uriListReviewArgs(command, first.uri+" "+invalid, false), "")
				if binds.Load() != 0 || stderr == "" {
					t.Errorf("expected atomic URI 2 rejection; exit=%d binds=%d stderr=%q", code, binds.Load(), stderr)
				}
			})
		}
	}
}

func TestLDAPURIListReviewDirectDNComma(t *testing.T) {
	for _, dn := range []string{"cn=review%5C,", "cn=review%5C%2C"} {
		t.Run(dn, func(t *testing.T) {
			direct, err := parseLDAPSearchDirectURL("ldap://127.0.0.1/" + dn)
			if err != nil || !direct.direct || direct.baseDN != `cn=review\,` {
				t.Fatalf("escaped DN comma was altered: direct=%#v err=%v", direct, err)
			}
		})
	}
}

func TestLDAPURIListReviewBindRejections(t *testing.T) {
	for _, command := range []string{"ldapwhoami", "ldapsearch", "ldapcompare"} {
		for _, sasl := range []bool{false, true} {
			for _, result := range []ldapwire.ResultCode{ldapwire.ResultInvalidCredentials, ldapwire.ResultAuthMethodNotSupported, ldapwire.ResultInsufficientAccessRights, ldapwire.ResultUnavailable} {
				t.Run(fmt.Sprintf("%s/SASL=%t/code=%d", command, sasl, result), func(t *testing.T) {
					var rejected, fallback atomic.Int32
					second := startLDAPClientWireFixture(t, uriListReviewHandler(&rejected, result))
					third := startLDAPClientWireFixture(t, uriListReviewHandler(&fallback, ldapwire.ResultSuccess))
					uri := unavailableLDAPClientURI(t) + " " + second.uri + " " + third.uri
					_, stderr, code := runLDAPClientCommand(uriListReviewArgs(command, uri, sasl), "")
					if code == 0 || rejected.Load() != 1 || fallback.Load() != 0 ||
						!strings.Contains(stderr, ldap.LDAPResultCodeMap[uint16(result)]) || strings.Contains(stderr, "review-password") {
						t.Errorf("exit=%d rejected=%d fallback=%d stderr=%q", code, rejected.Load(), fallback.Load(), stderr)
					}
				})
			}
		}
	}
}

func TestLDAPURIListReviewSelectedEndpoint(t *testing.T) {
	for _, raw := range []bool{false, true} {
		for _, sasl := range []bool{false, true} {
			t.Run(fmt.Sprintf("raw=%t/SASL=%t", raw, sasl), func(t *testing.T) {
				var selected atomic.Int32
				second := startLDAPClientWireFixture(t, uriListReviewHandler(&selected, ldapwire.ResultSuccess))
				flags := flag.NewFlagSet("review", flag.ContinueOnError)
				var options ldapClientOptions
				options.register(flags)
				if err := flags.Parse(uriListReviewArgs("ldapwhoami", unavailableLDAPClientURI(t)+","+second.uri, sasl)[1:]); err != nil {
					t.Fatal(err)
				}
				options.observeSearch = !raw
				if raw {
					conn, err := connectLDAPCompareRaw(&options, flags, strings.NewReader(""), io.Discard)
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
				} else {
					conn, err := options.connectAndBind(flags, strings.NewReader(""), io.Discard)
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					if options.searchObserver == nil {
						t.Error("selected search connection has no observer")
					}
				}
				if options.uri != second.uri || selected.Load() != 1 {
					t.Errorf("selected=%q second=%d", options.uri, selected.Load())
				}
			})
		}
	}
}

func TestLDAPURIListReviewRawCompareLDAPI(t *testing.T) {
	if !platformSupportsLDAPI() {
		t.Skip("Unix sockets unavailable")
	}
	var binds atomic.Int32
	fixture := startLDAPClientWireFixture(t, uriListReviewHandler(&binds, ldapwire.ResultSuccess))
	uri := uriListReviewUnixProxy(t, fixture.uri)
	flags := flag.NewFlagSet("review", flag.ContinueOnError)
	var options ldapClientOptions
	options.register(flags)
	if err := flags.Parse([]string{"-H", unavailableLDAPClientURI(t) + " " + uri, "-x"}); err != nil {
		t.Fatal(err)
	}
	endpoints, err := options.connectionConfigurations(flags)
	if err != nil {
		t.Fatal(err)
	}
	// Inspect the transport before sending credentials to an unintended TCP listener.
	conn, err := dialLDAPRawConnection(endpoints[1].parsedURI, endpoints[1].tlsConfig, time.Second, false)
	if err != nil {
		t.Fatalf("raw Compare cannot dial LDAPI endpoint: %v", err)
	}
	defer conn.Close()
	if conn.RemoteAddr().Network() != "unix" {
		t.Fatalf("raw Compare selected %s, want Unix socket %s", conn.RemoteAddr(), uri)
	}
}

func uriListReviewUnixProxy(t *testing.T, upstream string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ldap-uri-review-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "ldap.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var connections sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				connections.Wait()
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer conn.Close()
				target, err := net.DialTimeout("tcp", strings.TrimPrefix(upstream, "ldap://"), time.Second)
				if err != nil {
					t.Error(err)
					return
				}
				defer target.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_ = target.SetDeadline(time.Now().Add(3 * time.Second))
				copied := make(chan struct{})
				go func() {
					_, _ = io.Copy(target, conn)
					_ = target.Close()
					close(copied)
				}()
				_, _ = io.Copy(conn, target)
				_ = conn.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return "ldapi://" + url.PathEscape(path) + "/"
}

func TestLDAPURIListReviewExternal(t *testing.T) {
	if os.Getenv("LDAP_GO_URI_REVIEW_EXTERNAL") != "1" {
		t.Skip("set LDAP_GO_URI_REVIEW_EXTERNAL=1 to compare the installed OpenLDAP 2.6.13 CLI")
	}
	tool, err := exec.LookPath("ldapsearch")
	if err != nil {
		t.Fatal(err)
	}
	version, err := exec.Command(tool, "-VV").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "OpenLDAP: ldapsearch 2.6.13") {
		t.Fatalf("requires OpenLDAP 2.6.13: %v %s", err, version)
	}
	runExternal := func(t *testing.T, args []string) (string, int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, filepath.Join(filepath.Dir(tool), args[0]), args[1:]...)
		cmd.Env = append(os.Environ(), "LDAPNOINIT=1", "LC_ALL=C")
		output, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("external command timed out: %v", args)
		}
		code := 0
		if err != nil {
			if cmd.ProcessState == nil {
				t.Fatal(err)
			}
			code = cmd.ProcessState.ExitCode()
		}
		return string(output), code
	}
	t.Run("parsing", func(t *testing.T) {
		var binds atomic.Int32
		good := startLDAPClientWireFixture(t, uriListReviewHandler(&binds, ldapwire.ResultSuccess))
		for _, separator := range []string{" ", ",", ",,  ,", "\t", "\n", "\u00a0"} {
			t.Run(fmt.Sprintf("separator=%q", separator), func(t *testing.T) {
				args := uriListReviewArgs("ldapwhoami", unavailableLDAPClientURI(t)+separator+good.uri, false)
				stdout, stderr, local := runLDAPClientCommand(args, "")
				output, external := runExternal(t, args)
				t.Logf("local=%d %q %q external=%d %q", local, stdout, stderr, external, output)
				if (local == 0) != (external == 0) {
					t.Error("separator acceptance differs")
				}
			})
		}
		for _, suffix := range []string{"/dc=example,dc=com", "/dc=example%2Cdc=com", " ldap://127.0.0.1:", " ldap://127.0.0.1:65536"} {
			t.Run(suffix, func(t *testing.T) {
				args := uriListReviewArgs("ldapsearch", good.uri+suffix, false)
				stdout, stderr, local := runLDAPClientCommand(args, "")
				output, external := runExternal(t, args)
				// Direct search URL support intentionally extends OpenLDAP's -H semantics.
				t.Logf("local=%d %q %q external=%d %q", local, stdout, stderr, external, output)
			})
		}
	})
	t.Run("bind-results", func(t *testing.T) {
		for _, sasl := range []bool{false, true} {
			for _, result := range []ldapwire.ResultCode{ldapwire.ResultInvalidCredentials, ldapwire.ResultUnavailable} {
				t.Run(fmt.Sprintf("SASL=%t/code=%d", sasl, result), func(t *testing.T) {
					var rejected, fallback atomic.Int32
					first := startLDAPClientWireFixture(t, uriListReviewHandler(&rejected, result))
					second := startLDAPClientWireFixture(t, uriListReviewHandler(&fallback, ldapwire.ResultSuccess))
					args := uriListReviewArgs("ldapwhoami", unavailableLDAPClientURI(t)+","+first.uri+","+second.uri, sasl)
					_, stderr, local := runLDAPClientCommand(args, "")
					localBinds := fallback.Swap(0)
					if sasl {
						args = append(args, "-Q", "-N", "-O", "none")
					}
					output, external := runExternal(t, args)
					t.Logf("local=%d fallback=%d %q external=%d fallback=%d %q", local, localBinds, stderr, external, fallback.Load(), output)
					if external != int(result) || fallback.Load() != 0 {
						t.Error("external CLI did not stop at the bind rejection")
					}
				})
			}
		}
	})
	t.Run("LDAPI", func(t *testing.T) {
		if !platformSupportsLDAPI() {
			t.Skip("Unix sockets unavailable")
		}
		var binds atomic.Int32
		good := startLDAPClientWireFixture(t, uriListReviewHandler(&binds, ldapwire.ResultSuccess))
		uri := unavailableLDAPClientURI(t) + " " + uriListReviewUnixProxy(t, good.uri)
		for _, command := range []string{"ldapwhoami", "ldapsearch", "ldapcompare"} {
			args := uriListReviewArgs(command, uri, false)
			output, external := runExternal(t, args)
			t.Logf("%s external=%d %q", command, external, output)
			want := 0
			if command == "ldapcompare" {
				want = int(ldap.LDAPResultCompareTrue)
			} else {
				_, stderr, local := runLDAPClientCommand(args, "")
				if local != want {
					t.Errorf("%s local=%d %q", command, local, stderr)
				}
			}
			if external != want {
				t.Errorf("%s external=%d, want %d", command, external, want)
			}
		}
	})
	t.Run("LDAPS", func(t *testing.T) {
		serverTLS, pem := newLDAPClientToolTLSConfig(t)
		ca := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(ca, pem, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, command := range []string{"ldapwhoami", "ldapsearch", "ldapcompare"} {
			for _, external := range []bool{false, true} {
				var binds atomic.Int32
				uri := startLDAPClientTLSWireFixture(t, serverTLS.Clone(), uriListReviewHandler(&binds, ldapwire.ResultSuccess))
				args := []string{command, "-H", unavailableLDAPClientURI(t) + " " + uri, "-x"}
				if !external {
					args = append(args, "-tls-ca", ca)
				} else {
					args = append(args, "-o", "TLS_CACERT="+ca, "-o", "TLS_REQCERT=demand")
				}
				if command == "ldapsearch" {
					args = append(args, "-b", "", "-s", "base", "-LLL")
				} else if command == "ldapcompare" {
					args = append(args, "cn=review", "cn:review")
				}
				want := 0
				if command == "ldapcompare" {
					want = int(ldap.LDAPResultCompareTrue)
				}
				if external {
					output, code := runExternal(t, args)
					if code != want {
						t.Errorf("%s external=%d %q", command, code, output)
					}
				} else {
					_, stderr, code := runLDAPClientCommand(args, "")
					if code != want {
						t.Errorf("%s local=%d %q", command, code, stderr)
					}
				}
			}
		}
	})
	t.Run("StartTLS", func(t *testing.T) {
		serverTLS, pem := newLDAPClientToolTLSConfig(t)
		good := startLDAPClientToolSASLServer(t, serverTLS)
		ca := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(ca, pem, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, command := range []string{"ldapwhoami", "ldapsearch", "ldapcompare"} {
			for _, sasl := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/SASL=%t", command, sasl), func(t *testing.T) {
					uri := unavailableLDAPClientURI(t) + " " + good
					for _, external := range []bool{false, true} {
						args := []string{command, "-H", uri, "-ZZ"}
						if external {
							args = append(args, "-o", "TLS_CACERT="+ca, "-o", "TLS_REQCERT=demand")
						} else {
							args = append(args, "-tls-ca", ca)
						}
						if sasl {
							args = append(args, "-Y", "PLAIN", "-U", "alice", "-w", "sasl-client-secret")
							if external {
								args = append(args, "-Q", "-N", "-O", "none")
							}
						} else {
							args = append(args, "-x")
						}
						want := 0
						if command == "ldapsearch" {
							args = append(args, "-b", "", "-s", "base", "-LLL")
						} else if command == "ldapcompare" {
							args = append(args, "uid=alice,"+clientToolPeopleDN, "uid:alice")
							want = int(ldap.LDAPResultCompareTrue)
						}
						if external {
							output, code := runExternal(t, args)
							if code != want {
								t.Errorf("external=%d %q", code, output)
							}
						} else {
							_, stderr, code := runLDAPClientCommand(args, "")
							if code != want {
								t.Errorf("local=%d %q", code, stderr)
							}
						}
					}
				})
			}
		}
	})
}
