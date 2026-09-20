package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPSearchDirectURLRFC4516AndExplicitPrecedence(t *testing.T) {
	requests := make(chan ldapwire.SearchRequest, 3)
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		request, ok := message.Request.(ldapwire.SearchRequest)
		if !ok {
			return nil, nil
		}
		requests <- request
		return [][]byte{ldapwire.EncodeSearchResultDone(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		)}, nil
	})

	directURL := fixture.uri +
		"/ou%3Dpeople%2Cdc%3Dexample%2Cdc%3Dcom" +
		"?uid,cn?one?%28uid%3Dalice%29?x-direct=%2Bvalue"
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapsearch", "-H", directURL, "-url-search", "-x", "-LLL",
	}, "")
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("direct URL search exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPSearchURLRequest(t, awaitLDAPClientWireMessageValue(t, requests), ldapSearchURLRequest{
		baseDN:     "ou=people,dc=example,dc=com",
		scope:      directory.ScopeSingleLevel,
		filterKind: directory.FilterEquality,
		attribute:  "uid",
		assertion:  "alice",
		attributes: []string{"uid", "cn"},
	})

	stdout, stderr, exitCode = runLDAPClientCommand([]string{
		"ldapsearch", "-H", directURL, "-url-search", "-x", "-LLL",
		"-b", "dc=example,dc=com", "-s", "sub",
		"(uid=bob)", "description",
	}, "")
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("explicit URL override exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPSearchURLRequest(t, awaitLDAPClientWireMessageValue(t, requests), ldapSearchURLRequest{
		baseDN:     "dc=example,dc=com",
		scope:      directory.ScopeWholeSubtree,
		filterKind: directory.FilterEquality,
		attribute:  "uid",
		assertion:  "bob",
		attributes: []string{"description"},
	})

	stdout, stderr, exitCode = runLDAPClientCommand([]string{
		"ldapsearch", "-H", directURL, "-url-search", "-x", "-LLL", "mail",
	}, "")
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("URL filter with positional attrs exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPSearchURLRequest(t, awaitLDAPClientWireMessageValue(t, requests), ldapSearchURLRequest{
		baseDN:     "ou=people,dc=example,dc=com",
		scope:      directory.ScopeSingleLevel,
		filterKind: directory.FilterEquality,
		attribute:  "uid",
		assertion:  "alice",
		attributes: []string{"mail"},
	})
}

func TestLDAPSearchDirectURLEmptyComponentsUseRFC4516Defaults(t *testing.T) {
	requests := make(chan ldapwire.SearchRequest, 1)
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		request, ok := message.Request.(ldapwire.SearchRequest)
		if !ok {
			return nil, nil
		}
		requests <- request
		return [][]byte{ldapwire.EncodeSearchResultDone(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		)}, nil
	})

	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapsearch", "-H", fixture.uri + "/???", "-url-search", "-x", "-LLL",
	}, "")
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("default URL search exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	request := awaitLDAPClientWireMessageValue(t, requests)
	if request.BaseDN != "" || request.Scope != directory.ScopeBase ||
		request.Filter.Kind != directory.FilterPresent ||
		request.Filter.Attribute != "objectClass" || len(request.Attributes) != 0 {
		t.Fatalf("default direct URL request = %#v", request)
	}
}

func TestLDAPSearchPlainURIKeepsSlashAndPositionalAttributeSemantics(t *testing.T) {
	requests := make(chan ldapwire.SearchRequest, 1)
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		request, ok := message.Request.(ldapwire.SearchRequest)
		if !ok {
			return nil, nil
		}
		requests <- request
		return [][]byte{ldapwire.EncodeSearchResultDone(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		)}, nil
	})

	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapsearch", "-H", fixture.uri + "/", "-x", "-LLL",
	}, "")
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("plain slash URI exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	request := awaitLDAPClientWireMessageValue(t, requests)
	if request.BaseDN != "" || request.Scope != directory.ScopeWholeSubtree ||
		request.Filter.Kind != directory.FilterPresent ||
		!strings.EqualFold(request.Filter.Attribute, "objectClass") {
		t.Fatalf("plain slash URI request = %#v", request)
	}

	stdout, stderr, exitCode = runLDAPClientCommand([]string{
		"ldapsearch", "-H", fixture.uri, "-x", "-LLL", "cn",
	}, "")
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("plain positional attribute exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	assertLDAPSearchURLRequest(t, awaitLDAPClientWireMessageValue(t, requests), ldapSearchURLRequest{
		scope:      directory.ScopeWholeSubtree,
		filterKind: directory.FilterPresent,
		attribute:  "objectClass",
		attributes: []string{"cn"},
	})
}

func TestLDAPSearchConnectionURLDefaultsAndFailover(t *testing.T) {
	requests := make(chan ldapwire.SearchRequest, 1)
	var binds atomic.Int32
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.BindRequest); ok {
			binds.Add(1)
			return [][]byte{ldapwire.EncodeBindResponse(message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess}, nil)}, nil
		}
		if request, ok := message.Request.(ldapwire.SearchRequest); ok {
			requests <- request
			return [][]byte{ldapwire.EncodeSearchResultDone(message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess}, nil)}, nil
		}
		return nil, nil
	})
	fullURL := fixture.uri + "/dc=ignored?cn?one?%28uid%3Dignored%29"
	for _, test := range []struct {
		name string
		uri  string
		args []string
	}{
		{name: "full URL", uri: fullURL},
		{name: "explicitly disabled extension", uri: fullURL, args: []string{"-url-search=false"}},
		{name: "empty components", uri: fixture.uri + "/???"},
		{name: "DN only", uri: fixture.uri + "/dc=ignored"},
		{name: "space failover", uri: unavailableLDAPClientURI(t) + "/dc=unused " + fullURL},
		{name: "comma failover", uri: unavailableLDAPClientURI(t) + "/dc=unused," + fullURL},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"ldapsearch", "-H", test.uri, "-x", "-LLL"}, test.args...)
			stdout, stderr, code := runLDAPClientCommand(args, "")
			if code != 0 || stdout != "" || stderr != "" {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			assertLDAPSearchURLRequest(t, awaitLDAPClientWireMessageValue(t, requests), ldapSearchURLRequest{
				scope: directory.ScopeWholeSubtree, filterKind: directory.FilterPresent, attribute: "objectClass",
			})
		})
	}
	bindsBeforeRejections := binds.Load()
	_, stderr, code := runLDAPClientCommand([]string{
		"ldapsearch", "-H", fixture.uri + " " + fullURL, "-url-search", "-x", "-LLL",
	}, "")
	if code == 0 || !strings.Contains(stderr, "cannot be combined") {
		t.Fatalf("ambiguous URL search exit=%d stderr=%q", code, stderr)
	}
	for _, invalid := range []string{
		"ldap://127.0.0.1:65536/dc=ignored",
		"ldap://user:secret@127.0.0.1/dc=ignored",
		"ldap://127.0.0.1/???%28uid%3D",
		fixture.uri + "/dc=ignored,dc=example",
		fixture.uri + "/dc%3Dignored%2Cdc%3Dexample",
		fixture.uri + "/?cn,sn",
		fixture.uri + "/???%28cn%3Da%2Cb%29",
	} {
		_, stderr, code := runLDAPClientCommand([]string{
			"ldapsearch", "-H", fullURL + " " + invalid, "-x", "-LLL",
		}, "")
		if code == 0 || stderr == "" {
			t.Fatalf("invalid URL list exit=%d stderr=%q", code, stderr)
		}
	}
	select {
	case request := <-requests:
		t.Fatalf("invalid URL list sent a search: %#v", request)
	default:
	}
	if got := binds.Load(); got != bindsBeforeRejections {
		t.Fatalf("invalid URL list sent %d binds", got-bindsBeforeRejections)
	}
}

func TestLDAPSearchDirectURLStrictParsingAndCriticalExtensions(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		message string
	}{
		{name: "query without slash", uri: "ldap://127.0.0.1:1?cn", message: "requires a /"},
		{name: "bad percent", uri: "ldap://127.0.0.1:1/%ZZ", message: "invalid URL escape"},
		{name: "invalid UTF-8", uri: "ldap://127.0.0.1:1/%FF", message: "not valid UTF-8"},
		{name: "raw slash in DN", uri: "ldap://127.0.0.1:1/cn=a/ou=b", message: "percent-encode reserved /"},
		{name: "invalid DN", uri: "ldap://127.0.0.1:1/cn%2Cdc%3Dx", message: "URL DN"},
		{name: "invalid attr", uri: "ldap://127.0.0.1:1/?cn%2Csn", message: "attribute description"},
		{name: "invalid scope", uri: "ldap://127.0.0.1:1/??children", message: "URL scope"},
		{name: "invalid filter", uri: "ldap://127.0.0.1:1/???%28uid%3D", message: "URL filter"},
		{name: "empty extension", uri: "ldap://127.0.0.1:1/????", message: "empty extensions"},
		{name: "extra component", uri: "ldap://127.0.0.1:1/?????extra", message: "more than four"},
		{name: "invalid extension", uri: "ldap://127.0.0.1:1/????1..2", message: "extension type"},
		{name: "critical extension", uri: "ldap://127.0.0.1:1/????!x-direct", message: "unsupported critical"},
		{name: "fragment", uri: "ldap://127.0.0.1:1/#fragment", message: "fragments are not permitted"},
		{name: "empty fragment", uri: "ldap://127.0.0.1:1/#", message: "fragments are not permitted"},
	}
	for _, mode := range []string{"-url-search=false", "-url-search=true"} {
		for _, test := range tests {
			t.Run(mode+"/"+test.name, func(t *testing.T) {
				stdout, stderr, exitCode := runLDAPClientCommand([]string{
					"ldapsearch", "-H", test.uri, mode, "-x", "-LLL",
				}, "")
				if exitCode == 0 || stdout != "" || !strings.Contains(stderr, test.message) {
					t.Fatalf("direct URL exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
				}
				if strings.Contains(stderr, "connect to") {
					t.Fatalf("direct URL validation attempted a connection: %q", stderr)
				}
			})
		}
	}
}

func TestLDAPSearchDirectURLStripsQueryAndPreservesTLSHost(t *testing.T) {
	parsed, err := parseLDAPSearchDirectURL(
		"ldaps://LDAP.Example:1636/dc%3Dexample?cn?base?%28objectClass%3D%2A%29",
	)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.dialURI != "ldaps://LDAP.Example:1636" {
		t.Fatalf("dial URI = %q", parsed.dialURI)
	}
	options := ldapClientOptions{uri: parsed.dialURI, timeout: defaultLDAPClientTimeout}
	flags := flag.NewFlagSet("ldapsearch", flag.ContinueOnError)
	_, dialURI, tlsConfig, err := options.connectionConfiguration(flags)
	if err != nil {
		t.Fatal(err)
	}
	if dialURI != parsed.dialURI || tlsConfig.ServerName != "LDAP.Example" ||
		tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("dial URI=%q TLS config=%#v", dialURI, tlsConfig)
	}
}

func TestLDAPSearchDirectURLPreservesHostDuringRealLDAPSHandshake(t *testing.T) {
	serverTLS, certificatePEM := newLDAPClientToolTLSConfig(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"-url-search=false", "-url-search=true"} {
		t.Run(mode, func(t *testing.T) {
			requests := make(chan ldapwire.SearchRequest, 1)
			uri := startLDAPClientTLSWireFixture(t, serverTLS.Clone(), func(message ldapwire.Message) ([][]byte, error) {
				switch request := message.Request.(type) {
				case ldapwire.BindRequest:
					return [][]byte{ldapwire.EncodeBindResponse(message.ID,
						ldapwire.Result{Code: ldapwire.ResultSuccess}, nil)}, nil
				case ldapwire.SearchRequest:
					requests <- request
					return [][]byte{ldapwire.EncodeSearchResultDone(message.ID,
						ldapwire.Result{Code: ldapwire.ResultSuccess}, nil)}, nil
				default:
					return nil, nil
				}
			})
			uri = strings.Replace(uri, "127.0.0.1", "localhost", 1)
			directURL := uri + "/dc%3Dexample?dc?base?%28objectClass%3D%2A%29"
			stdout, stderr, exitCode := runLDAPClientCommand([]string{
				"ldapsearch", "-H", directURL, mode, "-x", "-tls-ca", caPath, "-LLL",
			}, "")
			if exitCode != 0 || stdout != "" || stderr != "" {
				t.Fatalf("LDAPS direct URL exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
			}
			want := ldapSearchURLRequest{
				scope: directory.ScopeWholeSubtree, filterKind: directory.FilterPresent, attribute: "objectClass",
			}
			if mode == "-url-search=true" {
				want.baseDN, want.scope, want.attributes = "dc=example", directory.ScopeBase, []string{"dc"}
			}
			assertLDAPSearchURLRequest(t, awaitLDAPClientWireMessageValue(t, requests), want)
		})
	}
}

func TestLDAPSearchURLStartTLSVerifiesTarget(t *testing.T) {
	serverTLS, certificatePEM := newLDAPClientToolTLSConfig(t)
	uri := startLDAPClientToolServer(t, serverTLS) + "/dc=ignored?cn?one?%28uid%3Dignored%29"
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"-url-search=false", "-url-search=true"} {
		t.Run(mode, func(t *testing.T) {
			args := []string{
				"ldapsearch", "-H", uri, mode, "-x", "-ZZ", "-tls-ca", caPath,
				"-b", clientToolBaseDN, "-s", "base", "-LLL",
			}
			stdout, stderr, code := runLDAPClientCommand(append(args, "(objectClass=*)", "dc"), "")
			if code != 0 || stderr != "" || !strings.Contains(stdout, "dn: "+clientToolBaseDN) {
				t.Fatalf("StartTLS URL search exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			stdout, stderr, code = runLDAPClientCommand(append(args,
				"-tls-server-name", "wrong.example", "(objectClass=*)", "dc"), "")
			if code == 0 || stdout != "" || !strings.Contains(stderr, "wrong.example") ||
				!strings.Contains(stderr, "certificate") {
				t.Fatalf("StartTLS URL accepted wrong peer identity: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestLDAPSearchDirectURLDoesNotReplaceReferralURLSemantics(t *testing.T) {
	providerRequests := make(chan ldapwire.SearchRequest, 1)
	provider := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		request, ok := message.Request.(ldapwire.SearchRequest)
		if !ok {
			return nil, nil
		}
		providerRequests <- request
		return [][]byte{ldapwire.EncodeSearchResultDone(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		)}, nil
	})
	referral := provider.uri +
		"/ou%3Dtarget%2Cdc%3Dexample%2Cdc%3Dcom?description?sub?%28uid%3Dreferral%29"
	source := startLDAPClientWireFixture(t, searchReferralFixtureHandler(referral))
	initialURL := source.uri +
		"/ou%3Dsource%2Cdc%3Dexample%2Cdc%3Dcom?cn?one?%28uid%3Dinitial%29"

	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapsearch", "-H", initialURL, "-url-search", "-x", "-C", "-LLL",
	}, "")
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("direct referral search exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	request := awaitLDAPClientWireMessageValue(t, providerRequests)
	if request.BaseDN != "ou=target,dc=example,dc=com" ||
		request.Scope != directory.ScopeWholeSubtree ||
		request.Filter.Kind != directory.FilterEquality || request.Filter.Attribute != "uid" ||
		string(request.Filter.Assertion) != "initial" ||
		!reflect.DeepEqual(request.Attributes, []string{"cn"}) {
		t.Fatalf("referred direct URL request = %#v", request)
	}
}

func TestOpenLDAP213LDAPSearchDirectURLExplicitPrecedenceDifferential(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") != "1" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 to run the OpenLDAP direct URL differential")
	}
	if os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" ||
		os.Getenv("OPENLDAP_COMMIT") != openLDAPClientToolsCommit {
		t.Skip("requires the pinned verified OpenLDAP 2.6.13 reference")
	}
	referenceTool := filepath.Join(os.Getenv("OPENLDAP_BUILD"), "clients", "tools", "ldapsearch")
	if _, err := os.Stat(referenceTool); err != nil {
		t.Fatalf("find pinned OpenLDAP ldapsearch: %v", err)
	}
	runReference := func(arguments ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, referenceTool, arguments...)
		command.Env = append(os.Environ(), "LDAPNOINIT=1", "LC_ALL=C")
		return command.CombinedOutput()
	}

	requests := make(chan ldapwire.SearchRequest, 10)
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		request, ok := message.Request.(ldapwire.SearchRequest)
		if !ok {
			return nil, nil
		}
		requests <- request
		return [][]byte{ldapwire.EncodeSearchResultDone(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		)}, nil
	})
	fullURL := fixture.uri + "/dc%3Dignored?description?base?%28uid%3Dbob%29?x-direct"
	arguments := []string{
		"-H", fullURL, "-x", "-LLL", "-b", "dc=example,dc=com", "-s", "one",
		"(uid=alice)", "uid",
	}

	localStdout, localStderr, localExit := runLDAPClientCommand(
		append([]string{"ldapsearch"}, arguments...),
		"",
	)
	if localExit != 0 || localStdout != "" || localStderr != "" {
		t.Fatalf("ldap-go exit=%d stdout=%q stderr=%q", localExit, localStdout, localStderr)
	}
	localRequest := awaitLDAPClientWireMessageValue(t, requests)
	referenceOutput, referenceErr := runReference(arguments...)
	if referenceErr != nil || len(referenceOutput) != 0 {
		t.Fatalf("OpenLDAP ldapsearch: %v output=%q", referenceErr, referenceOutput)
	}
	referenceRequest := awaitLDAPClientWireMessageValue(t, requests)
	if !reflect.DeepEqual(localRequest, referenceRequest) {
		t.Fatalf("explicit precedence differs: ldap-go=%#v OpenLDAP=%#v", localRequest, referenceRequest)
	}

	plainSlashArguments := []string{"-H", fixture.uri + "/", "-x", "-LLL"}
	localStdout, localStderr, localExit = runLDAPClientCommand(
		append([]string{"ldapsearch"}, plainSlashArguments...),
		"",
	)
	if localExit != 0 || localStdout != "" || localStderr != "" {
		t.Fatalf("ldap-go slash URI exit=%d stdout=%q stderr=%q", localExit, localStdout, localStderr)
	}
	localSlashRequest := awaitLDAPClientWireMessageValue(t, requests)
	referenceOutput, referenceErr = runReference(plainSlashArguments...)
	if referenceErr != nil || len(referenceOutput) != 0 {
		t.Fatalf("OpenLDAP slash URI ldapsearch: %v output=%q", referenceErr, referenceOutput)
	}
	referenceSlashRequest := awaitLDAPClientWireMessageValue(t, requests)
	if localSlashRequest.BaseDN != referenceSlashRequest.BaseDN ||
		localSlashRequest.Scope != referenceSlashRequest.Scope ||
		localSlashRequest.Filter.Kind != referenceSlashRequest.Filter.Kind ||
		!strings.EqualFold(localSlashRequest.Filter.Attribute, referenceSlashRequest.Filter.Attribute) ||
		!reflect.DeepEqual(localSlashRequest.Attributes, referenceSlashRequest.Attributes) {
		t.Fatalf(
			"plain slash URI differs: ldap-go=%#v OpenLDAP=%#v",
			localSlashRequest,
			referenceSlashRequest,
		)
	}

	localStdout, localStderr, localExit = runLDAPClientCommand([]string{
		"ldapsearch", "-H", fullURL, "-x", "-LLL",
	}, "")
	if localExit != 0 || localStdout != "" || localStderr != "" {
		t.Fatalf("ldap-go URL-only exit=%d stdout=%q stderr=%q", localExit, localStdout, localStderr)
	}
	localURLRequest := awaitLDAPClientWireMessageValue(t, requests)
	referenceOutput, referenceErr = runReference(
		"-H",
		fullURL,
		"-x",
		"-LLL",
	)
	if referenceErr != nil || len(referenceOutput) != 0 {
		t.Fatalf("OpenLDAP URL-only ldapsearch: %v output=%q", referenceErr, referenceOutput)
	}
	referenceURLRequest := awaitLDAPClientWireMessageValue(t, requests)
	assertLDAPSearchURLRequest(t, localURLRequest, ldapSearchURLRequest{
		scope:      directory.ScopeWholeSubtree,
		filterKind: directory.FilterPresent,
		attribute:  "objectClass",
	})
	if referenceURLRequest.BaseDN != "" ||
		referenceURLRequest.Scope != directory.ScopeWholeSubtree ||
		referenceURLRequest.Filter.Kind != directory.FilterPresent ||
		!strings.EqualFold(referenceURLRequest.Filter.Attribute, "objectClass") ||
		len(referenceURLRequest.Attributes) != 0 {
		t.Fatalf("unexpected OpenLDAP URL-only request = %#v", referenceURLRequest)
	}

	localStdout, localStderr, localExit = runLDAPClientCommand([]string{
		"ldapsearch", "-H", fullURL, "-x", "-LLL", "uid",
	}, "")
	if localExit != 0 || localStdout != "" || localStderr != "" {
		t.Fatalf("ldap-go URL attrs override exit=%d stdout=%q stderr=%q", localExit, localStdout, localStderr)
	}
	localAttrsRequest := awaitLDAPClientWireMessageValue(t, requests)
	referenceOutput, referenceErr = runReference(
		"-H",
		fullURL,
		"-x",
		"-LLL",
		"uid",
	)
	if referenceErr != nil || len(referenceOutput) != 0 {
		t.Fatalf("OpenLDAP URL attrs ldapsearch: %v output=%q", referenceErr, referenceOutput)
	}
	referenceAttrsRequest := awaitLDAPClientWireMessageValue(t, requests)
	if !reflect.DeepEqual(localAttrsRequest.Attributes, []string{"uid"}) ||
		localAttrsRequest.Filter.Kind != directory.FilterPresent ||
		!strings.EqualFold(localAttrsRequest.Filter.Attribute, "objectClass") ||
		!reflect.DeepEqual(referenceAttrsRequest.Attributes, []string{"uid"}) ||
		referenceAttrsRequest.Filter.Kind != directory.FilterPresent {
		t.Fatalf(
			"direct positional attrs precedence: ldap-go=%#v OpenLDAP=%#v",
			localAttrsRequest,
			referenceAttrsRequest,
		)
	}
	for _, test := range []struct {
		name string
		uri  string
		args []string
	}{
		{name: "DN only", uri: fixture.uri + "/dc%3Dignored"},
		{name: "empty URL components", uri: fixture.uri + "/???"},
		{name: "explicit base only", uri: fullURL, args: []string{"-b", "dc=explicit"}},
		{name: "explicit scope only", uri: fullURL, args: []string{"-s", "one"}},
		{name: "explicit filter only", uri: fullURL, args: []string{"(uid=explicit)"}},
		{name: "plain URI attributes", uri: fixture.uri, args: []string{"uid", "cn"}},
		{name: "URL list space failover", uri: unavailableLDAPClientURI(t) + "/dc%3Dunused " + fullURL},
		{name: "URL list comma failover", uri: unavailableLDAPClientURI(t) + "/dc%3Dunused," + fullURL},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"-H", test.uri, "-x", "-LLL"}, test.args...)
			localOut, localErr, code := runLDAPClientCommand(append([]string{"ldapsearch"}, args...), "")
			if code != 0 || localOut != "" || localErr != "" {
				t.Fatalf("ldap-go exit=%d stdout=%q stderr=%q", code, localOut, localErr)
			}
			local := awaitLDAPClientWireMessageValue(t, requests)
			output, err := runReference(args...)
			if err != nil || len(output) != 0 {
				t.Fatalf("OpenLDAP: %v output=%q", err, output)
			}
			reference := awaitLDAPClientWireMessageValue(t, requests)
			// Attribute descriptions are case-insensitive on the wire.
			local.Filter.Attribute = strings.ToLower(local.Filter.Attribute)
			reference.Filter.Attribute = strings.ToLower(reference.Filter.Attribute)
			if !reflect.DeepEqual(local, reference) {
				t.Fatalf("-H requests differ: ldap-go=%#v OpenLDAP=%#v", local, reference)
			}
		})
	}
	for _, suffix := range []string{
		"/dc=ignored,dc=example",
		"/dc%3Dignored%2Cdc%3Dexample",
		"/dc%3Dignored?cn,sn?one?%28uid%3Dignored%29",
		"/???%28cn%3Da%2Cb%29",
	} {
		t.Run("reject comma "+suffix, func(t *testing.T) {
			args := []string{"-H", fixture.uri + suffix, "-x", "-LLL"}
			_, localErr, code := runLDAPClientCommand(append([]string{"ldapsearch"}, args...), "")
			output, err := runReference(args...)
			if code != 1 || err == nil || len(output) == 0 || localErr == "" {
				t.Fatalf("comma rejection differs: ldap-go=%d %q OpenLDAP=%v %q", code, localErr, err, output)
			}
			if failure, ok := err.(*exec.ExitError); !ok || failure.ExitCode() != code {
				t.Fatalf("OpenLDAP comma rejection exit code: %v", err)
			}
			select {
			case request := <-requests:
				t.Fatalf("rejected URL sent a search: %#v", request)
			default:
			}
		})
	}

	// Retain fail-closed handling of unsupported critical URL extensions.
	criticalURL := fixture.uri + "/????!x-direct"
	_, localError, localExit := runLDAPClientCommand([]string{
		"ldapsearch", "-H", criticalURL, "-x", "-LLL",
	}, "")
	if localExit == 0 || !strings.Contains(localError, "unsupported critical") {
		t.Fatalf("ldap-go critical URL exit=%d stderr=%q", localExit, localError)
	}
	referenceOutput, referenceErr = runReference(
		"-H",
		criticalURL,
		"-x",
		"-LLL",
	)
	if referenceErr != nil || len(referenceOutput) != 0 {
		t.Fatalf("OpenLDAP critical URL ldapsearch: %v output=%q", referenceErr, referenceOutput)
	}
	_ = awaitLDAPClientWireMessageValue(t, requests)

	badScope := []string{"-H", criticalURL, "-x", "-s", "invalid"}
	_, localError, localExit = runLDAPClientCommand(append([]string{"ldapsearch"}, badScope...), "")
	referenceError, referenceErr := runReference(badScope...)
	if localExit == 0 || referenceErr == nil ||
		!bytes.Contains([]byte(localError), []byte("-s must be")) ||
		!bytes.Contains(referenceError, []byte("scope should be")) {
		t.Fatalf(
			"scope/URL error order differs: ldap-go exit=%d stderr=%q; OpenLDAP err=%v output=%q",
			localExit,
			localError,
			referenceErr,
			referenceError,
		)
	}
}

type ldapSearchURLRequest struct {
	baseDN     string
	scope      directory.Scope
	filterKind directory.FilterKind
	attribute  string
	assertion  string
	attributes []string
}

func assertLDAPSearchURLRequest(
	t *testing.T,
	request ldapwire.SearchRequest,
	want ldapSearchURLRequest,
) {
	t.Helper()
	if request.BaseDN != want.baseDN || request.Scope != want.scope ||
		request.Filter.Kind != want.filterKind || request.Filter.Attribute != want.attribute ||
		string(request.Filter.Assertion) != want.assertion ||
		!slices.Equal(request.Attributes, want.attributes) {
		t.Fatalf("direct URL request = %#v, want %#v", request, want)
	}
}
