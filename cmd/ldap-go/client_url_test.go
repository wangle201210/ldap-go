package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

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
		"ldapsearch", "-H", directURL, "-x", "-LLL",
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
		"ldapsearch", "-H", directURL, "-x", "-LLL",
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
		"ldapsearch", "-H", directURL, "-x", "-LLL", "mail",
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
		"ldapsearch", "-H", fixture.uri + "/???", "-x", "-LLL",
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

func TestLDAPSearchPlainURIKeepsSlashAndFirstPositionalFilterSemantics(t *testing.T) {
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
	if exitCode == 0 || stdout != "" || !strings.Contains(stderr, "Bad search filter") {
		t.Fatalf("plain positional filter exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
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
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, exitCode := runLDAPClientCommand([]string{
				"ldapsearch", "-H", test.uri, "-x", "-LLL",
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
	requests := make(chan ldapwire.SearchRequest, 1)
	uri := startLDAPClientTLSWireFixture(t, serverTLS, func(message ldapwire.Message) ([][]byte, error) {
		switch request := message.Request.(type) {
		case ldapwire.BindRequest:
			return [][]byte{ldapwire.EncodeBindResponse(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			)}, nil
		case ldapwire.SearchRequest:
			requests <- request
			return [][]byte{ldapwire.EncodeSearchResultDone(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			)}, nil
		default:
			return nil, nil
		}
	})
	uri = strings.Replace(uri, "127.0.0.1", "localhost", 1)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	directURL := uri + "/dc%3Dexample%2Cdc%3Dcom?dc?base?%28objectClass%3D%2A%29"
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapsearch", "-H", directURL, "-x", "-tls-ca", caPath, "-LLL",
	}, "")
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("LDAPS direct URL exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	request := awaitLDAPClientWireMessageValue(t, requests)
	if request.BaseDN != "dc=example,dc=com" || request.Scope != directory.ScopeBase {
		t.Fatalf("LDAPS direct URL request = %#v", request)
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
		"ldapsearch", "-H", initialURL, "-x", "-C", "-LLL",
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
	referenceOutput, referenceErr := exec.Command(referenceTool, arguments...).CombinedOutput()
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
	referenceOutput, referenceErr = exec.Command(referenceTool, plainSlashArguments...).CombinedOutput()
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
	referenceOutput, referenceErr = exec.Command(
		referenceTool,
		"-H",
		fullURL,
		"-x",
		"-LLL",
	).CombinedOutput()
	if referenceErr != nil || len(referenceOutput) != 0 {
		t.Fatalf("OpenLDAP URL-only ldapsearch: %v output=%q", referenceErr, referenceOutput)
	}
	referenceURLRequest := awaitLDAPClientWireMessageValue(t, requests)
	assertLDAPSearchURLRequest(t, localURLRequest, ldapSearchURLRequest{
		baseDN:     "dc=ignored",
		scope:      directory.ScopeBase,
		filterKind: directory.FilterEquality,
		attribute:  "uid",
		assertion:  "bob",
		attributes: []string{"description"},
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
	referenceOutput, referenceErr = exec.Command(
		referenceTool,
		"-H",
		fullURL,
		"-x",
		"-LLL",
		"uid",
	).CombinedOutput()
	if referenceErr != nil || len(referenceOutput) != 0 {
		t.Fatalf("OpenLDAP URL attrs ldapsearch: %v output=%q", referenceErr, referenceOutput)
	}
	referenceAttrsRequest := awaitLDAPClientWireMessageValue(t, requests)
	if !reflect.DeepEqual(localAttrsRequest.Attributes, []string{"uid"}) ||
		localAttrsRequest.Filter.Kind != directory.FilterEquality ||
		string(localAttrsRequest.Filter.Assertion) != "bob" ||
		!reflect.DeepEqual(referenceAttrsRequest.Attributes, []string{"uid"}) ||
		referenceAttrsRequest.Filter.Kind != directory.FilterPresent {
		t.Fatalf(
			"direct positional attrs precedence: ldap-go=%#v OpenLDAP=%#v",
			localAttrsRequest,
			referenceAttrsRequest,
		)
	}

	criticalURL := fixture.uri + "/????!x-direct"
	_, localError, localExit := runLDAPClientCommand([]string{
		"ldapsearch", "-H", criticalURL, "-x", "-LLL",
	}, "")
	if localExit == 0 || !strings.Contains(localError, "unsupported critical") {
		t.Fatalf("ldap-go critical URL exit=%d stderr=%q", localExit, localError)
	}
	referenceOutput, referenceErr = exec.Command(
		referenceTool,
		"-H",
		criticalURL,
		"-x",
		"-LLL",
	).CombinedOutput()
	if referenceErr != nil || len(referenceOutput) != 0 {
		t.Fatalf("OpenLDAP critical URL ldapsearch: %v output=%q", referenceErr, referenceOutput)
	}
	_ = awaitLDAPClientWireMessageValue(t, requests)

	badScope := []string{"-H", criticalURL, "-x", "-s", "invalid"}
	_, localError, localExit = runLDAPClientCommand(append([]string{"ldapsearch"}, badScope...), "")
	referenceError, referenceErr := exec.Command(referenceTool, badScope...).CombinedOutput()
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
		!reflect.DeepEqual(request.Attributes, want.attributes) {
		t.Fatalf("direct URL request = %#v, want %#v", request, want)
	}
}
