package main

import (
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestParseLDAPReferralTargetRFC4516Fields(t *testing.T) {
	target, err := parseLDAPReferralTarget(
		"LDAP://local%68ost:0/%75id%3Dalice%2Cou%3Dpeople" +
			"?cn%2Cdescription%3Blang-en?subtree?%28uid%3Dalice%29" +
			"?x=%2C,%21X-StartTLS",
	)
	if err != nil {
		t.Fatalf("parseLDAPReferralTarget(): %v", err)
	}
	if target.endpoint != "ldap://localhost" ||
		target.dn != "uid=alice,ou=people" || !target.hasDN ||
		!target.hasAttributes ||
		!reflect.DeepEqual(target.attributes, []string{"cn", "description;lang-en"}) ||
		target.scope != ldap.ScopeWholeSubtree || !target.hasScope ||
		target.filter != "(uid=alice)" || !target.hasFilter ||
		!target.startTLS || !target.startTLSRequired {
		t.Fatalf("parsed referral target = %#v", target)
	}

	empty, err := parseLDAPReferralTarget("ldap:///")
	if err != nil {
		t.Fatalf("parse empty host and DN: %v", err)
	}
	if empty.endpoint != "ldap://localhost" || empty.hasDN || empty.hasAttributes ||
		empty.hasScope || empty.hasFilter {
		t.Fatalf("empty referral target = %#v", empty)
	}
}

func TestParseLDAPReferralTargetOpenLDAPScopeAliases(t *testing.T) {
	tests := []struct {
		value string
		want  int
	}{
		{value: "base", want: ldap.ScopeBaseObject},
		{value: "one", want: ldap.ScopeSingleLevel},
		{value: "onelevel", want: ldap.ScopeSingleLevel},
		{value: "sub", want: ldap.ScopeWholeSubtree},
		{value: "subtree", want: ldap.ScopeWholeSubtree},
		{value: "subord", want: ldap.ScopeChildren},
		{value: "subordinate", want: ldap.ScopeChildren},
		{value: "children", want: ldap.ScopeChildren},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			target, err := parseLDAPReferralTarget("ldap://example.test/??" + test.value)
			if err != nil {
				t.Fatalf("parse scope %q: %v", test.value, err)
			}
			if !target.hasScope || target.scope != test.want {
				t.Fatalf("scope %q = %d, has=%t", test.value, target.scope, target.hasScope)
			}
		})
	}
}

func TestParseLDAPReferralTargetCriticalExtensions(t *testing.T) {
	for _, value := range []string{
		"ldap://example.test/????!unsupported",
		"ldap://example.test/????!StartTLS=required",
		"ldap://example.test/????!StartTLS,!X-StartTLS",
	} {
		_, err := parseLDAPReferralTarget(value)
		var ldapErr *ldap.Error
		if !errors.As(err, &ldapErr) || ldapErr.ResultCode != ldap.LDAPResultNotSupported {
			t.Errorf("parseLDAPReferralTarget(%q) error = %v, want notSupported", value, err)
		}
	}
	for _, value := range []string{
		"ldap://example.test/????",
		"ldap://example.test/?????extra",
		"ldap://example.test/%ZZ",
		"ldap://user@example.test/",
		"ldap://example.test/??invalid",
		"ldap://[broken/",
		"ldap://example.test:not-a-port/",
		"ldap://example.test:65536/",
		"https://example.test/",
	} {
		_, err := parseLDAPReferralTarget(value)
		var ldapErr *ldap.Error
		if !errors.As(err, &ldapErr) || ldapErr.ResultCode != ldap.LDAPResultParamError {
			t.Errorf("parseLDAPReferralTarget(%q) error = %v, want paramError", value, err)
		}
	}
}

func TestLDAPSearchReferenceEmptyDNPreservesOriginalBase(t *testing.T) {
	const originalBase = "ou=source,dc=example,dc=com"
	tests := []struct {
		name      string
		urlSuffix string
		wantScope directory.Scope
	}{
		{name: "missing DN", wantScope: directory.ScopeBase},
		{name: "empty DN", urlSuffix: "/", wantScope: directory.ScopeBase},
		{name: "empty DN with scope", urlSuffix: "/??sub", wantScope: directory.ScopeWholeSubtree},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
			source := startLDAPClientWireFixture(t, searchReferralFixtureHandler(
				provider.uri+test.urlSuffix,
			))

			stdout, stderr, exitCode := runLDAPClientCommand([]string{
				"ldapsearch", "-H", source.uri, "-x", "-C", "-LLL",
				"-b", originalBase, "-s", "one", "(uid=alice)", "cn",
			}, "")
			if exitCode != 0 || stdout != "" || stderr != "" {
				t.Fatalf("ldapsearch exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
			}
			request := awaitLDAPClientWireMessageValue(t, providerRequests)
			if request.BaseDN != originalBase || request.Scope != test.wantScope {
				t.Fatalf(
					"referred search base=%q scope=%d, want base=%q scope=%d",
					request.BaseDN,
					request.Scope,
					originalBase,
					test.wantScope,
				)
			}
		})
	}
}

func TestLDAPSearchReferenceInvalidURLReturnsParamError(t *testing.T) {
	for _, referral := range []string{
		"ldap://example.test/??invalid",
		"ldap://example.test/%ZZ",
		"ldap://user@example.test/",
		"ldap://example.test:not-a-port/",
		"ldap://example.test/?????extra",
	} {
		t.Run(referral, func(t *testing.T) {
			source := startLDAPClientWireFixture(t, searchReferralFixtureHandler(referral))
			stdout, stderr, exitCode := runLDAPClientCommand([]string{
				"ldapsearch", "-H", source.uri, "-x", "-C", "-LLL",
				"-b", "ou=source,dc=example,dc=com", "-s", "one",
				"(objectClass=*)", "1.1",
			}, "")
			if exitCode != ldap.LDAPResultParamError || stdout != "" ||
				!strings.Contains(stderr, "(89)") {
				t.Fatalf("ldapsearch exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
			}
		})
	}
}

func TestLDAPSearchReferralURLAppliesOnlyDNAndScope(t *testing.T) {
	const targetBase = "ou=target,dc=example,dc=com"
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
	referral := provider.uri + "/ou%3Dtarget%2Cdc%3Dexample%2Cdc%3Dcom" +
		"?description%3Blang-fr?sub?%28uid%3Durl-filter%29"
	source := startLDAPClientWireFixture(t, searchReferralFixtureHandler(referral))

	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapsearch", "-H", source.uri, "-x", "-C", "-LLL",
		"-b", "ou=source,dc=example,dc=com", "-s", "one",
		"(uid=original)", "cn;lang-en",
	}, "")
	if exitCode != 0 || stdout != "" || stderr != "" {
		t.Fatalf("ldapsearch exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	request := awaitLDAPClientWireMessageValue(t, providerRequests)
	if request.BaseDN != targetBase || request.Scope != directory.ScopeWholeSubtree ||
		request.Filter.Kind != directory.FilterEquality || request.Filter.Attribute != "uid" ||
		string(request.Filter.Assertion) != "original" ||
		!reflect.DeepEqual(request.Attributes, []string{"cn;lang-en"}) {
		t.Fatalf("referred search request = %#v", request)
	}
}

func TestLDAPSearchReferralUnsupportedCriticalURLExtension(t *testing.T) {
	source := startLDAPClientWireFixture(t, searchReferralFixtureHandler(
		"ldap://example.test/????!unsupported",
	))
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapsearch", "-H", source.uri, "-x", "-C", "-LLL",
		"-b", "dc=example,dc=com", "(objectClass=*)", "1.1",
	}, "")
	if exitCode != ldap.LDAPResultNotSupported || stdout != "" ||
		!strings.Contains(stderr, "(92)") ||
		!strings.Contains(stderr, "unsupported critical extension") {
		t.Fatalf("ldapsearch exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestOpenLDAPReferenceLDAPSearchReferenceEmptyDNDifferential(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") == "" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 to run the OpenLDAP referral reference test")
	}
	if got := os.Getenv("OPENLDAP_REFERENCE_VERIFIED"); got != "1" {
		t.Fatalf("OPENLDAP_REFERENCE_VERIFIED = %q, want 1", got)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPClientToolsCommit {
		t.Fatalf("OPENLDAP_COMMIT = %q, want %q", got, openLDAPClientToolsCommit)
	}
	referenceTool, err := exec.LookPath("ldapsearch")
	if err != nil {
		t.Fatalf("find OpenLDAP ldapsearch: %v", err)
	}

	const originalBase = "ou=source,dc=example,dc=com"
	sourceRequests := make(chan ldapwire.SearchRequest, 2)
	providerRequests := make(chan ldapwire.SearchRequest, 2)
	provider := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		switch request := message.Request.(type) {
		case ldapwire.SearchRequest:
			providerRequests <- request
			return [][]byte{ldapwire.EncodeSearchResultDone(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			)}, nil
		case ldapwire.UnbindRequest:
			return [][]byte{nil}, nil
		default:
			return nil, nil
		}
	})
	source := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		switch request := message.Request.(type) {
		case ldapwire.SearchRequest:
			sourceRequests <- request
			return searchReferralResponses(message.ID, provider.uri+"/"), nil
		case ldapwire.UnbindRequest:
			return [][]byte{nil}, nil
		default:
			return nil, nil
		}
	})
	arguments := []string{
		"-H", source.uri, "-x", "-C", "-LLL",
		"-b", originalBase, "-s", "one", "(uid=alice)", "cn",
	}

	localStdout, localStderr, localExit := runLDAPClientCommand(
		append([]string{"ldapsearch"}, arguments...),
		"",
	)
	if localExit != 0 || localStdout != "" || localStderr != "" {
		t.Fatalf(
			"ldap-go ldapsearch exit=%d stdout=%q stderr=%q",
			localExit,
			localStdout,
			localStderr,
		)
	}
	localSourceRequest := awaitLDAPClientWireMessageValue(t, sourceRequests)
	localRequest := awaitLDAPClientWireMessageValue(t, providerRequests)

	referenceOutput, referenceErr := exec.Command(referenceTool, arguments...).CombinedOutput()
	if referenceErr != nil {
		t.Fatalf("OpenLDAP ldapsearch: %v\n%s", referenceErr, referenceOutput)
	}
	referenceSourceRequest := awaitLDAPClientWireMessageValue(t, sourceRequests)
	referenceRequest := awaitLDAPClientWireMessageValue(t, providerRequests)
	if localSourceRequest.BaseDN != originalBase || referenceSourceRequest.BaseDN != originalBase {
		t.Fatalf(
			"initial search bases: ldap-go=%q OpenLDAP=%q, want %q",
			localSourceRequest.BaseDN,
			referenceSourceRequest.BaseDN,
			originalBase,
		)
	}
	if localRequest.BaseDN != originalBase || localRequest.Scope != directory.ScopeBase {
		t.Fatalf("ldap-go expanded empty-DN referral search: %#v", localRequest)
	}
	// The pinned binary expands this search to the root despite passing
	// LDAP_PVT_URL_PARSE_NOEMPTY_DN. Keep the differential explicit while
	// requiring ldap-go to preserve the caller's security boundary.
	if referenceRequest.BaseDN != "" || referenceRequest.Scope != directory.ScopeBase ||
		!reflect.DeepEqual(localRequest.Filter, referenceRequest.Filter) ||
		!reflect.DeepEqual(localRequest.Attributes, referenceRequest.Attributes) {
		t.Fatalf("unexpected OpenLDAP empty-DN referral request: %#v", referenceRequest)
	}
}
