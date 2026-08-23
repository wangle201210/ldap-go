package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPSearchDefaultErrorOutput(t *testing.T) {
	const (
		baseDN      = "ou=missing,dc=example,dc=com"
		matchedDN   = "dc=example,dc=com"
		diagnostic  = "the search base does not exist"
		referralURL = "ldap://provider.example/dc=example,dc=com"
	)
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.SearchRequest); !ok {
			return nil, nil
		}
		return [][]byte{ldapwire.EncodeSearchResultDone(
			message.ID,
			ldapwire.Result{
				Code:              ldap.LDAPResultNoSuchObject,
				MatchedDN:         matchedDN,
				DiagnosticMessage: diagnostic,
				Referrals:         []string{referralURL},
			},
			nil,
		)}, nil
	})

	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapsearch", "-H", fixture.uri, "-x", "-b", baseDN, "-s", "base",
		"(objectClass=*)", "1.1",
	}, "")
	want := "# extended LDIF\n" +
		"#\n" +
		"# LDAPv3\n" +
		"# base <" + baseDN + "> with scope baseObject\n" +
		"# filter: (objectClass=*)\n" +
		"# requesting: 1.1 \n" +
		"#\n\n" +
		"# search result\n" +
		"search: 2\n" +
		"result: 32 No such object\n" +
		"matchedDN: " + matchedDN + "\n" +
		"text: " + diagnostic + "\n" +
		"ref: " + referralURL + "\n\n" +
		"# numResponses: 1\n"
	if exitCode != ldap.LDAPResultNoSuchObject || stdout != want || stderr != "" {
		t.Fatalf(
			"ldapsearch default error exit=%d\nstdout=%q\nwant=%q\nstderr=%q",
			exitCode,
			stdout,
			want,
			stderr,
		)
	}
}

func TestLDAPSearchReferenceOutput(t *testing.T) {
	const (
		baseDN      = "dc=example,dc=com"
		referralURL = "ldap://provider.example/ou=people,dc=example,dc=com"
	)
	for _, test := range []struct {
		name string
		flag string
		ref  string
	}{
		{name: "default", ref: "ref: " + referralURL + "\n"},
		{name: "L", flag: "-L", ref: "# ref" + referralURL + "\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := startLDAPClientWireFixture(t, searchReferralFixtureHandler(referralURL))
			arguments := []string{
				"ldapsearch", "-H", fixture.uri, "-x", "-b", baseDN, "-s", "base",
			}
			if test.flag != "" {
				arguments = append(arguments, test.flag)
			}
			arguments = append(arguments, "(objectClass=*)", "1.1")
			stdout, stderr, exitCode := runLDAPClientCommand(arguments, "")
			if exitCode != 0 || stderr != "" ||
				!strings.Contains(stdout, "# search reference\n"+test.ref+"\n# search result\n") ||
				!strings.HasSuffix(stdout, "# numResponses: 2\n# numReferences: 1\n") {
				t.Fatalf(
					"ldapsearch reference %s exit=%d stdout=%q stderr=%q",
					test.name,
					exitCode,
					stdout,
					stderr,
				)
			}
		})
	}
}

func TestOpenLDAPReferenceLDAPSearchDefaultErrorAndReferenceOutput(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") == "" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 to run the OpenLDAP ldapsearch reference test")
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

	t.Run("error", func(t *testing.T) {
		const baseDN = "ou=missing,dc=example,dc=com"
		fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
			if _, ok := message.Request.(ldapwire.UnbindRequest); ok {
				return [][]byte{ldapwire.EncodeBindResponse(
					message.ID,
					ldapwire.Result{Code: ldap.LDAPResultSuccess},
					nil,
				)}, nil
			}
			if _, ok := message.Request.(ldapwire.SearchRequest); !ok {
				return nil, nil
			}
			return [][]byte{ldapwire.EncodeSearchResultDone(
				message.ID,
				ldapwire.Result{
					Code:              ldap.LDAPResultNoSuchObject,
					MatchedDN:         "dc=example,dc=com",
					DiagnosticMessage: "the search base does not exist",
					Referrals: []string{
						"ldap://provider.example/dc=example,dc=com",
					},
				},
				nil,
			)}, nil
		})
		assertLDAPSearchMatchesOpenLDAP(t, referenceTool, []string{
			"-H", fixture.uri, "-x", "-b", baseDN, "-s", "base",
			"(objectClass=*)", "1.1",
		})
	})

	t.Run("reference", func(t *testing.T) {
		const referralURL = "ldap://provider.example/ou=people,dc=example,dc=com"
		searchHandler := searchReferralFixtureHandler(referralURL)
		fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
			if _, ok := message.Request.(ldapwire.UnbindRequest); ok {
				return [][]byte{ldapwire.EncodeBindResponse(
					message.ID,
					ldapwire.Result{Code: ldap.LDAPResultSuccess},
					nil,
				)}, nil
			}
			return searchHandler(message)
		})
		for _, level := range [][]string{{}, {"-L"}} {
			arguments := []string{
				"-H", fixture.uri, "-x", "-b", "dc=example,dc=com", "-s", "base",
			}
			arguments = append(arguments, level...)
			arguments = append(arguments, "(objectClass=*)", "1.1")
			assertLDAPSearchMatchesOpenLDAP(t, referenceTool, arguments)
		}
	})
}
