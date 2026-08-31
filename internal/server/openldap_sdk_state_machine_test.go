package server

import (
	"path/filepath"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
	"github.com/wangle201210/ldap-go/internal/testutil/ldapdiff"
)

func TestOpenLDAPReferenceGoLDAPSDKStateMachineDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServer(t, tools, nil)
	defer stopOpenLDAP()

	store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	seedCoreReferenceDirectory(t, store)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	defer stopLDAPGo()
	ldapGoURI := "ldap://" + ldapGoAddress
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}

	options := ldapdiff.Options{
		IgnoreDiagnostic: true,
		IgnoreAttributes: map[string]struct{}{
			"userpassword": {},
		},
		OpaqueControlValues: map[string]struct{}{
			ldapdiff.PagingControlOID: {},
		},
		NormalizeDN: func(value string) (string, error) {
			dn, normalizeErr := registry.NormalizeDN(value)
			if normalizeErr != nil {
				return "", normalizeErr
			}
			return dn.Key(), nil
		},
	}

	assertSDKURIs(t, openLDAPURI, ldapGoURI, options, "anonymous bind", 0,
		func(client *ldap.Conn) ldapdiff.Outcome {
			return ldapdiff.ResultOutcome(client.UnauthenticatedBind(""))
		})
	assertSDKURIs(t, openLDAPURI, ldapGoURI, options, "invalid root bind",
		ldap.LDAPResultInvalidCredentials,
		func(client *ldap.Conn) ldapdiff.Outcome {
			return ldapdiff.ResultOutcome(client.Bind(
				"cn=admin,dc=example,dc=com",
				"wrong",
			))
		})

	pair, err := ldapdiff.Dial(openLDAPURI, ldapGoURI, options)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Close()

	initialReference, initialCandidate := assertSDKPair(
		t,
		pair,
		"anonymous initial snapshot",
		0,
		sdkSnapshotOperation(options),
	)
	assertSDKEntryCount(t, "anonymous initial snapshot", initialReference, 5)
	assertSDKPair(t, pair, "root bind", 0, func(client *ldap.Conn) ldapdiff.Outcome {
		return ldapdiff.ResultOutcome(client.Bind(
			"cn=admin,dc=example,dc=com",
			"secret",
		))
	})

	for _, test := range []struct {
		name        string
		code        uint16
		wantEntries int
		request     func() *ldap.SearchRequest
	}{
		{
			name:        "base search",
			code:        0,
			wantEntries: 1,
			request: func() *ldap.SearchRequest {
				return ldap.NewSearchRequest(
					"uid=alice,ou=people,dc=example,dc=com",
					ldap.ScopeBaseObject,
					ldap.NeverDerefAliases,
					0,
					0,
					false,
					"(objectClass=*)",
					[]string{"objectClass", "uid", "cn", "sn"},
					nil,
				)
			},
		},
		{
			name:        "missing base",
			code:        ldap.LDAPResultNoSuchObject,
			wantEntries: 0,
			request: func() *ldap.SearchRequest {
				return ldap.NewSearchRequest(
					"uid=missing,ou=people,dc=example,dc=com",
					ldap.ScopeBaseObject,
					ldap.NeverDerefAliases,
					0,
					0,
					false,
					"(objectClass=*)",
					[]string{"1.1"},
					nil,
				)
			},
		},
		{
			name:        "one-level compound filter",
			code:        0,
			wantEntries: 2,
			request: func() *ldap.SearchRequest {
				return ldap.NewSearchRequest(
					"ou=people,dc=example,dc=com",
					ldap.ScopeSingleLevel,
					ldap.NeverDerefAliases,
					0,
					0,
					false,
					"(&(|(uid=alice)(uid=bob))(!(sn=Carol)))",
					[]string{"uid", "cn"},
					nil,
				)
			},
		},
		{
			name:        "subtree substring filter",
			code:        0,
			wantEntries: 1,
			request: func() *ldap.SearchRequest {
				return ldap.NewSearchRequest(
					"dc=example,dc=com",
					ldap.ScopeWholeSubtree,
					ldap.NeverDerefAliases,
					0,
					0,
					false,
					"(cn=*LI*)",
					[]string{"uid", "cn"},
					nil,
				)
			},
		},
		{
			name:        "types only",
			code:        0,
			wantEntries: 1,
			request: func() *ldap.SearchRequest {
				return ldap.NewSearchRequest(
					"uid=alice,ou=people,dc=example,dc=com",
					ldap.ScopeBaseObject,
					ldap.NeverDerefAliases,
					0,
					0,
					true,
					"(objectClass=*)",
					[]string{"uid", "cn"},
					nil,
				)
			},
		},
		{
			name:        "size limit",
			code:        ldap.LDAPResultSizeLimitExceeded,
			wantEntries: 2,
			request: func() *ldap.SearchRequest {
				return ldap.NewSearchRequest(
					"ou=people,dc=example,dc=com",
					ldap.ScopeSingleLevel,
					ldap.NeverDerefAliases,
					2,
					0,
					false,
					"(objectClass=inetOrgPerson)",
					[]string{"uid"},
					nil,
				)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			reference, _ := assertSDKPair(t, pair, test.name, test.code,
				func(client *ldap.Conn) ldapdiff.Outcome {
					result, searchErr := client.Search(test.request())
					if test.code == ldap.LDAPResultSizeLimitExceeded {
						return ldapdiff.SearchCountOutcome(result, searchErr, options)
					}
					return ldapdiff.SearchOutcome(result, searchErr, options)
				})
			assertSDKEntryCount(t, test.name, reference, test.wantEntries)
		})
	}

	pagedReference, _ := assertSDKPair(t, pair, "paged subtree search", 0,
		func(client *ldap.Conn) ldapdiff.Outcome {
			result, searchErr := client.SearchWithPaging(ldap.NewSearchRequest(
				"ou=people,dc=example,dc=com",
				ldap.ScopeSingleLevel,
				ldap.NeverDerefAliases,
				0,
				0,
				false,
				"(objectClass=inetOrgPerson)",
				[]string{"uid", "cn"},
				nil,
			), 2)
			return ldapdiff.SearchOutcome(result, searchErr, options)
		})
	assertSDKEntryCount(t, "paged subtree search", pagedReference, 3)

	archiveDN := "ou=sdk-archive,dc=example,dc=com"
	assertSDKPair(t, pair, "add archive", 0,
		func(client *ldap.Conn) ldapdiff.Outcome {
			request := ldap.NewAddRequest(archiveDN, nil)
			request.Attribute("objectClass", []string{"top", "organizationalUnit"})
			request.Attribute("ou", []string{"sdk-archive"})
			return ldapdiff.ResultOutcome(client.Add(request))
		})

	userDN := "uid=sdk-user,ou=people,dc=example,dc=com"
	assertSDKPair(t, pair, "add SDK user", 0,
		func(client *ldap.Conn) ldapdiff.Outcome {
			return ldapdiff.ResultOutcome(client.Add(sdkDifferentialPersonAdd(
				userDN,
				"sdk-user",
				"initial-secret",
			)))
		})
	assertSDKPair(t, pair, "duplicate add", ldap.LDAPResultEntryAlreadyExists,
		func(client *ldap.Conn) ldapdiff.Outcome {
			return ldapdiff.ResultOutcome(client.Add(sdkDifferentialPersonAdd(
				userDN,
				"sdk-user",
				"initial-secret",
			)))
		})
	afterAdd, _ := assertSDKPair(
		t, pair, "snapshot after add", 0, sdkSnapshotOperation(options),
	)
	assertSDKEntryCount(t, "snapshot after add", afterAdd, 7)

	assertSDKPair(t, pair, "compare true", ldap.LDAPResultCompareTrue,
		func(client *ldap.Conn) ldapdiff.Outcome {
			matched, compareErr := client.Compare(userDN, "cn", "SDK USER")
			return ldapdiff.CompareOutcome(matched, compareErr)
		})
	assertSDKPair(t, pair, "compare false", ldap.LDAPResultCompareFalse,
		func(client *ldap.Conn) ldapdiff.Outcome {
			matched, compareErr := client.Compare(userDN, "cn", "Other")
			return ldapdiff.CompareOutcome(matched, compareErr)
		})
	assertSDKPair(t, pair, "compare missing attribute", ldap.LDAPResultNoSuchAttribute,
		func(client *ldap.Conn) ldapdiff.Outcome {
			matched, compareErr := client.Compare(userDN, "mail", "missing@example.test")
			return ldapdiff.CompareOutcome(matched, compareErr)
		})

	assertSDKPair(t, pair, "mixed modify", 0,
		func(client *ldap.Conn) ldapdiff.Outcome {
			request := ldap.NewModifyRequest(userDN, nil)
			request.Replace("cn", []string{"SDK User Updated"})
			request.Add("mail", []string{"sdk-user@example.test"})
			request.Add("description", []string{"alpha", "beta"})
			return ldapdiff.ResultOutcome(client.Modify(request))
		})
	afterModify, _ := assertSDKPair(
		t, pair, "snapshot after modify", 0, sdkSnapshotOperation(options),
	)
	assertSDKEntryCount(t, "snapshot after modify", afterModify, 7)

	assertSDKPair(t, pair, "password modify", 0,
		func(client *ldap.Conn) ldapdiff.Outcome {
			_, passwordErr := client.PasswordModify(ldap.NewPasswordModifyRequest(
				userDN,
				"",
				"changed-secret",
			))
			return ldapdiff.ResultOutcome(passwordErr)
		})
	assertSDKURIs(t, openLDAPURI, ldapGoURI, options, "old password rejected",
		ldap.LDAPResultInvalidCredentials,
		func(client *ldap.Conn) ldapdiff.Outcome {
			return ldapdiff.ResultOutcome(client.Bind(userDN, "initial-secret"))
		})
	assertSDKURIs(t, openLDAPURI, ldapGoURI, options, "new password accepted", 0,
		func(client *ldap.Conn) ldapdiff.Outcome {
			return ldapdiff.ResultOutcome(client.Bind(userDN, "changed-secret"))
		})

	childDN := "cn=profile," + userDN
	assertSDKPair(t, pair, "add child", 0,
		func(client *ldap.Conn) ldapdiff.Outcome {
			request := ldap.NewAddRequest(childDN, nil)
			request.Attribute("objectClass", []string{"top", "organizationalRole"})
			request.Attribute("cn", []string{"profile"})
			return ldapdiff.ResultOutcome(client.Add(request))
		})
	assertSDKPair(t, pair, "delete non-leaf", ldap.LDAPResultNotAllowedOnNonLeaf,
		func(client *ldap.Conn) ldapdiff.Outcome {
			return ldapdiff.ResultOutcome(client.Del(ldap.NewDelRequest(userDN, nil)))
		})

	renamedDN := "uid=sdk-renamed," + archiveDN
	renamedChildDN := "cn=profile," + renamedDN
	assertSDKPair(t, pair, "move subtree", 0,
		func(client *ldap.Conn) ldapdiff.Outcome {
			return ldapdiff.ResultOutcome(client.ModifyDN(ldap.NewModifyDNRequest(
				userDN,
				"uid=sdk-renamed",
				true,
				archiveDN,
			)))
		})
	afterMove, _ := assertSDKPair(
		t, pair, "snapshot after move", 0, sdkSnapshotOperation(options),
	)
	assertSDKEntryCount(t, "snapshot after move", afterMove, 8)

	for _, deletion := range []struct {
		name string
		dn   string
		code uint16
	}{
		{name: "delete moved child", dn: renamedChildDN},
		{name: "delete moved user", dn: renamedDN},
		{name: "delete archive", dn: archiveDN},
		{name: "delete missing user", dn: renamedDN, code: ldap.LDAPResultNoSuchObject},
	} {
		assertSDKPair(t, pair, deletion.name, deletion.code,
			func(client *ldap.Conn) ldapdiff.Outcome {
				return ldapdiff.ResultOutcome(client.Del(ldap.NewDelRequest(deletion.dn, nil)))
			})
	}
	finalReference, finalCandidate := assertSDKPair(
		t,
		pair,
		"final snapshot",
		0,
		sdkSnapshotOperation(options),
	)
	assertSDKEntryCount(t, "final snapshot", finalReference, 5)
	if err := ldapdiff.CompareOutcomes(initialReference, finalReference, options); err != nil {
		t.Fatalf("OpenLDAP final state did not return to its initial snapshot: %v", err)
	}
	if err := ldapdiff.CompareOutcomes(initialCandidate, finalCandidate, options); err != nil {
		t.Fatalf("ldap-go final state did not return to its initial snapshot: %v", err)
	}
}

func assertSDKEntryCount(
	t *testing.T,
	name string,
	outcome ldapdiff.Outcome,
	want int,
) {
	t.Helper()
	got := len(outcome.Entries)
	if outcome.EntryCount != nil {
		got = *outcome.EntryCount
	}
	if got != want {
		t.Fatalf("%s entry count = %d, want %d", name, got, want)
	}
}

func assertSDKPair(
	t *testing.T,
	pair *ldapdiff.Pair,
	name string,
	wantCode uint16,
	operation ldapdiff.Operation,
) (ldapdiff.Outcome, ldapdiff.Outcome) {
	t.Helper()
	reference, candidate, err := pair.Observe(name, operation)
	if err != nil {
		t.Fatal(err)
	}
	if reference.Code != wantCode {
		t.Fatalf("%s result code = %d, want %d", name, reference.Code, wantCode)
	}
	t.Logf("SDK differential step passed: %s (result code %d)", name, wantCode)
	return reference, candidate
}

func assertSDKURIs(
	t *testing.T,
	referenceURI,
	candidateURI string,
	options ldapdiff.Options,
	name string,
	wantCode uint16,
	operation ldapdiff.Operation,
) {
	t.Helper()
	pair, err := ldapdiff.Dial(referenceURI, candidateURI, options)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Close()
	assertSDKPair(t, pair, name, wantCode, operation)
}

func sdkSnapshotOperation(options ldapdiff.Options) ldapdiff.Operation {
	return func(client *ldap.Conn) ldapdiff.Outcome {
		result, err := client.Search(ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"*"},
			nil,
		))
		return ldapdiff.SearchOutcome(result, err, options)
	}
}

func sdkDifferentialPersonAdd(dn, uid, password string) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{
		"top",
		"person",
		"organizationalPerson",
		"inetOrgPerson",
	})
	request.Attribute("uid", []string{uid})
	request.Attribute("cn", []string{"SDK User"})
	request.Attribute("sn", []string{"User"})
	request.Attribute("userPassword", []string{password})
	return request
}
