package server

import (
	"context"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	proxyAuthorizationRootDN       = "cn=admin,dc=example,dc=com"
	proxyAuthorizationRootPassword = "admin-secret"
	proxyAuthorizationBobDN        = "uid=bob,ou=people,dc=example,dc=com"
	proxyAuthorizationGroupDN      = "cn=proxy targets,dc=example,dc=com"
)

func TestParseSASLAuthorizationPolicy(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		value string
		want  saslAuthorizationPolicy
		valid bool
	}{
		{value: "none", valid: true},
		{value: "FROM", want: saslAuthorizationFrom, valid: true},
		{value: "to", want: saslAuthorizationTo, valid: true},
		{
			value: "any",
			want:  saslAuthorizationFrom | saslAuthorizationTo,
			valid: true,
		},
		{
			value: "both",
			want:  saslAuthorizationFrom | saslAuthorizationTo,
			valid: true,
		},
		{
			value: "all",
			want: saslAuthorizationFrom |
				saslAuthorizationTo |
				saslAuthorizationAll,
			valid: true,
		},
		{value: "sometimes"},
	} {
		t.Run(test.value, func(t *testing.T) {
			t.Parallel()

			got, err := parseSASLAuthorizationPolicy(test.value)
			if (err == nil) != test.valid || got != test.want {
				t.Fatalf(
					"parseSASLAuthorizationPolicy(%q) = %d, %v; want %d, valid %t",
					test.value,
					got,
					err,
					test.want,
					test.valid,
				)
			}
		})
	}
}

func TestLoadSASLAuthorizationPolicyRejectsMultipleValues(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcAuthzPolicy",
				Values:      stringValues("to", "from"),
			}},
		}, false)
	}); err != nil {
		t.Fatalf("seed duplicate olcAuthzPolicy: %v", err)
	}
	err := store.View(context.Background(), func(reader storage.Reader) error {
		_, err := loadSASLRuntimeConfiguration(reader)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "multiple values") {
		t.Fatalf("duplicate olcAuthzPolicy error = %v", err)
	}
}

func TestProxyAuthorizationOperationSupport(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		request   ldapwire.Request
		supported bool
	}{
		{name: "search", request: ldapwire.SearchRequest{}, supported: true},
		{name: "compare", request: ldapwire.CompareRequest{}, supported: true},
		{name: "add", request: ldapwire.AddRequest{}, supported: true},
		{name: "modify", request: ldapwire.ModifyRequest{}, supported: true},
		{name: "delete", request: ldapwire.DeleteRequest{}, supported: true},
		{name: "modify DN", request: ldapwire.ModifyDNRequest{}, supported: true},
		{
			name: "password modify",
			request: ldapwire.ExtendedRequest{
				Name: passwordModifyOID,
			},
			supported: true,
		},
		{
			name: "Who Am I",
			request: ldapwire.ExtendedRequest{
				Name: whoAmIOID,
			},
			supported: true,
		},
		{
			name: "dynamic refresh",
			request: ldapwire.ExtendedRequest{
				Name: dynamicRefreshOID,
			},
			supported: true,
		},
		{name: "Bind", request: ldapwire.BindRequest{}},
		{name: "Unbind", request: ldapwire.UnbindRequest{}},
		{name: "Abandon", request: ldapwire.AbandonRequest{}},
		{
			name: "StartTLS",
			request: ldapwire.ExtendedRequest{
				Name: startTLSOID,
			},
		},
		{
			name: "transaction start",
			request: ldapwire.ExtendedRequest{
				Name: transactionStartOID,
			},
		},
		{
			name: "transaction end",
			request: ldapwire.ExtendedRequest{
				Name: transactionEndOID,
			},
		},
		{
			name: "Cancel",
			request: ldapwire.ExtendedRequest{
				Name: cancelOID,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := supportsProxyAuthorization(test.request); got !=
				test.supported {
				t.Fatalf(
					"supportsProxyAuthorization() = %t, want %t",
					got,
					test.supported,
				)
			}
		})
	}
}

func TestParseSASLAuthzLDAPURLRejectsNonLocalComponents(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"ldap://ldap.example/dc=example,dc=com??sub?(uid=bob)",
		"ldap:///dc=example,dc=com?uid?sub?(uid=bob)",
		"ldap:///dc=example,dc=com??sub?(uid=bob)?bindname=cn=admin",
	} {
		if _, err := parseSASLAuthzLDAPURL(value); err == nil {
			t.Fatalf("parseSASLAuthzLDAPURL(%q) succeeded", value)
		}
	}
	if _, err := parseSASLAuthzLDAPURL(
		"ldap:///dc=example,dc=com??sub?(uid=bob)",
	); err != nil {
		t.Fatalf("parse local LDAP URL: %v", err)
	}
}

func TestLDAPProxyAuthorizationRootDSEAndControlValidation(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedProxyAuthorizationDirectory(t, store, "", nil, nil)

	address, stop := startServer(t, store, Config{
		RootDN:       proxyAuthorizationRootDN,
		RootPassword: []byte(proxyAuthorizationRootPassword),
	})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	rootDSE, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedControl"},
		nil,
	))
	_ = client.Close()
	if err != nil ||
		len(rootDSE.Entries) != 1 ||
		!containsString(
			rootDSE.Entries[0].GetAttributeValues("supportedControl"),
			proxyAuthorizationControlOID,
		) {
		t.Fatalf("proxy authorization Root DSE = %#v, %v", rootDSE, err)
	}

	connection := dialAndBindRawLDAP(
		t,
		address,
		proxyAuthorizationRootDN,
		proxyAuthorizationRootPassword,
	)
	defer connection.Close()

	tests := []struct {
		name       string
		controls   []*ber.Packet
		code       ldapwire.ResultCode
		diagnostic string
		authzID    string
	}{
		{
			name: "absent value",
			controls: []*ber.Packet{
				rawProxyAuthorizationControl(true, nil, false),
			},
			code:       ldapwire.ResultProtocolError,
			diagnostic: "proxy authorization control value absent",
		},
		{
			name: "duplicate",
			controls: []*ber.Packet{
				rawProxyAuthorizationControl(
					true,
					[]byte("dn:"+aliceDN),
					true,
				),
				rawProxyAuthorizationControl(
					true,
					[]byte("dn:"+aliceDN),
					true,
				),
			},
			code:       ldapwire.ResultProtocolError,
			diagnostic: "proxy authorization control specified multiple times",
		},
		{
			name: "invalid authzID",
			controls: []*ber.Packet{
				rawProxyAuthorizationControl(
					true,
					[]byte("not-an-authzid"),
					true,
				),
			},
			code:       ldapwire.ResultProxiedAuthorizationDenied,
			diagnostic: "authzId mapping failed",
		},
		{
			name: "invalid UTF-8 authzID",
			controls: []*ber.Packet{
				rawProxyAuthorizationControl(
					true,
					[]byte{0xff},
					true,
				),
			},
			code:       ldapwire.ResultProxiedAuthorizationDenied,
			diagnostic: "authzId mapping failed",
		},
		{
			name: "noncritical accepted by default",
			controls: []*ber.Packet{
				rawProxyAuthorizationControl(
					false,
					[]byte("dn:"+aliceDN),
					true,
				),
			},
			code:    ldapwire.ResultSuccess,
			authzID: "dn:" + aliceDN,
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := sendRawLDAPOperation(
				t,
				connection,
				int64(index+2),
				rawExtendedRequest(whoAmIOID, nil, false),
				test.controls...,
			)
			assertRawLDAPResult(t, response, int64(test.code))
			if got := rawLDAPDiagnostic(response); got != test.diagnostic {
				t.Fatalf("diagnostic = %q, want %q", got, test.diagnostic)
			}
			if test.code == ldapwire.ResultSuccess {
				value, present := rawExtendedResponseValue(response)
				if !present || string(value) != test.authzID {
					t.Fatalf(
						"WhoAmI response = %q, present %t; want %q",
						value,
						present,
						test.authzID,
					)
				}
			}
		})
	}
}

func TestLDAPProxyAuthorizationGlobalPolicies(t *testing.T) {
	t.Parallel()

	t.Run("noncritical disallowed", func(t *testing.T) {
		t.Parallel()

		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedProxyAuthorizationDirectory(t, store, "", nil, nil)
		replaceGlobalConfigurationValues(
			t,
			store,
			"olcDisallows",
			"proxy_authz_non_critical",
		)

		address, stop := startServer(t, store, Config{
			RootDN:       proxyAuthorizationRootDN,
			RootPassword: []byte(proxyAuthorizationRootPassword),
		})
		defer stop()
		connection := dialAndBindRawLDAP(
			t,
			address,
			proxyAuthorizationRootDN,
			proxyAuthorizationRootPassword,
		)
		defer connection.Close()

		response := sendRawLDAPOperation(
			t,
			connection,
			2,
			rawExtendedRequest(whoAmIOID, nil, false),
			rawProxyAuthorizationControl(
				false,
				[]byte("dn:"+aliceDN),
				true,
			),
		)
		assertRawLDAPResult(
			t,
			response,
			int64(ldapwire.ResultProtocolError),
		)
		if diagnostic := rawLDAPDiagnostic(response); diagnostic !=
			"proxied authorization criticality of FALSE not allowed" {
			t.Fatalf("diagnostic = %q", diagnostic)
		}
	})

	t.Run("anonymous default and opt-in", func(t *testing.T) {
		t.Parallel()

		for _, test := range []struct {
			name       string
			allow      bool
			target     string
			code       ldapwire.ResultCode
			diagnostic string
		}{
			{
				name:       "default denied",
				code:       ldapwire.ResultProxiedAuthorizationDenied,
				diagnostic: "anonymous proxied authorization not allowed",
			},
			{
				name:  "anonymous target allowed",
				allow: true,
				code:  ldapwire.ResultSuccess,
			},
			{
				name:       "nonanonymous target still denied",
				allow:      true,
				target:     "dn:" + aliceDN,
				code:       ldapwire.ResultProxiedAuthorizationDenied,
				diagnostic: "not authorized to assume identity",
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				store := storage.NewMemory()
				t.Cleanup(func() { _ = store.Close() })
				seedProxyAuthorizationDirectory(t, store, "", nil, nil)
				if test.allow {
					replaceGlobalConfigurationValues(
						t,
						store,
						"olcAllows",
						"proxy_authz_anon",
					)
				}
				address, stop := startServer(t, store, Config{})
				defer stop()
				connection := dialAndBindRawLDAP(t, address, "", "")
				defer connection.Close()

				response := sendRawLDAPOperation(
					t,
					connection,
					2,
					rawExtendedRequest(whoAmIOID, nil, false),
					rawProxyAuthorizationControl(
						true,
						[]byte(test.target),
						true,
					),
				)
				assertRawLDAPResult(t, response, int64(test.code))
				if diagnostic := rawLDAPDiagnostic(response); diagnostic !=
					test.diagnostic {
					t.Fatalf(
						"diagnostic = %q, want %q",
						diagnostic,
						test.diagnostic,
					)
				}
			})
		}
	})
}

func TestLDAPProxyAuthorizationUsesEffectiveIdentityPerOperation(
	t *testing.T,
) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedProxyAuthorizationDirectory(t, store, "", nil, nil)

	address, stop := startServer(t, store, Config{
		RootDN:       proxyAuthorizationRootDN,
		RootPassword: []byte(proxyAuthorizationRootPassword),
	})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(
		proxyAuthorizationRootDN,
		proxyAuthorizationRootPassword,
	); err != nil {
		t.Fatalf("root Bind(): %v", err)
	}

	result, err := client.WhoAmI([]ldap.Control{
		proxyAuthorizationControl("dn:"+aliceDN, true),
	})
	if err != nil || result.AuthzID != "dn:"+aliceDN {
		t.Fatalf("proxied WhoAmI = %#v, %v", result, err)
	}
	result, err = client.WhoAmI(nil)
	if err != nil || result.AuthzID != "dn:"+proxyAuthorizationRootDN {
		t.Fatalf("restored WhoAmI = %#v, %v", result, err)
	}
	result, err = client.WhoAmI([]ldap.Control{
		proxyAuthorizationControl("", true),
	})
	if err != nil || result.AuthzID != "" {
		t.Fatalf("anonymous proxied WhoAmI = %#v, %v", result, err)
	}
	missingDN := "uid=missing,ou=people,dc=example,dc=com"
	result, err = client.WhoAmI([]ldap.Control{
		proxyAuthorizationControl("dn:"+missingDN, true),
	})
	if err != nil || result.AuthzID != "dn:"+missingDN {
		t.Fatalf("nonexistent proxied WhoAmI = %#v, %v", result, err)
	}

	aliceModify := ldap.NewModifyRequest(
		aliceDN,
		[]ldap.Control{
			proxyAuthorizationControl("dn:"+aliceDN, true),
		},
	)
	aliceModify.Replace("mail", []string{"alice.proxy@example.com"})
	if err := client.Modify(aliceModify); err != nil {
		t.Fatalf("proxied self Modify(): %v", err)
	}

	bobModify := ldap.NewModifyRequest(
		proxyAuthorizationBobDN,
		[]ldap.Control{
			proxyAuthorizationControl("dn:"+aliceDN, true),
		},
	)
	bobModify.Replace("mail", []string{"denied@example.com"})
	assertLDAPResultCode(
		t,
		client.Modify(bobModify),
		ldap.LDAPResultInsufficientAccessRights,
	)

	rootModify := ldap.NewModifyRequest(proxyAuthorizationBobDN, nil)
	rootModify.Replace("mail", []string{"root@example.com"})
	if err := client.Modify(rootModify); err != nil {
		t.Fatalf("root Modify() after proxied operation: %v", err)
	}
}

func TestLDAPProxyAuthorizationSelfAndAnonymousNeedNoPolicy(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedProxyAuthorizationDirectory(t, store, "none", nil, nil)
	address, stop := startServer(t, store, Config{})
	defer stop()
	client := dialAndBindLDAPClient(t, address, aliceDN, "secret")
	defer client.Close()

	for _, authorizationID := range []string{
		"dn:" + aliceDN,
		"",
		"anonymous",
	} {
		result, err := client.WhoAmI([]ldap.Control{
			proxyAuthorizationControl(authorizationID, true),
		})
		if err != nil {
			t.Fatalf("WhoAmI(%q): %v", authorizationID, err)
		}
		want := "dn:" + aliceDN
		if authorizationID == "" || authorizationID == "anonymous" {
			want = ""
		}
		if result.AuthzID != want {
			t.Fatalf(
				"WhoAmI(%q) identity = %q, want %q",
				authorizationID,
				result.AuthzID,
				want,
			)
		}
	}
	assertProxyAuthorizationDenied(t, client, proxyAuthorizationBobDN)
}

func TestLDAPProxyAuthorizationPolicyModes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		policy     string
		authzTo    []string
		authzFrom  []string
		authorized bool
	}{
		{name: "none", policy: "none"},
		{
			name:       "to",
			policy:     "to",
			authzTo:    []string{"dn:" + proxyAuthorizationBobDN},
			authorized: true,
		},
		{
			name:       "from",
			policy:     "from",
			authzFrom:  []string{"dn:" + aliceDN},
			authorized: true,
		},
		{
			name:       "any-to",
			policy:     "any",
			authzTo:    []string{"dn:" + proxyAuthorizationBobDN},
			authorized: true,
		},
		{
			name:       "any-from",
			policy:     "both",
			authzFrom:  []string{"dn:" + aliceDN},
			authorized: true,
		},
		{
			name:       "any-continues-after-invalid-to",
			policy:     "any",
			authzTo:    []string{"dn.regex:["},
			authzFrom:  []string{"dn:" + aliceDN},
			authorized: true,
		},
		{
			name:      "all-requires-both",
			policy:    "all",
			authzTo:   []string{"dn:" + proxyAuthorizationBobDN},
			authzFrom: nil,
		},
		{
			name:       "all",
			policy:     "all",
			authzTo:    []string{"dn:" + proxyAuthorizationBobDN},
			authzFrom:  []string{"dn:" + aliceDN},
			authorized: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedProxyAuthorizationDirectory(
				t,
				store,
				test.policy,
				test.authzTo,
				test.authzFrom,
			)
			address, stop := startServer(t, store, Config{})
			defer stop()
			client := dialAndBindLDAPClient(t, address, aliceDN, "secret")
			defer client.Close()

			result, err := client.WhoAmI([]ldap.Control{
				proxyAuthorizationControl(
					"dn:"+proxyAuthorizationBobDN,
					true,
				),
			})
			if test.authorized {
				if err != nil ||
					result.AuthzID != "dn:"+proxyAuthorizationBobDN {
					t.Fatalf("proxied WhoAmI = %#v, %v", result, err)
				}
				return
			}
			assertLDAPResultCode(
				t,
				err,
				ldap.LDAPResultAuthorizationDenied,
			)
		})
	}
}

func TestLDAPProxyAuthorizationRuleForms(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		rules      []string
		authorized bool
	}{
		{
			name:       "legacy exact DN",
			rules:      []string{proxyAuthorizationBobDN},
			authorized: true,
		},
		{
			name:       "ordered exact DN",
			rules:      []string{"{7}dn.exact:" + proxyAuthorizationBobDN},
			authorized: true,
		},
		{
			name:       "onelevel",
			rules:      []string{"dn.onelevel:ou=people,dc=example,dc=com"},
			authorized: true,
		},
		{
			name:       "children",
			rules:      []string{"dn.children:dc=example,dc=com"},
			authorized: true,
		},
		{
			name:       "subtree",
			rules:      []string{"dn.subtree:ou=people,dc=example,dc=com"},
			authorized: true,
		},
		{
			name: "regex",
			rules: []string{
				`dn.regex:^uid=bob,ou=people,dc=example,dc=com$`,
			},
			authorized: true,
		},
		{
			name:       "typed wildcard",
			rules:      []string{"dn:*"},
			authorized: true,
		},
		{
			name:       "legacy wildcard",
			rules:      []string{"*"},
			authorized: true,
		},
		{
			name:       "user",
			rules:      []string{"u:Bob"},
			authorized: true,
		},
		{
			name:       "qualified user",
			rules:      []string{"u.SIMPLE:Bob"},
			authorized: true,
		},
		{
			name: "group",
			rules: []string{
				"group/groupOfNames/member:" + proxyAuthorizationGroupDN,
			},
			authorized: true,
		},
		{
			name: "LDAP URL",
			rules: []string{
				"ldap:///ou=people,dc=example,dc=com??sub?(uid=bob)",
			},
			authorized: true,
		},
		{
			name: "invalid rule followed by valid rule",
			rules: []string{
				"dn.regex:[",
				"dn:" + proxyAuthorizationBobDN,
			},
			authorized: true,
		},
		{
			name:  "onelevel mismatch",
			rules: []string{"dn.onelevel:dc=example,dc=com"},
		},
		{
			name: "LDAP URL filter mismatch",
			rules: []string{
				"ldap:///ou=people,dc=example,dc=com??sub?(uid=alice)",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedProxyAuthorizationDirectory(
				t,
				store,
				"to",
				test.rules,
				nil,
			)
			address, stop := startServer(t, store, Config{
				Schema: proxyAuthorizationTestSchema(t),
			})
			defer stop()
			client := dialAndBindLDAPClient(t, address, aliceDN, "secret")
			defer client.Close()

			result, err := client.WhoAmI([]ldap.Control{
				proxyAuthorizationControl(
					"dn:"+proxyAuthorizationBobDN,
					true,
				),
			})
			if test.authorized {
				if err != nil ||
					result.AuthzID != "dn:"+proxyAuthorizationBobDN {
					t.Fatalf("proxied WhoAmI = %#v, %v", result, err)
				}
				return
			}
			assertLDAPResultCode(
				t,
				err,
				ldap.LDAPResultAuthorizationDenied,
			)
		})
	}
}

func TestLDAPProxyAuthorizationUserURLMappingUsesAuthenticationACL(
	t *testing.T,
) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedProxyAuthorizationDirectory(
		t,
		store,
		"to",
		[]string{"dn:" + proxyAuthorizationBobDN},
		nil,
	)
	replaceGlobalConfigurationValues(
		t,
		store,
		"olcAuthzRegexp",
		`{0}^uid=([^,]+),cn=simple,cn=auth$ `+
			`ldap:///ou=people,dc=example,dc=com??sub?(uid=$1)`,
	)

	address, stop := startServer(t, store, Config{})
	defer stop()
	client := dialAndBindLDAPClient(t, address, aliceDN, "secret")
	defer client.Close()

	result, err := client.WhoAmI([]ldap.Control{
		proxyAuthorizationControl("u:bob", true),
	})
	if err != nil || result.AuthzID != "dn:"+proxyAuthorizationBobDN {
		t.Fatalf("u: LDAP URL proxied WhoAmI = %#v, %v", result, err)
	}
}

func TestLDAPProxyAuthorizationPolicyReloadRollbackAndRestart(
	t *testing.T,
) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	addProxyAuthorizationEntries(
		t,
		store,
		[]string{"dn:" + proxyAuthorizationBobDN},
		nil,
	)

	address, firstStop := startServer(t, store, Config{})
	defer func() {
		if firstStop != nil {
			firstStop()
		}
	}()
	configClient := dialAndBindLDAPClient(
		t,
		address,
		"cn=config",
		"config-secret",
	)
	alice := dialAndBindLDAPClient(t, address, aliceDN, "secret")
	assertProxyAuthorizationDenied(t, alice, proxyAuthorizationBobDN)

	enable := ldap.NewModifyRequest("cn=config", nil)
	enable.Replace("olcAuthzPolicy", []string{"to"})
	if err := configClient.Modify(enable); err != nil {
		t.Fatalf("enable olcAuthzPolicy: %v", err)
	}
	assertProxyAuthorizationIdentity(t, alice, proxyAuthorizationBobDN)

	invalid := ldap.NewModifyRequest("cn=config", nil)
	invalid.Replace("olcAuthzPolicy", []string{"invalid-policy"})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	assertProxyAuthorizationIdentity(t, alice, proxyAuthorizationBobDN)

	alice.Close()
	configClient.Close()
	firstStop()
	firstStop = nil

	restartedAddress, stopRestarted := startServer(t, store, Config{})
	defer stopRestarted()
	restartedAlice := dialAndBindLDAPClient(
		t,
		restartedAddress,
		aliceDN,
		"secret",
	)
	defer restartedAlice.Close()
	assertProxyAuthorizationIdentity(
		t,
		restartedAlice,
		proxyAuthorizationBobDN,
	)
}

func TestLDAPProxyAuthorizationIdentityIsCapturedByTransaction(
	t *testing.T,
) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedProxyAuthorizationDirectory(t, store, "", nil, nil)
	address, stop := startServer(t, store, Config{
		RootDN:       proxyAuthorizationRootDN,
		RootPassword: []byte(proxyAuthorizationRootPassword),
	})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		proxyAuthorizationRootDN,
		proxyAuthorizationRootPassword,
	)
	defer connection.Close()
	identifier := startRawLDAPTransaction(t, connection, 2)

	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			3,
			rawModifyReplaceRequest(
				aliceDN,
				"mail",
				"alice.transaction@example.com",
			),
			rawProxyAuthorizationControl(
				true,
				[]byte("dn:"+aliceDN),
				true,
			),
			rawTransactionSpecificationControl(identifier, true, true),
		),
		int64(ldapwire.ResultSuccess),
	)
	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			4,
			rawModifyReplaceRequest(
				aliceDN,
				"mail",
				"bob-denied@example.com",
			),
			rawProxyAuthorizationControl(
				true,
				[]byte("dn:"+proxyAuthorizationBobDN),
				true,
			),
			rawTransactionSpecificationControl(identifier, true, true),
		),
		int64(ldapwire.ResultSuccess),
	)

	response := endRawLDAPTransaction(t, connection, 5, true, identifier)
	assertRawLDAPResult(
		t,
		response,
		int64(ldapwire.ResultInsufficientAccessRights),
	)
	value, present := rawExtendedResponseValue(response)
	if !present {
		t.Fatal("failed transaction response value is absent")
	}
	decoded, err := ldapwire.DecodeTransactionEndResponseValue(value)
	if err != nil {
		t.Fatalf("DecodeTransactionEndResponseValue(): %v", err)
	}
	if !decoded.HasFailedMessageID || decoded.FailedMessageID != 4 {
		t.Fatalf("transaction response = %#v", decoded)
	}
	if values := readStoredEntry(t, store, aliceDN).Values("mail"); len(values) != 0 {
		t.Fatalf("failed transaction committed mail = %q", values)
	}
}

func TestLDAPSASLPlainUsesOpenLDAPAuthorizationPolicy(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedProxyAuthorizationDirectory(
		t,
		store,
		"to",
		[]string{"dn:" + proxyAuthorizationBobDN},
		nil,
	)
	replaceGlobalConfigurationValues(
		t,
		store,
		"olcSaslSecProps",
		"none",
	)

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection, err := dialAndBindSASLPlain(
		address,
		"dn:"+proxyAuthorizationBobDN,
		"alice",
		"secret",
	)
	if err != nil {
		t.Fatalf("PLAIN proxy Bind(): %v", err)
	}
	defer connection.Close()

	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawExtendedRequest(whoAmIOID, nil, false),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultSuccess))
	value, present := rawExtendedResponseValue(response)
	if !present || string(value) != "dn:"+proxyAuthorizationBobDN {
		t.Fatalf("PLAIN proxy identity = %q, present %t", value, present)
	}
}

func TestOpenLDAPReferenceProxyAuthorizationControls(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"disallow proxy_authz_non_critical",
		"",
		"",
	)
	defer stopReference()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedProxyAuthorizationDirectory(t, store, "", nil, nil)
	replaceGlobalConfigurationValues(
		t,
		store,
		"olcDisallows",
		"proxy_authz_non_critical",
	)
	address, stop := startServer(t, store, Config{
		RootDN:       proxyAuthorizationRootDN,
		RootPassword: []byte(proxyAuthorizationRootPassword),
	})
	defer stop()

	tests := []struct {
		name     string
		controls func() []*ber.Packet
		want     proxyAuthorizationObservation
	}{
		{
			name: "absent value",
			controls: func() []*ber.Packet {
				return []*ber.Packet{
					rawProxyAuthorizationControl(true, nil, false),
				}
			},
			want: proxyAuthorizationObservation{
				code:       ldapwire.ResultProtocolError,
				diagnostic: "proxy authorization control value absent",
			},
		},
		{
			name: "duplicate",
			controls: func() []*ber.Packet {
				return []*ber.Packet{
					rawProxyAuthorizationControl(
						true,
						[]byte("dn:"+aliceDN),
						true,
					),
					rawProxyAuthorizationControl(
						true,
						[]byte("dn:"+aliceDN),
						true,
					),
				}
			},
			want: proxyAuthorizationObservation{
				code:       ldapwire.ResultProtocolError,
				diagnostic: "proxy authorization control specified multiple times",
			},
		},
		{
			name: "invalid authzID",
			controls: func() []*ber.Packet {
				return []*ber.Packet{
					rawProxyAuthorizationControl(
						true,
						[]byte("not-an-authzid"),
						true,
					),
				}
			},
			want: proxyAuthorizationObservation{
				code:       ldapwire.ResultProxiedAuthorizationDenied,
				diagnostic: "authzId mapping failed",
			},
		},
		{
			name: "critical root proxy",
			controls: func() []*ber.Packet {
				return []*ber.Packet{
					rawProxyAuthorizationControl(
						true,
						[]byte("dn:"+aliceDN),
						true,
					),
				}
			},
			want: proxyAuthorizationObservation{
				code:       ldapwire.ResultSuccess,
				hasAuthzID: true,
				authzID:    "dn:" + aliceDN,
			},
		},
		{
			name: "anonymous target",
			controls: func() []*ber.Packet {
				return []*ber.Packet{
					rawProxyAuthorizationControl(true, []byte{}, true),
				}
			},
			want: proxyAuthorizationObservation{
				code:       ldapwire.ResultSuccess,
				hasAuthzID: true,
				authzID:    "",
			},
		},
		{
			name: "noncritical disallowed",
			controls: func() []*ber.Packet {
				return []*ber.Packet{
					rawProxyAuthorizationControl(
						false,
						[]byte("dn:"+aliceDN),
						true,
					),
				}
			},
			want: proxyAuthorizationObservation{
				code:       ldapwire.ResultProtocolError,
				diagnostic: "proxied authorization criticality of FALSE not allowed",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := observeRawProxyAuthorizationWhoAmI(
				t,
				address,
				proxyAuthorizationRootDN,
				proxyAuthorizationRootPassword,
				test.controls(),
			)
			reference := observeRawProxyAuthorizationWhoAmI(
				t,
				proxyAuthorizationAddress(referenceURI),
				proxyAuthorizationRootDN,
				"secret",
				test.controls(),
			)
			if got != test.want || reference != test.want {
				t.Fatalf(
					"ldap-go = %#v, OpenLDAP = %#v, want %#v",
					got,
					reference,
					test.want,
				)
			}
		})
	}

	wantAnonymous := proxyAuthorizationObservation{
		code:       ldapwire.ResultProxiedAuthorizationDenied,
		diagnostic: "anonymous proxied authorization not allowed",
	}
	gotAnonymous := observeRawProxyAuthorizationWhoAmI(
		t,
		address,
		"",
		"",
		[]*ber.Packet{
			rawProxyAuthorizationControl(true, []byte{}, true),
		},
	)
	referenceAnonymous := observeRawProxyAuthorizationWhoAmI(
		t,
		proxyAuthorizationAddress(referenceURI),
		"",
		"",
		[]*ber.Packet{
			rawProxyAuthorizationControl(true, []byte{}, true),
		},
	)
	if gotAnonymous != wantAnonymous ||
		referenceAnonymous != wantAnonymous {
		t.Fatalf(
			"anonymous ldap-go = %#v, OpenLDAP = %#v, want %#v",
			gotAnonymous,
			referenceAnonymous,
			wantAnonymous,
		)
	}
}

func TestOpenLDAPReferenceAuthorizationPolicy(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"authz-policy to",
		"access to attrs=userPassword by anonymous auth by self write by * none\n"+
			"access to * by * read",
		`
dn: uid=dave,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: dave
cn: Dave
sn: Dave
userPassword: dave-secret
authzTo: dn:uid=bob,ou=people,dc=example,dc=com
`,
	)
	defer stopReference()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedProxyAuthorizationDirectory(t, store, "to", nil, nil)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "uid=dave,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{
					Description: "objectClass",
					Values:      stringValues("inetOrgPerson"),
				},
				{Description: "uid", Values: stringValues("dave")},
				{Description: "cn", Values: stringValues("Dave")},
				{Description: "sn", Values: stringValues("Dave")},
				{
					Description: "userPassword",
					Values:      stringValues("dave-secret"),
				},
				{
					Description: "authzTo",
					Values: stringValues(
						"dn:" + proxyAuthorizationBobDN,
					),
				},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed ldap-go authorization source: %v", err)
	}
	address, stop := startServer(t, store, Config{})
	defer stop()

	want := proxyAuthorizationObservation{
		code:       ldapwire.ResultSuccess,
		hasAuthzID: true,
		authzID:    "dn:" + proxyAuthorizationBobDN,
	}
	got := observeRawProxyAuthorizationWhoAmI(
		t,
		address,
		"uid=dave,ou=people,dc=example,dc=com",
		"dave-secret",
		[]*ber.Packet{
			rawProxyAuthorizationControl(
				true,
				[]byte("dn:"+proxyAuthorizationBobDN),
				true,
			),
		},
	)
	reference := observeRawProxyAuthorizationWhoAmI(
		t,
		proxyAuthorizationAddress(referenceURI),
		"uid=dave,ou=people,dc=example,dc=com",
		"dave-secret",
		[]*ber.Packet{
			rawProxyAuthorizationControl(
				true,
				[]byte("dn:"+proxyAuthorizationBobDN),
				true,
			),
		},
	)
	if got != want || reference != want {
		t.Fatalf(
			"ldap-go = %#v, OpenLDAP = %#v, want %#v",
			got,
			reference,
			want,
		)
	}
}

func proxyAuthorizationControl(
	authorizationID string,
	critical bool,
) ldap.Control {
	return ldapProxyAuthorizationControl{
		critical: critical,
		value:    authorizationID,
	}
}

type ldapProxyAuthorizationControl struct {
	critical bool
	value    string
}

func (control ldapProxyAuthorizationControl) GetControlType() string {
	return proxyAuthorizationControlOID
}

func (control ldapProxyAuthorizationControl) Encode() *ber.Packet {
	return rawProxyAuthorizationControl(
		control.critical,
		[]byte(control.value),
		true,
	)
}

func (control ldapProxyAuthorizationControl) String() string {
	return "Proxy Authorization Control"
}

func rawProxyAuthorizationControl(
	critical bool,
	value []byte,
	hasValue bool,
) *ber.Packet {
	control := ber.NewSequence("ProxyAuthorizationControl")
	control.AppendChild(rawOctetString([]byte(proxyAuthorizationControlOID)))
	if critical {
		control.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"criticality",
		))
	}
	if hasValue {
		control.AppendChild(rawOctetString(value))
	}
	return control
}

func dialAndBindLDAPClient(
	t *testing.T,
	address,
	dn,
	password string,
) *ldap.Conn {
	t.Helper()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	if err := client.Bind(dn, password); err != nil {
		client.Close()
		t.Fatalf("Bind(%q): %v", dn, err)
	}
	return client
}

func assertProxyAuthorizationIdentity(
	t *testing.T,
	client *ldap.Conn,
	targetDN string,
) {
	t.Helper()

	result, err := client.WhoAmI([]ldap.Control{
		proxyAuthorizationControl("dn:"+targetDN, true),
	})
	if err != nil || result.AuthzID != "dn:"+targetDN {
		t.Fatalf("proxied WhoAmI(%q) = %#v, %v", targetDN, result, err)
	}
}

func assertProxyAuthorizationDenied(
	t *testing.T,
	client *ldap.Conn,
	targetDN string,
) {
	t.Helper()

	_, err := client.WhoAmI([]ldap.Control{
		proxyAuthorizationControl("dn:"+targetDN, true),
	})
	assertLDAPResultCode(t, err, ldap.LDAPResultAuthorizationDenied)
}

func seedProxyAuthorizationDirectory(
	t *testing.T,
	store storage.Store,
	policy string,
	authzTo,
	authzFrom []string,
) {
	t.Helper()
	seedDirectory(t, store)
	addProxyAuthorizationEntries(t, store, authzTo, authzFrom)

	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		attributes := []directory.Attribute{
			{
				Description: "objectClass",
				Values:      stringValues("olcGlobal"),
			},
			{Description: "cn", Values: stringValues("config")},
			{
				Description: "olcAuthzRegexp",
				Values: stringValues(
					`{0}^uid=([^,]+),cn=authz,cn=auth$ `+
						`uid=$1,ou=people,dc=example,dc=com`,
					`{1}^uid=([^,]+),cn=simple,cn=auth$ `+
						`uid=$1,ou=people,dc=example,dc=com`,
					`{2}^uid=([^,]+),cn=plain,cn=auth$ `+
						`uid=$1,ou=people,dc=example,dc=com`,
				),
			},
		}
		if policy != "" {
			attributes = append(attributes, directory.Attribute{
				Description: "olcAuthzPolicy",
				Values:      stringValues(policy),
			})
		}
		return writer.Put(directory.Entry{
			DN:         "cn=config",
			Attributes: attributes,
		}, false)
	}); err != nil {
		t.Fatalf("seed proxy authorization configuration: %v", err)
	}
}

func addProxyAuthorizationEntries(
	t *testing.T,
	store storage.Store,
	authzTo,
	authzFrom []string,
) {
	t.Helper()

	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		alice, err := writer.Get(mustProxyAuthorizationDN(aliceDN))
		if err != nil {
			return err
		}
		if len(authzTo) > 0 {
			alice.ReplaceValues("authzTo", stringValues(authzTo...))
		}
		if err := writer.Put(alice, true); err != nil {
			return err
		}
		return putProxyAuthorizationEntries(writer, authzFrom)
	}); err != nil {
		t.Fatalf("seed proxy authorization entries: %v", err)
	}
}

func putProxyAuthorizationEntries(
	writer storage.Writer,
	authzFrom []string,
) error {
	bobAttributes := []directory.Attribute{
		{
			Description: "objectClass",
			Values:      stringValues("inetOrgPerson"),
		},
		{Description: "uid", Values: stringValues("bob")},
		{Description: "cn", Values: stringValues("Bob Example")},
		{Description: "sn", Values: stringValues("Example")},
		{Description: "userPassword", Values: stringValues("bob-secret")},
	}
	if len(authzFrom) > 0 {
		bobAttributes = append(bobAttributes, directory.Attribute{
			Description: "authzFrom",
			Values:      stringValues(authzFrom...),
		})
	}
	for _, entry := range []directory.Entry{
		{
			DN:         proxyAuthorizationBobDN,
			Attributes: bobAttributes,
		},
		{
			DN: proxyAuthorizationGroupDN,
			Attributes: []directory.Attribute{
				{
					Description: "objectClass",
					Values:      stringValues("groupOfNames"),
				},
				{
					Description: "cn",
					Values:      stringValues("proxy targets"),
				},
				{
					Description: "member",
					Values: stringValues(
						proxyAuthorizationBobDN,
					),
				},
			},
		},
	} {
		if err := writer.Put(entry, false); err != nil {
			return err
		}
	}
	return nil
}

func mustProxyAuthorizationDN(value string) directory.DN {
	dn, err := directory.ParseDN(value)
	if err != nil {
		panic(err)
	}
	return dn
}

func proxyAuthorizationTestSchema(t *testing.T) *schema.Registry {
	t.Helper()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	return registry
}

type proxyAuthorizationObservation struct {
	code       ldapwire.ResultCode
	diagnostic string
	hasAuthzID bool
	authzID    string
}

func observeRawProxyAuthorizationWhoAmI(
	t *testing.T,
	address,
	bindDN,
	password string,
	controls []*ber.Packet,
) proxyAuthorizationObservation {
	t.Helper()

	connection := dialAndBindRawLDAP(t, address, bindDN, password)
	defer connection.Close()
	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawExtendedRequest(whoAmIOID, nil, false),
		controls...,
	)
	observation := proxyAuthorizationObservation{
		code: ldapwire.ResultCode(
			rawLDAPResultCode(t, response.Children[1]),
		),
		diagnostic: rawLDAPDiagnostic(response),
	}
	if value, present := rawExtendedResponseValue(response); present {
		observation.hasAuthzID = true
		observation.authzID = string(value)
	}
	return observation
}

func proxyAuthorizationAddress(uri string) string {
	return strings.TrimPrefix(uri, "ldap://")
}
