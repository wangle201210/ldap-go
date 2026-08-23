package server

import (
	"context"
	"net"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	dnIdentityReferralUpperDN = "exactName=Remote+foldName=Team,dc=example,dc=com"
	dnIdentityReferralLowerDN = "exactName=remote+foldName=team,dc=example,dc=com"
	dnIdentityReferralRequest = dnMultiAVAFoldOID + "=TEAM+exactAlias=Remote," +
		"DC=EXAMPLE,DC=COM"
	dnIdentityReferralURL = "ldap://remote.example/" +
		"exactName=Mapped+foldName=Directory,dc=remote,dc=example" +
		"?cn,sn??%28uid%3D%2A%29?!x-test=one"
)

func TestDNIdentityReferralURLRewrite(t *testing.T) {
	registry := newDNMultiAVARegistry(t)
	base := mustDNIdentityReferralURLDN(
		t,
		registry,
		"exactAlias=Remote+foldAlias=Team,dc=example,dc=com",
	)
	target := mustDNIdentityReferralURLDN(
		t,
		registry,
		"uid=child,"+dnMultiAVAFoldOID+"=TEAM+"+
			dnMultiAVAExactOID+"=Remote,DC=EXAMPLE,DC=COM",
	)
	raw := "ldap://remote.example/foldAlias=Directory+" +
		dnMultiAVAExactOID + "=Mapped,dc=remote,dc=example" +
		"?cn,sn??%28uid%3D%2A%29?!x-test=one"

	got, ok := rewriteReferralURLWithNormalizer(
		raw,
		&base,
		&target,
		referralScopeSubtree,
		registry,
	)
	const want = "ldap://remote.example/uid=child," +
		"exactName=Mapped+foldName=Directory,dc=remote,dc=example" +
		"?cn,sn?sub?%28uid%3D%2A%29?!x-test=one"
	if !ok || got != want {
		t.Fatalf("schema-aware referral URL = %q, %t; want %q, true", got, ok, want)
	}

	caseExactSibling := mustDNIdentityReferralURLDN(
		t,
		registry,
		"uid=child,exactName=remote+foldName=team,dc=example,dc=com",
	)
	got, ok = rewriteReferralURLWithNormalizer(
		raw,
		&base,
		&caseExactSibling,
		referralScopeSubtree,
		registry,
	)
	const siblingWant = "ldap://remote.example/uid=child," +
		"exactName=remote+foldName=team,dc=example,dc=com" +
		"?cn,sn?sub?%28uid%3D%2A%29?!x-test=one"
	if !ok || got != siblingWant {
		t.Fatalf("caseExact sibling referral URL = %q, %t; want %q, true", got, ok, siblingWant)
	}
}

func TestDNIdentityReferralManageDsaIT(t *testing.T) {
	for _, backend := range dnIdentityCoreWriteBackends() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			client, address := startDNIdentityReferralURLServer(t, backend.open)
			manage := ldap.NewControlManageDsaIT(true)
			seedDNIdentityReferralEntries(t, client, manage)

			t.Run("caseExact isolation", func(t *testing.T) {
				result, err := client.Search(ldap.NewSearchRequest(
					dnMultiAVAFoldOID+"=TEAM+exactAlias=remote,dc=example,dc=com",
					ldap.ScopeBaseObject,
					ldap.NeverDerefAliases,
					0,
					0,
					false,
					"(objectClass=*)",
					[]string{"cn"},
					nil,
				))
				if err != nil || len(result.Entries) != 1 ||
					result.Entries[0].DN != dnIdentityReferralLowerDN {
					t.Fatalf("caseExact sibling Search = %#v, %v", result, err)
				}

				_, err = client.Search(ldap.NewSearchRequest(
					"uid=missing,"+dnIdentityReferralLowerDN,
					ldap.ScopeBaseObject,
					ldap.NeverDerefAliases,
					0,
					0,
					false,
					"(objectClass=*)",
					[]string{"1.1"},
					nil,
				))
				assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
			})

			t.Run("search and URL query", func(t *testing.T) {
				_, err := client.Search(ldap.NewSearchRequest(
					dnIdentityReferralRequest,
					ldap.ScopeBaseObject,
					ldap.NeverDerefAliases,
					0,
					0,
					false,
					"(objectClass=*)",
					[]string{"1.1"},
					nil,
				))
				assertLDAPReferral(
					t,
					err,
					dnIdentityReferralUpperDN,
					strings.Replace(dnIdentityReferralURL, "??", "?base?", 1),
				)

				_, err = client.Search(ldap.NewSearchRequest(
					"uid=child,"+dnIdentityReferralRequest,
					ldap.ScopeWholeSubtree,
					ldap.NeverDerefAliases,
					0,
					0,
					false,
					"(objectClass=*)",
					[]string{"1.1"},
					nil,
				))
				assertLDAPReferral(
					t,
					err,
					dnIdentityReferralUpperDN,
					strings.Replace(
						strings.Replace(
							dnIdentityReferralURL,
							"/exactName=Mapped",
							"/uid=child,exactName=Mapped",
							1,
						),
						"??",
						"?sub?",
						1,
					),
				)

				subtree, err := client.Search(ldap.NewSearchRequest(
					"dc=example,dc=com",
					ldap.ScopeWholeSubtree,
					ldap.NeverDerefAliases,
					0,
					0,
					false,
					"(cn=does-not-match)",
					[]string{"1.1"},
					nil,
				))
				if err != nil || len(subtree.Referrals) != 1 {
					t.Fatalf("subtree referral Search = %#v, %v", subtree, err)
				}
				want := strings.Replace(dnIdentityReferralURL, "??", "?sub?", 1)
				if subtree.Referrals[0] != want {
					t.Fatalf("subtree referral = %q, want %q", subtree.Referrals[0], want)
				}
			})

			t.Run("compare and ManageDsaIT", func(t *testing.T) {
				matched, err := client.Compare(
					dnIdentityReferralRequest,
					"ref",
					dnIdentityReferralURL,
				)
				if matched {
					t.Fatal("unmanaged Compare returned true")
				}
				assertLDAPReferral(
					t,
					err,
					dnIdentityReferralUpperDN,
					dnIdentityReferralURL,
				)

				code := dnIdentityReferralManagedCompare(
					t,
					address,
					dnIdentityReferralRequest,
					"ref",
					dnIdentityReferralURL,
				)
				if code != ldap.LDAPResultCompareTrue {
					t.Fatalf("managed Compare result = %d, want compareTrue", code)
				}

				managed, err := client.Search(ldap.NewSearchRequest(
					dnIdentityReferralRequest,
					ldap.ScopeBaseObject,
					ldap.NeverDerefAliases,
					0,
					0,
					false,
					"(objectClass=referral)",
					[]string{"ref"},
					[]ldap.Control{manage},
				))
				if err != nil || len(managed.Entries) != 1 ||
					managed.Entries[0].DN != dnIdentityReferralUpperDN ||
					managed.Entries[0].GetAttributeValue("ref") != dnIdentityReferralURL {
					t.Fatalf("managed referral Search = %#v, %v", managed, err)
				}
			})

			t.Run("write operations", func(t *testing.T) {
				modify := ldap.NewModifyRequest(dnIdentityReferralRequest, nil)
				modify.Replace("description", []string{"managed"})
				assertLDAPReferral(
					t,
					client.Modify(modify),
					dnIdentityReferralUpperDN,
					dnIdentityReferralURL,
				)
				modify.Controls = []ldap.Control{manage}
				if err := client.Modify(modify); err != nil {
					t.Fatalf("managed Modify(referral): %v", err)
				}

				child := ldap.NewAddRequest(
					"uid=child,"+dnIdentityReferralRequest,
					[]ldap.Control{manage},
				)
				child.Attribute("objectClass", []string{"inetOrgPerson"})
				child.Attribute("uid", []string{"child"})
				child.Attribute("cn", []string{"Child"})
				child.Attribute("sn", []string{"Child"})
				childReferralURL := strings.Replace(
					dnIdentityReferralURL,
					"/exactName=Mapped",
					"/uid=child,exactName=Mapped",
					1,
				)
				assertLDAPReferral(
					t,
					client.Add(child),
					dnIdentityReferralUpperDN,
					childReferralURL,
				)

				rename := ldap.NewModifyDNRequest(
					dnIdentityReferralRequest,
					"exactAlias=Moved+"+dnMultiAVAFoldOID+"=TEAM",
					true,
					"",
				)
				assertLDAPReferral(
					t,
					client.ModifyDN(rename),
					dnIdentityReferralUpperDN,
					dnIdentityReferralURL,
				)
				rename.Controls = []ldap.Control{manage}
				if err := client.ModifyDN(rename); err != nil {
					t.Fatalf("managed ModifyDN(referral): %v", err)
				}

				movedDN := "exactName=Moved+foldName=TEAM,dc=example,dc=com"
				deleteRequest := ldap.NewDelRequest(movedDN, nil)
				assertLDAPReferral(
					t,
					client.Del(deleteRequest),
					movedDN,
					dnIdentityReferralURL,
				)
				deleteRequest.Controls = []ldap.Control{manage}
				if err := client.Del(deleteRequest); err != nil {
					t.Fatalf("managed Delete(referral): %v", err)
				}
			})
		})
	}
}

func startDNIdentityReferralURLServer(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) (*ldap.Conn, string) {
	t.Helper()
	store := openStore(t)
	t.Cleanup(func() { _ = store.Close() })
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(dnMultiAVAConfigLDIF),
		migration.ImportOptions{
			Database:             "0",
			Replace:              true,
			SkipSchemaValidation: true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(cn=config): %v", err)
	}
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(dnMultiAVAContentLDIF),
		migration.ImportOptions{Database: "1", Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(content): %v", err)
	}

	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(root): %v", err)
	}
	return client, address
}

func seedDNIdentityReferralEntries(
	t *testing.T,
	client *ldap.Conn,
	manage ldap.Control,
) {
	t.Helper()
	lower := newDNMultiAVAAdd(
		dnIdentityReferralLowerDN,
		"Case Exact Lower",
		map[string][]string{
			"exactName": {"remote"},
			"foldName":  {"team"},
		},
	)
	if err := client.Add(lower); err != nil {
		t.Fatalf("Add(caseExact sibling): %v", err)
	}

	upper := ldap.NewAddRequest(dnIdentityReferralUpperDN, []ldap.Control{manage})
	upper.Attribute("objectClass", []string{"referral", "extensibleObject"})
	upper.Attribute("exactAlias", []string{"Remote"})
	upper.Attribute(dnMultiAVAFoldOID, []string{"Team"})
	upper.Attribute("ref", []string{dnIdentityReferralURL})
	if err := client.Add(upper); err != nil {
		t.Fatalf("Add(referral): %v", err)
	}
}

func dnIdentityReferralManagedCompare(
	t *testing.T,
	address,
	dn,
	attribute,
	value string,
) int64 {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	defer connection.Close()

	bind := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationBindRequest,
		nil,
		"BindRequest",
	)
	bind.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		3,
		"version",
	))
	bind.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		"cn=admin,dc=example,dc=com",
		"name",
	))
	bind.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		"secret",
		"simple",
	))
	writeRawLDAPRequest(t, connection, 1, bind, nil)
	if code := readRawLDAPResultCode(t, connection); code != ldap.LDAPResultSuccess {
		t.Fatalf("raw Bind result = %d", code)
	}

	compare := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationCompareRequest,
		nil,
		"CompareRequest",
	)
	compare.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		dn,
		"entry",
	))
	assertion := ber.NewSequence("AttributeValueAssertion")
	assertion.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		attribute,
		"attribute",
	))
	assertion.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		value,
		"value",
	))
	compare.AppendChild(assertion)
	writeRawLDAPRequest(t, connection, 2, compare, rawManageDsaITControl())
	return readRawLDAPResultCode(t, connection)
}

func mustDNIdentityReferralURLDN(
	t *testing.T,
	normalizer directory.DNAttributeNormalizer,
	raw string,
) directory.DN {
	t.Helper()
	dn, err := directory.ParseDNWithNormalizer(raw, normalizer)
	if err != nil {
		t.Fatalf("ParseDNWithNormalizer(%q): %v", raw, err)
	}
	return dn
}
