package server

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type dynlistReferenceOutcome struct {
	values   []string
	filtered []string
	managed  []string
	memberOf []string
	compares []bool
}

type dynlistIdentityReferenceOutcome struct {
	anonymousBefore   []string
	withIdentity      []string
	anonymousDenied   []string
	authorized        []string
	anonymousCompare  uint16
	authorizedCompare uint16
}

type dynlistMultipleAttributeSetOutcome struct {
	dynamicMembers    []string
	uriMembers        []string
	aliceDGMemberOf   []string
	aliceSeeAlso      []string
	bobSeeAlso        []string
	negatedMemberOf   []string
	filteredSeeAlso   []string
	uniqueMemberCodes []uint16
}

func TestOpenLDAPReferenceDynlistOverlay(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	t.Run("default attribute set", func(t *testing.T) {
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dynlist"},
			"include "+tools.schemaDir+"/dyngroup.schema",
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addOpenLDAPDynlistListFixtures(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addDynlistFixtures(t, ldapGo)
		overlay := ldap.NewAddRequest(testDynlistOverlayDN, nil)
		overlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcDynListConfig"})
		overlay.Attribute("olcOverlay", []string{"{0}dynlist"})
		if err := configClient.Add(overlay); err != nil {
			t.Fatalf("Add(default ldap-go dynlist overlay): %v", err)
		}

		openLDAPOutcome := runMappedDynlistReferenceScenario(t, openLDAP)
		ldapGoOutcome := runMappedDynlistReferenceScenario(t, ldapGo)
		if !reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
			t.Fatalf(
				"default dynlist mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
				openLDAPOutcome,
				ldapGoOutcome,
			)
		}
	})

	t.Run("unmapped attributes are output only", func(t *testing.T) {
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dynlist\ndynlist-attrset groupOfURLs memberURL"},
			"include "+tools.schemaDir+"/dyngroup.schema",
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addOpenLDAPDynlistListFixtures(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addDynlistFixtures(t, ldapGo)
		addDynlistReferenceOverlay(
			t,
			configClient,
			"groupOfURLs memberURL",
			false,
		)

		openLDAPOutcome := runMappedDynlistReferenceScenario(t, openLDAP)
		ldapGoOutcome := runMappedDynlistReferenceScenario(t, ldapGo)
		if !reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
			t.Fatalf(
				"unmapped dynlist mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
				openLDAPOutcome,
				ldapGoOutcome,
			)
		}
	})

	t.Run("attribute set URI restriction", func(t *testing.T) {
		configuration := "groupOfURLs " +
			"ldap:///ou=groups,dc=example,dc=com??one?(cn=Dynamic*) " +
			"memberURL mail:mail"
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dynlist\ndynlist-attrset " + configuration},
			"include "+tools.schemaDir+"/dyngroup.schema",
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addOpenLDAPDynlistListFixtures(t, openLDAP)
		addExcludedDynlistReferenceGroup(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addDynlistFixtures(t, ldapGo)
		addExcludedDynlistReferenceGroup(t, ldapGo)
		addDynlistReferenceOverlay(t, configClient, configuration, false)

		openLDAPOutcome := runRestrictedDynlistReferenceScenario(t, openLDAP)
		ldapGoOutcome := runRestrictedDynlistReferenceScenario(t, ldapGo)
		if !reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
			t.Fatalf(
				"restricted dynlist mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
				openLDAPOutcome,
				ldapGoOutcome,
			)
		}
	})

	t.Run("mapped list and controls", func(t *testing.T) {
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{
				"dynlist\n" +
					"dynlist-attrset groupOfURLs memberURL mail:mail",
			},
			"include "+tools.schemaDir+"/dyngroup.schema",
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addOpenLDAPDynlistListFixtures(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addDynlistFixtures(t, ldapGo)
		addDynlistReferenceOverlay(
			t,
			configClient,
			"groupOfURLs memberURL mail:mail",
			false,
		)

		openLDAPOutcome := runMappedDynlistReferenceScenario(t, openLDAP)
		ldapGoOutcome := runMappedDynlistReferenceScenario(t, ldapGo)
		if !reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
			t.Fatalf(
				"mapped dynlist mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
				openLDAPOutcome,
				ldapGoOutcome,
			)
		}
	})

	t.Run("empty mapped attribute compare result", func(t *testing.T) {
		configuration := "groupOfURLs memberURL mail:mail"
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dynlist\ndynlist-attrset " + configuration},
			"include "+tools.schemaDir+"/dyngroup.schema",
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addOpenLDAPDynlistListFixtures(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addDynlistFixtures(t, ldapGo)
		addDynlistReferenceOverlay(t, configClient, configuration, false)
		for _, client := range []*ldap.Conn{openLDAP, ldapGo} {
			memberURL := ldap.NewModifyRequest(testDynlistGroupDN, nil)
			memberURL.Replace(
				"memberURL",
				[]string{
					"ldap:///ou=people,dc=example,dc=com?mail?sub?(uid=missing)",
				},
			)
			if err := client.Modify(memberURL); err != nil {
				t.Fatalf("Modify(empty mapped memberURL): %v", err)
			}
		}

		openLDAPCode := overlayCompareResultCode(
			t,
			openLDAP,
			testDynlistGroupDN,
			"mail",
			"missing@example.com",
		)
		ldapGoCode := overlayCompareResultCode(
			t,
			ldapGo,
			testDynlistGroupDN,
			"mail",
			"missing@example.com",
		)
		if openLDAPCode != ldapGoCode {
			t.Fatalf(
				"empty mapped Compare mismatch: OpenLDAP=%d, ldap-go=%d",
				openLDAPCode,
				ldapGoCode,
			)
		}
	})

	t.Run("missing URL attribute compare result", func(t *testing.T) {
		configuration := "groupOfURLs memberURL member"
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dynlist\ndynlist-attrset " + configuration},
			"include "+tools.schemaDir+"/dyngroup.schema",
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addLegacyDynlistReferenceFixture(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addLegacyDynlistReferenceFixture(t, ldapGo)
		addDynlistReferenceOverlay(t, configClient, configuration, false)
		for _, client := range []*ldap.Conn{openLDAP, ldapGo} {
			modify := ldap.NewModifyRequest(testDynlistGroupDN, nil)
			modify.Delete("memberURL", nil)
			if err := client.Modify(modify); err != nil {
				t.Fatalf("Modify(delete memberURL): %v", err)
			}
		}

		openLDAPCode := overlayCompareResultCode(
			t,
			openLDAP,
			testDynlistGroupDN,
			"member",
			testDynlistAliceDN,
		)
		ldapGoCode := overlayCompareResultCode(
			t,
			ldapGo,
			testDynlistGroupDN,
			"member",
			testDynlistAliceDN,
		)
		if openLDAPCode != ldapGoCode {
			t.Fatalf(
				"missing memberURL Compare mismatch: OpenLDAP=%d, ldap-go=%d",
				openLDAPCode,
				ldapGoCode,
			)
		}
	})

	t.Run("paged dynamic filter", func(t *testing.T) {
		configuration := "groupOfURLs memberURL mail:mail"
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dynlist\ndynlist-attrset " + configuration},
			"include "+tools.schemaDir+"/dyngroup.schema",
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addOpenLDAPDynlistListFixtures(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addDynlistFixtures(t, ldapGo)
		addDynlistReferenceOverlay(t, configClient, configuration, false)

		openLDAPDNs := runPagedDynlistFilterReferenceScenario(t, openLDAP)
		ldapGoDNs := runPagedDynlistFilterReferenceScenario(t, ldapGo)
		if !reflect.DeepEqual(openLDAPDNs, ldapGoDNs) {
			t.Fatalf(
				"paged dynlist filter mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
				openLDAPDNs,
				ldapGoDNs,
			)
		}
	})

	t.Run("paged memberOf filter", func(t *testing.T) {
		configuration := "groupOfURLs memberURL member+dgMemberOf"
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dynlist\ndynlist-attrset " + configuration},
			"include "+tools.schemaDir+"/dyngroup.schema",
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addDynlistIdentityGroup(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		ensureDynlistReferenceBob(t, ldapGo)
		addDynlistIdentityGroup(t, ldapGo)
		addDynlistReferenceOverlay(t, configClient, configuration, false)

		openLDAPDNs := runPagedDynlistMemberOfReferenceScenario(t, openLDAP)
		ldapGoDNs := runPagedDynlistMemberOfReferenceScenario(t, ldapGo)
		if !reflect.DeepEqual(openLDAPDNs, ldapGoDNs) {
			t.Fatalf(
				"paged dynlist memberOf mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
				openLDAPDNs,
				ldapGoDNs,
			)
		}
	})

	t.Run("nested dynamic and static groups", func(t *testing.T) {
		configuration := "groupOfURLs memberURL " +
			"member+dgMemberOf@groupOfNames*"
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dynlist\ndynlist-attrset " + configuration},
			"include "+tools.schemaDir+"/dyngroup.schema",
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addNestedDynlistReferenceFixtures(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addNestedDynlistReferenceFixtures(t, ldapGo)
		addDynlistReferenceOverlay(t, configClient, configuration, false)

		openLDAPOutcome := runNestedDynlistReferenceScenario(t, openLDAP)
		ldapGoOutcome := runNestedDynlistReferenceScenario(t, ldapGo)
		if !reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
			t.Fatalf(
				"nested dynlist mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
				openLDAPOutcome,
				ldapGoOutcome,
			)
		}
	})

	t.Run("multiple attribute sets and negated filters", func(t *testing.T) {
		attributeSets := []string{
			"groupOfURLs memberURL member+dgMemberOf@groupOfNames*",
			"labeledURIObject labeledURI uniqueMember+seeAlso@groupOfUniqueNames",
		}
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dynlist\ndynlist-attrset " + attributeSets[0] +
				"\ndynlist-attrset " + attributeSets[1]},
			"include "+tools.schemaDir+"/dyngroup.schema",
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addMultipleAttributeSetDynlistFixtures(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addMultipleAttributeSetDynlistFixtures(t, ldapGo)
		addDynlistReferenceOverlaySets(t, configClient, attributeSets, false)

		openLDAPOutcome := runMultipleAttributeSetDynlistScenario(t, openLDAP)
		ldapGoOutcome := runMultipleAttributeSetDynlistScenario(t, ldapGo)
		if !reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
			t.Fatalf(
				"multiple attrset dynlist mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
				openLDAPOutcome,
				ldapGoOutcome,
			)
		}
	})

	t.Run("request-sensitive dynamic nesting", func(t *testing.T) {
		configuration := "groupOfURLs memberURL member+dgMemberOf*"
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dynlist\ndynlist-attrset " + configuration},
			"include "+tools.schemaDir+"/dyngroup.schema",
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addDynamicNestedDynlistReferenceFixtures(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addDynamicNestedDynlistReferenceFixtures(t, ldapGo)
		addDynlistReferenceOverlay(t, configClient, configuration, false)

		openLDAPOutcome := runDynamicNestedDynlistReferenceScenario(t, openLDAP)
		ldapGoOutcome := runDynamicNestedDynlistReferenceScenario(t, ldapGo)
		if !reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
			t.Fatalf(
				"dynamic nesting mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
				openLDAPOutcome,
				ldapGoOutcome,
			)
		}
	})

	t.Run("URL attributes and extensions", func(t *testing.T) {
		configuration := "groupOfURLs memberURL member+dgMemberOf*"
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dynlist\ndynlist-attrset " + configuration},
			"include "+tools.schemaDir+"/dyngroup.schema",
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addDynlistURLMetadataReferenceFixtures(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addDynlistURLMetadataReferenceFixtures(t, ldapGo)
		addDynlistReferenceOverlay(t, configClient, configuration, false)

		openLDAPOutcome := runDynlistURLMetadataReferenceScenario(t, openLDAP)
		ldapGoOutcome := runDynlistURLMetadataReferenceScenario(t, ldapGo)
		if !reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
			t.Fatalf(
				"dynlist URL metadata mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
				openLDAPOutcome,
				ldapGoOutcome,
			)
		}
	})

	t.Run("local LDAP URL schemes", func(t *testing.T) {
		configuration := "groupOfURLs memberURL member"
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dynlist\ndynlist-attrset " + configuration},
			"include "+tools.schemaDir+"/dyngroup.schema",
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addLegacyDynlistReferenceFixture(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addLegacyDynlistReferenceFixture(t, ldapGo)
		addDynlistReferenceOverlay(t, configClient, configuration, false)

		run := func(client *ldap.Conn) []string {
			t.Helper()
			var outcome []string
			for _, prefix := range []string{
				"ldap://",
				"ldaps://",
				"ldapi://",
				"pldap://",
				"pldaps://",
				"<URL:ldap://",
			} {
				rawURL := prefix +
					"/ou=people,dc=example,dc=com??sub?(uid=alice)"
				if strings.HasPrefix(prefix, "<") {
					rawURL += ">"
				}
				modify := ldap.NewModifyRequest(testDynlistGroupDN, nil)
				modify.Replace("memberURL", []string{rawURL})
				if err := client.Modify(modify); err != nil {
					t.Fatalf("Modify(local URL %q): %v", rawURL, err)
				}
				entry := searchDynlistEntry(
					t,
					client,
					testDynlistGroupDN,
					ldap.ScopeBaseObject,
					"(objectClass=groupOfURLs)",
					[]string{"member"},
					nil,
				)
				outcome = append(
					outcome,
					prefix+"="+strings.Join(
						dynlistSortedStrings(entry.GetAttributeValues("member")),
						",",
					)+fmt.Sprintf(
						"/%d",
						overlayCompareResultCode(
							t,
							client,
							testDynlistGroupDN,
							"member",
							testDynlistAliceDN,
						),
					),
				)
			}
			return outcome
		}
		openLDAPOutcome := run(openLDAP)
		ldapGoOutcome := run(ldapGo)
		if !reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
			t.Fatalf(
				"local dynlist URL mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
				openLDAPOutcome,
				ldapGoOutcome,
			)
		}
	})

	t.Run("invalid URL compare results", func(t *testing.T) {
		configuration := "groupOfURLs memberURL member"
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dynlist\ndynlist-attrset " + configuration},
			"include "+tools.schemaDir+"/dyngroup.schema",
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addLegacyDynlistReferenceFixture(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addLegacyDynlistReferenceFixture(t, ldapGo)
		addDynlistReferenceOverlay(t, configClient, configuration, false)

		run := func(client *ldap.Conn) []uint16 {
			t.Helper()
			var codes []uint16
			for _, rawURL := range []string{
				"ldap:///ou=people,dc=example,dc=com??sub?(uid=alice",
				"ldap:///ou=people,dc=example,dc=com?mail?sub?(uid=alice",
				"ldap:///ou=people,dc=example,dc=com??sub?(uid=alice)?",
			} {
				modify := ldap.NewModifyRequest(testDynlistGroupDN, nil)
				modify.Replace("memberURL", []string{rawURL})
				if err := client.Modify(modify); err != nil {
					t.Fatalf("Modify(invalid-filter memberURL): %v", err)
				}
				codes = append(codes, overlayCompareResultCode(
					t,
					client,
					testDynlistGroupDN,
					"member",
					testDynlistAliceDN,
				))
			}
			return codes
		}
		openLDAPCodes := run(openLDAP)
		ldapGoCodes := run(ldapGo)
		if !reflect.DeepEqual(openLDAPCodes, ldapGoCodes) {
			t.Fatalf(
				"invalid URL filter Compare mismatch: OpenLDAP=%v, ldap-go=%v",
				openLDAPCodes,
				ldapGoCodes,
			)
		}
	})

	t.Run("mapped DN membership identity", func(t *testing.T) {
		configuration := "groupOfURLs memberURL member:seeAlso+dgMemberOf"
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dynlist\ndynlist-attrset " + configuration},
			"include "+tools.schemaDir+"/dyngroup.schema",
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addMappedDNDynlistReferenceFixtures(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addMappedDNDynlistReferenceFixtures(t, ldapGo)
		addDynlistReferenceOverlay(t, configClient, configuration, false)

		openLDAPOutcome := runMappedDNDynlistReferenceScenario(t, openLDAP)
		ldapGoOutcome := runMappedDNDynlistReferenceScenario(t, ldapGo)
		if !reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
			t.Fatalf(
				"mapped DN dynlist mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
				openLDAPOutcome,
				ldapGoOutcome,
			)
		}
	})

	t.Run("expansion identity authorization", func(t *testing.T) {
		databaseACL := fmt.Sprintf(
			"access to attrs=userPassword by self write by anonymous auth by * none\n"+
				"access to dn.base=\"%s\" by * read\n"+
				"access to * by users read by * search",
			testDynlistGroupDN,
		)
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{
				"dynlist\n" +
					"dynlist-attrset groupOfURLs memberURL member",
			},
			"include "+tools.schemaDir+"/dyngroup.schema",
			databaseACL,
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addOpenLDAPDynlistIdentityFixtures(t, openLDAP)

		ldapGo, configClient, ldapGoURI, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addLDAPGoDynlistIdentityFixtures(t, ldapGo)
		addDynlistReferenceOverlay(
			t,
			configClient,
			"groupOfURLs memberURL member",
			false,
		)
		access := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
		access.Replace("olcAccess", []string{
			"{0}to attrs=userPassword by self write by anonymous auth by * none",
			"{1}to dn.base=\"" + testDynlistGroupDN + "\" by * read",
			"{2}to * by users read by * search",
		})
		if err := configClient.Modify(access); err != nil {
			t.Fatalf("Modify(ldap-go dynlist ACL): %v", err)
		}

		openLDAPOutcome := runDynlistIdentityReferenceScenario(
			t,
			openLDAP,
			openLDAPURI,
		)
		ldapGoOutcome := runDynlistIdentityReferenceScenario(
			t,
			ldapGo,
			ldapGoURI,
		)
		if !reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
			t.Fatalf(
				"dynlist identity mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
				openLDAPOutcome,
				ldapGoOutcome,
			)
		}
	})

	t.Run("memberOf URL attribute ACL", func(t *testing.T) {
		configuration := "groupOfURLs memberURL member+dgMemberOf"
		databaseACL := "access to dn.base=\"" + testDynlistGroupDN +
			"\" attrs=memberURL by * none\naccess to * by * read"
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dynlist\ndynlist-attrset " + configuration},
			"include "+tools.schemaDir+"/dyngroup.schema",
			databaseACL,
			"",
		)
		defer stopOpenLDAP()
		openLDAPRoot := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		addLegacyDynlistReferenceFixture(t, openLDAPRoot)
		restrictOpenLDAP := ldap.NewModifyRequest(testDynlistGroupDN, nil)
		restrictOpenLDAP.Replace(
			"memberURL",
			[]string{"ldap:///ou=people,dc=example,dc=com??sub?(uid=alice)"},
		)
		if err := openLDAPRoot.Modify(restrictOpenLDAP); err != nil {
			t.Fatalf("Modify(OpenLDAP ACL fixture URL): %v", err)
		}
		openLDAPRoot.Close()

		ldapGoRoot, configClient, ldapGoURI, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		addLegacyDynlistReferenceFixture(t, ldapGoRoot)
		restrictLDAPGo := ldap.NewModifyRequest(testDynlistGroupDN, nil)
		restrictLDAPGo.Replace(
			"memberURL",
			[]string{"ldap:///ou=people,dc=example,dc=com??sub?(uid=alice)"},
		)
		if err := ldapGoRoot.Modify(restrictLDAPGo); err != nil {
			t.Fatalf("Modify(ldap-go ACL fixture URL): %v", err)
		}
		addDynlistReferenceOverlay(t, configClient, configuration, false)
		access := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
		access.Replace("olcAccess", []string{
			"{0}to dn.base=\"" + testDynlistGroupDN + "\" attrs=memberURL by * none",
			"{1}to * by * read",
		})
		if err := configClient.Modify(access); err != nil {
			t.Fatalf("Modify(ldap-go dynlist URL ACL): %v", err)
		}
		ldapGoRoot.Close()
		configClient.Close()

		run := func(uri string) []string {
			t.Helper()
			client, err := ldap.DialURL(uri)
			if err != nil {
				t.Fatalf("DialURL(dynlist ACL): %v", err)
			}
			defer client.Close()
			group := searchDynlistEntry(
				t,
				client,
				testDynlistGroupDN,
				ldap.ScopeBaseObject,
				"(objectClass=groupOfURLs)",
				[]string{"member"},
				nil,
			)
			alice := searchDynlistEntry(
				t,
				client,
				testDynlistAliceDN,
				ldap.ScopeBaseObject,
				"(objectClass=inetOrgPerson)",
				[]string{"dgMemberOf"},
				nil,
			)
			filtered := searchDynlist(
				t,
				client,
				"ou=people,dc=example,dc=com",
				ldap.ScopeWholeSubtree,
				"(dgMemberOf="+ldap.EscapeFilter(testDynlistGroupDN)+")",
				[]string{"uid"},
				nil,
			)
			return []string{
				"member=" + strings.Join(
					dynlistSortedStrings(group.GetAttributeValues("member")),
					",",
				),
				"memberOf=" + strings.Join(
					dynlistSortedStrings(alice.GetAttributeValues("dgMemberOf")),
					",",
				),
				"filter=" + strings.Join(sortedLDAPEntryDNs(filtered.Entries), ","),
			}
		}
		openLDAPOutcome := run(openLDAPURI)
		ldapGoOutcome := run(ldapGoURI)
		if !reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
			t.Fatalf(
				"dynlist URL ACL mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
				openLDAPOutcome,
				ldapGoOutcome,
			)
		}
	})

	t.Run("memberOf hidden group ACL", func(t *testing.T) {
		configuration := "groupOfURLs memberURL member+dgMemberOf"
		databaseACL := "access to dn.base=\"" + testDynlistGroupDN +
			"\" by * none\naccess to * by * read"
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dynlist\ndynlist-attrset " + configuration},
			"include "+tools.schemaDir+"/dyngroup.schema",
			databaseACL,
			"",
		)
		defer stopOpenLDAP()
		openLDAPRoot := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		addLegacyDynlistReferenceFixture(t, openLDAPRoot)
		openLDAPURL := ldap.NewModifyRequest(testDynlistGroupDN, nil)
		openLDAPURL.Replace(
			"memberURL",
			[]string{"ldap:///ou=people,dc=example,dc=com??sub?(uid=alice)"},
		)
		if err := openLDAPRoot.Modify(openLDAPURL); err != nil {
			t.Fatalf("Modify(OpenLDAP hidden-group URL): %v", err)
		}
		openLDAPRoot.Close()

		ldapGoRoot, configClient, ldapGoURI, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		addLegacyDynlistReferenceFixture(t, ldapGoRoot)
		ldapGoURL := ldap.NewModifyRequest(testDynlistGroupDN, nil)
		ldapGoURL.Replace(
			"memberURL",
			[]string{"ldap:///ou=people,dc=example,dc=com??sub?(uid=alice)"},
		)
		if err := ldapGoRoot.Modify(ldapGoURL); err != nil {
			t.Fatalf("Modify(ldap-go hidden-group URL): %v", err)
		}
		addDynlistReferenceOverlay(t, configClient, configuration, false)
		access := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
		access.Replace("olcAccess", []string{
			"{0}to dn.base=\"" + testDynlistGroupDN + "\" by * none",
			"{1}to * by * read",
		})
		if err := configClient.Modify(access); err != nil {
			t.Fatalf("Modify(ldap-go hidden-group ACL): %v", err)
		}
		ldapGoRoot.Close()
		configClient.Close()

		run := func(uri string) []string {
			t.Helper()
			client, err := ldap.DialURL(uri)
			if err != nil {
				t.Fatalf("DialURL(hidden dynlist group): %v", err)
			}
			defer client.Close()
			alice := searchDynlistEntry(
				t,
				client,
				testDynlistAliceDN,
				ldap.ScopeBaseObject,
				"(objectClass=inetOrgPerson)",
				[]string{"dgMemberOf"},
				nil,
			)
			filtered := searchDynlist(
				t,
				client,
				"ou=people,dc=example,dc=com",
				ldap.ScopeWholeSubtree,
				"(dgMemberOf="+ldap.EscapeFilter(testDynlistGroupDN)+")",
				[]string{"uid"},
				nil,
			)
			return []string{
				"memberOf=" + strings.Join(
					dynlistSortedStrings(alice.GetAttributeValues("dgMemberOf")),
					",",
				),
				"filter=" + strings.Join(sortedLDAPEntryDNs(filtered.Entries), ","),
			}
		}
		openLDAPOutcome := run(openLDAPURI)
		ldapGoOutcome := run(ldapGoURI)
		if !reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
			t.Fatalf(
				"hidden-group dynlist mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
				openLDAPOutcome,
				ldapGoOutcome,
			)
		}
	})

	t.Run("legacy dyngroup compare only", func(t *testing.T) {
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dyngroup\nattrpair member memberURL"},
			"include "+tools.schemaDir+"/dyngroup.schema",
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addLegacyDynlistReferenceFixture(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addLegacyDynlistReferenceFixture(t, ldapGo)
		overlay := ldap.NewAddRequest(
			"olcOverlay={0}dyngroup,olcDatabase={1}mdb,cn=config",
			nil,
		)
		overlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcDynGroupConfig"})
		overlay.Attribute("olcOverlay", []string{"{0}dyngroup"})
		overlay.Attribute("olcDynGroupAttrPair", []string{"member memberURL"})
		if err := configClient.Add(overlay); err != nil {
			t.Fatalf("Add(ldap-go dyngroup overlay): %v", err)
		}

		openLDAPOutcome := runLegacyDynlistReferenceScenario(t, openLDAP)
		ldapGoOutcome := runLegacyDynlistReferenceScenario(t, ldapGo)
		if !reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
			t.Fatalf(
				"legacy dyngroup mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
				openLDAPOutcome,
				ldapGoOutcome,
			)
		}
	})

	t.Run("legacy dyngroup target ACL", func(t *testing.T) {
		compareACL := "access to dn.base=\"" + testDynlistGroupDN +
			"\" attrs=entry by * read\naccess to dn.base=\"" + testDynlistGroupDN +
			"\" attrs=member by * compare\naccess to * by * none"
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{"dyngroup\nattrpair member memberURL"},
			"include "+tools.schemaDir+"/dyngroup.schema",
			compareACL,
			"",
		)
		defer stopOpenLDAP()
		openLDAPRoot := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		addLegacyDynlistReferenceFixture(t, openLDAPRoot)
		openLDAPRoot.Close()

		ldapGoRoot, configClient, ldapGoURI, stopLDAPGo := startDynlistReferenceLDAPGo(t)
		defer stopLDAPGo()
		addLegacyDynlistReferenceFixture(t, ldapGoRoot)
		overlay := ldap.NewAddRequest(
			"olcOverlay={0}dyngroup,olcDatabase={1}mdb,cn=config",
			nil,
		)
		overlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcDynGroupConfig"})
		overlay.Attribute("olcOverlay", []string{"{0}dyngroup"})
		overlay.Attribute("olcDynGroupAttrPair", []string{"member memberURL"})
		if err := configClient.Add(overlay); err != nil {
			t.Fatalf("Add(ldap-go ACL dyngroup overlay): %v", err)
		}
		access := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
		access.Replace("olcAccess", []string{
			"{0}to dn.base=\"" + testDynlistGroupDN + "\" attrs=entry by * read",
			"{1}to dn.base=\"" + testDynlistGroupDN + "\" attrs=member by * compare",
			"{2}to * by * none",
		})
		if err := configClient.Modify(access); err != nil {
			t.Fatalf("Modify(ldap-go ACL dyngroup access): %v", err)
		}
		ldapGoRoot.Close()
		configClient.Close()

		openLDAPAnonymous, err := ldap.DialURL(openLDAPURI)
		if err != nil {
			t.Fatalf("DialURL(OpenLDAP anonymous): %v", err)
		}
		defer openLDAPAnonymous.Close()
		ldapGoAnonymous, err := ldap.DialURL(ldapGoURI)
		if err != nil {
			t.Fatalf("DialURL(ldap-go anonymous): %v", err)
		}
		defer ldapGoAnonymous.Close()
		openLDAPMatched, openLDAPErr := openLDAPAnonymous.Compare(
			testDynlistGroupDN,
			"member",
			testDynlistAliceDN,
		)
		ldapGoMatched, ldapGoErr := ldapGoAnonymous.Compare(
			testDynlistGroupDN,
			"member",
			testDynlistAliceDN,
		)
		if openLDAPErr != nil || ldapGoErr != nil ||
			openLDAPMatched != ldapGoMatched {
			t.Fatalf(
				"ACL dyngroup compare mismatch: OpenLDAP=(%v, %v), ldap-go=(%v, %v)",
				openLDAPMatched,
				openLDAPErr,
				ldapGoMatched,
				ldapGoErr,
			)
		}
	})
}

func TestOpenLDAPSlapcatDynlistAndDyngroupConfigImport(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	slaptest := findOpenLDAPSchemaTool(
		t,
		"slaptest",
		"/opt/homebrew/opt/openldap/sbin/slaptest",
		"/usr/sbin/slaptest",
	)
	slapcat := findOpenLDAPSchemaTool(
		t,
		"slapcat",
		"/opt/homebrew/opt/openldap/sbin/slapcat",
		"/usr/sbin/slapcat",
	)

	root := t.TempDir()
	configDir := filepath.Join(root, "slapd.d")
	databaseDir := filepath.Join(root, "db")
	for _, path := range []string{configDir, databaseDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("Mkdir(%s): %v", path, err)
		}
	}
	configPath := filepath.Join(root, "slapd.conf")
	config := fmt.Sprintf(
		`include %s
include %s
include %s
include %s
pidfile %s
argsfile %s

database mdb
maxsize 1073741824
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
directory %s
overlay dynlist
dynlist-attrset groupOfURLs "ldap:///ou=groups,dc=example,dc=com??sub?(cn=*)" memberURL member+dgMemberOf@groupOfNames*
dynlist-simple FALSE
overlay dyngroup
attrpair uniqueMember memberURL
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		filepath.Join(tools.schemaDir, "dyngroup.schema"),
		filepath.Join(root, "slapd.pid"),
		filepath.Join(root, "slapd.args"),
		databaseDir,
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write slapd.conf: %v", err)
	}
	dataPath := filepath.Join(root, "data.ldif")
	data := `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

`
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		t.Fatalf("write OpenLDAP seed data: %v", err)
	}
	command := exec.Command(
		tools.slapadd,
		"-q",
		"-f",
		configPath,
		"-l",
		dataPath,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("slapadd failed: %v\n%s", err, output)
	}
	command = exec.Command(slaptest, "-f", configPath, "-F", configDir)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("slaptest failed: %v\n%s", err, output)
	}

	var stderr bytes.Buffer
	command = exec.Command(
		slapcat,
		"-F",
		configDir,
		"-n",
		"0",
		"-a",
		"(olcOverlay=*)",
	)
	command.Stderr = &stderr
	exported, err := command.Output()
	if err != nil {
		t.Fatalf("slapcat -n 0 failed: %v\n%s", err, stderr.Bytes())
	}
	for _, expected := range [][]byte{
		[]byte("olcDynListConfig"),
		[]byte("olcDynListAttrSet:"),
		[]byte("olcDynListSimple: FALSE"),
		[]byte("olcDynGroupConfig"),
		[]byte("olcDynGroupAttrPair: uniqueMember memberURL"),
	} {
		if !bytes.Contains(exported, expected) {
			t.Fatalf("slapcat output is missing %q:\n%s", expected, exported)
		}
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		bytes.NewReader(exported),
		migration.ImportOptions{},
	); err != nil {
		t.Fatalf("ImportLDIF(real slapcat dynlist config): %v\n%s", err, exported)
	}
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer client.Close()
	addDynlistFixtures(t, client)
	memberURL := ldap.NewModifyRequest(testDynlistGroupDN, nil)
	memberURL.Replace(
		"memberURL",
		[]string{"ldap:///ou=people,dc=example,dc=com??sub?(uid=alice)"},
	)
	if err := client.Modify(memberURL); err != nil {
		t.Fatalf("Modify(imported dynlist memberURL): %v", err)
	}

	group := searchDynlistEntry(
		t,
		client,
		testDynlistGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"member"},
		nil,
	)
	assertDynlistValues(
		t,
		group.GetAttributeValues("member"),
		[]string{testDynlistAliceDN},
	)
	member, err := client.Compare(testDynlistGroupDN, "member", testDynlistAliceDN)
	if err != nil || !member {
		t.Fatalf("Compare(imported dynlist member) = %v, %v", member, err)
	}
	uniqueMember, err := client.Compare(
		testDynlistGroupDN,
		"uniqueMember",
		testDynlistAliceDN,
	)
	if err != nil || !uniqueMember {
		t.Fatalf("Compare(imported dyngroup uniqueMember) = %v, %v", uniqueMember, err)
	}
}

func startDynlistReferenceLDAPGo(
	t *testing.T,
) (*ldap.Conn, *ldap.Conn, string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	dataClient := bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	configClient := bindConstraintClient(t, address, "cn=config", "config-secret")
	return dataClient, configClient, "ldap://" + address, stop
}

func addDynlistReferenceOverlay(
	t *testing.T,
	configClient *ldap.Conn,
	configuration string,
	simple bool,
) {
	t.Helper()
	addDynlistReferenceOverlaySets(
		t,
		configClient,
		[]string{configuration},
		simple,
	)
}

func addDynlistReferenceOverlaySets(
	t *testing.T,
	configClient *ldap.Conn,
	configurations []string,
	simple bool,
) {
	t.Helper()
	overlay := ldap.NewAddRequest(testDynlistOverlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcDynListConfig"})
	overlay.Attribute("olcOverlay", []string{"{0}dynlist"})
	overlay.Attribute("olcDynListAttrSet", configurations)
	if simple {
		overlay.Attribute("olcDynListSimple", []string{"TRUE"})
	}
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(ldap-go dynlist overlay): %v", err)
	}
}

func addMultipleAttributeSetDynlistFixtures(t *testing.T, client *ldap.Conn) {
	t.Helper()
	ensureDynlistReferenceBob(t, client)
	addDynlistGroupsOU(t, client)

	dynamic := ldap.NewAddRequest(testDynlistGroupDN, nil)
	dynamic.Attribute("objectClass", []string{"groupOfURLs"})
	dynamic.Attribute("cn", []string{"Dynamic Group"})
	dynamic.Attribute(
		"memberURL",
		[]string{"ldap:///ou=people,dc=example,dc=com??sub?(uid=alice)"},
	)
	if err := client.Add(dynamic); err != nil {
		t.Fatalf("Add(multiple attrset dynamic group): %v", err)
	}

	uriGroupDN := "cn=URI Group,ou=groups,dc=example,dc=com"
	uriGroup := ldap.NewAddRequest(uriGroupDN, nil)
	uriGroup.Attribute("objectClass", []string{"organizationalRole", "labeledURIObject"})
	uriGroup.Attribute("cn", []string{"URI Group"})
	uriGroup.Attribute(
		"labeledURI",
		[]string{"ldap:///ou=people,dc=example,dc=com??sub?(uid=bob)"},
	)
	if err := client.Add(uriGroup); err != nil {
		t.Fatalf("Add(multiple attrset URI group): %v", err)
	}

	staticGroupDN := "cn=Unique Static,ou=groups,dc=example,dc=com"
	staticGroup := ldap.NewAddRequest(staticGroupDN, nil)
	staticGroup.Attribute("objectClass", []string{"groupOfUniqueNames"})
	staticGroup.Attribute("cn", []string{"Unique Static"})
	staticGroup.Attribute(
		"uniqueMember",
		[]string{testDynlistAliceDN, testDynlistBobDN + "#'1'B"},
	)
	if err := client.Add(staticGroup); err != nil {
		t.Fatalf("Add(multiple attrset static group): %v", err)
	}
}

func runMultipleAttributeSetDynlistScenario(
	t *testing.T,
	client *ldap.Conn,
) dynlistMultipleAttributeSetOutcome {
	t.Helper()
	uriGroupDN := "cn=URI Group,ou=groups,dc=example,dc=com"
	staticGroupDN := "cn=Unique Static,ou=groups,dc=example,dc=com"
	dynamic := searchDynlistEntry(
		t,
		client,
		testDynlistGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"member"},
		nil,
	)
	uriGroup := searchDynlistEntry(
		t,
		client,
		uriGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=labeledURIObject)",
		[]string{"uniqueMember"},
		nil,
	)
	alice := searchDynlistEntry(
		t,
		client,
		testDynlistAliceDN,
		ldap.ScopeBaseObject,
		"(objectClass=inetOrgPerson)",
		[]string{"dgMemberOf", "seeAlso"},
		nil,
	)
	bob := searchDynlistEntry(
		t,
		client,
		testDynlistBobDN,
		ldap.ScopeBaseObject,
		"(objectClass=inetOrgPerson)",
		[]string{"dgMemberOf", "seeAlso"},
		nil,
	)
	negated := searchDynlist(
		t,
		client,
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(&(|(uid=alice)(uid=bob))(!(dgMemberOf="+
			ldap.EscapeFilter(testDynlistGroupDN)+")))",
		[]string{"uid", "dgMemberOf"},
		nil,
	)
	filteredSeeAlso := searchDynlist(
		t,
		client,
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(&(objectClass=inetOrgPerson)(seeAlso="+
			ldap.EscapeFilter(uriGroupDN)+"))",
		[]string{"uid", "seeAlso"},
		nil,
	)
	return dynlistMultipleAttributeSetOutcome{
		dynamicMembers:  dynlistSortedStrings(dynamic.GetAttributeValues("member")),
		uriMembers:      dynlistSortedStrings(uriGroup.GetAttributeValues("uniqueMember")),
		aliceDGMemberOf: dynlistSortedStrings(alice.GetAttributeValues("dgMemberOf")),
		aliceSeeAlso:    dynlistSortedStrings(alice.GetAttributeValues("seeAlso")),
		bobSeeAlso:      dynlistSortedStrings(bob.GetAttributeValues("seeAlso")),
		negatedMemberOf: sortedLDAPEntryDNs(negated.Entries),
		filteredSeeAlso: sortedLDAPEntryDNs(filteredSeeAlso.Entries),
		uniqueMemberCodes: []uint16{
			overlayCompareResultCode(t, client, uriGroupDN, "uniqueMember", testDynlistBobDN),
			overlayCompareResultCode(
				t,
				client,
				uriGroupDN,
				"uniqueMember",
				testDynlistBobDN+"#'1'B",
			),
			overlayCompareResultCode(
				t,
				client,
				staticGroupDN,
				"uniqueMember",
				testDynlistBobDN+"#'1'B",
			),
		},
	}
}

func addOpenLDAPDynlistListFixtures(t *testing.T, client *ldap.Conn) {
	t.Helper()
	for _, fixture := range []struct {
		dn   string
		mail string
	}{
		{dn: testDynlistAliceDN, mail: "alice@example.com"},
		{dn: testDynlistBobDN, mail: "bob@example.com"},
	} {
		modify := ldap.NewModifyRequest(fixture.dn, nil)
		modify.Add("mail", []string{fixture.mail})
		if err := client.Modify(modify); err != nil {
			t.Fatalf("Modify(OpenLDAP %s mail): %v", fixture.dn, err)
		}
	}
	addDynlistGroupsOU(t, client)
	group := ldap.NewAddRequest(testDynlistGroupDN, nil)
	group.Attribute("objectClass", []string{"groupOfURLs"})
	group.Attribute("cn", []string{"Dynamic Group"})
	group.Attribute(
		"memberURL",
		[]string{
			"ldap:///ou=people,dc=example,dc=com?mail?sub?" +
				"(objectClass=inetOrgPerson)",
		},
	)
	if err := client.Add(group); err != nil {
		t.Fatalf("Add(OpenLDAP dynamic list): %v", err)
	}
}

func addExcludedDynlistReferenceGroup(t *testing.T, client *ldap.Conn) {
	t.Helper()
	group := ldap.NewAddRequest(
		"cn=Outside Restriction,ou=groups,dc=example,dc=com",
		nil,
	)
	group.Attribute("objectClass", []string{"groupOfURLs"})
	group.Attribute("cn", []string{"Outside Restriction"})
	group.Attribute(
		"memberURL",
		[]string{
			"ldap:///ou=people,dc=example,dc=com?mail?sub?" +
				"(objectClass=inetOrgPerson)",
		},
	)
	if err := client.Add(group); err != nil {
		t.Fatalf("Add(excluded dynamic list): %v", err)
	}
}

func runRestrictedDynlistReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
) dynlistReferenceOutcome {
	t.Helper()
	included := searchDynlistEntry(
		t,
		client,
		testDynlistGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"mail"},
		nil,
	)
	excluded := searchDynlistEntry(
		t,
		client,
		"cn=Outside Restriction,ou=groups,dc=example,dc=com",
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"mail"},
		nil,
	)
	filtered := searchDynlist(
		t,
		client,
		"ou=groups,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(mail=alice@example.com)",
		[]string{"cn"},
		nil,
	)
	return dynlistReferenceOutcome{
		values:   dynlistSortedStrings(included.GetAttributeValues("mail")),
		managed:  dynlistSortedStrings(excluded.GetAttributeValues("mail")),
		filtered: sortedLDAPEntryDNs(filtered.Entries),
	}
}

func runMappedDynlistReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
) dynlistReferenceOutcome {
	t.Helper()
	group := searchDynlistEntry(
		t,
		client,
		testDynlistGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"mail"},
		nil,
	)
	filtered := searchDynlist(
		t,
		client,
		"ou=groups,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(mail=alice@example.com)",
		[]string{"cn"},
		nil,
	)
	managed := searchDynlistEntry(
		t,
		client,
		testDynlistGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"mail", "memberURL"},
		[]ldap.Control{ldap.NewControlManageDsaIT(true)},
	)
	trueCompare, err := client.Compare(
		testDynlistGroupDN,
		"mail",
		"alice@example.com",
	)
	if err != nil {
		t.Fatalf("Compare(dynamic mail true): %v", err)
	}
	falseCompare, err := client.Compare(
		testDynlistGroupDN,
		"mail",
		"missing@example.com",
	)
	if err != nil {
		t.Fatalf("Compare(dynamic mail false): %v", err)
	}
	return dynlistReferenceOutcome{
		values:   dynlistSortedStrings(group.GetAttributeValues("mail")),
		filtered: sortedLDAPEntryDNs(filtered.Entries),
		managed:  dynlistSortedStrings(managed.GetAttributeValues("mail")),
		compares: []bool{trueCompare, falseCompare},
	}
}

func runPagedDynlistFilterReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
) []string {
	t.Helper()
	result := searchDynlist(
		t,
		client,
		"ou=groups,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(mail=alice@example.com)",
		[]string{"cn"},
		[]ldap.Control{ldap.NewControlPaging(1)},
	)
	return sortedLDAPEntryDNs(result.Entries)
}

func runPagedDynlistMemberOfReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
) []string {
	t.Helper()
	paging := ldap.NewControlPaging(1)
	request := ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(dgMemberOf="+ldap.EscapeFilter(testDynlistGroupDN)+")",
		[]string{"uid", "dgMemberOf"},
		[]ldap.Control{paging},
	)
	var dns []string
	for {
		result, err := client.Search(request)
		if err != nil {
			t.Fatalf("Search(paged dynlist memberOf): %v", err)
		}
		for _, entry := range result.Entries {
			dns = append(dns, entry.DN)
		}
		response, ok := ldap.FindControl(result.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if !ok {
			t.Fatal("paged dynlist memberOf response is missing paging control")
		}
		if len(response.Cookie) == 0 {
			break
		}
		paging.SetCookie(response.Cookie)
	}
	return dynlistSortedStrings(dns)
}

func addNestedDynlistReferenceFixtures(t *testing.T, client *ldap.Conn) {
	t.Helper()
	addDynlistGroupsOU(t, client)
	childDN := "cn=Static Child,ou=groups,dc=example,dc=com"
	child := ldap.NewAddRequest(childDN, nil)
	child.Attribute("objectClass", []string{"groupOfNames"})
	child.Attribute("cn", []string{"Static Child"})
	child.Attribute("member", []string{testDynlistAliceDN})
	if err := client.Add(child); err != nil {
		t.Fatalf("Add(reference static child): %v", err)
	}
	parent := ldap.NewAddRequest(
		"cn=Nested Parent,ou=groups,dc=example,dc=com",
		nil,
	)
	parent.Attribute("objectClass", []string{"groupOfURLs"})
	parent.Attribute("cn", []string{"Nested Parent"})
	parent.Attribute(
		"memberURL",
		[]string{
			"ldap:///ou=groups,dc=example,dc=com??sub?" +
				"(cn=Static Child)",
		},
	)
	if err := client.Add(parent); err != nil {
		t.Fatalf("Add(reference nested parent): %v", err)
	}
}

func runNestedDynlistReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
) dynlistReferenceOutcome {
	t.Helper()
	parentDN := "cn=Nested Parent,ou=groups,dc=example,dc=com"
	parent := searchDynlistEntry(
		t,
		client,
		parentDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"member"},
		nil,
	)
	alice := searchDynlistEntry(
		t,
		client,
		testDynlistAliceDN,
		ldap.ScopeBaseObject,
		"(objectClass=inetOrgPerson)",
		[]string{"dgMemberOf"},
		nil,
	)
	filtered := searchDynlist(
		t,
		client,
		"ou=groups,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(member="+ldap.EscapeFilter(testDynlistAliceDN)+")",
		[]string{"cn"},
		nil,
	)
	matched, err := client.Compare(parentDN, "member", testDynlistAliceDN)
	if err != nil {
		t.Fatalf("Compare(nested member): %v", err)
	}
	return dynlistReferenceOutcome{
		values:   dynlistSortedStrings(parent.GetAttributeValues("member")),
		filtered: sortedLDAPEntryDNs(filtered.Entries),
		memberOf: dynlistSortedStrings(alice.GetAttributeValues("dgMemberOf")),
		compares: []bool{matched},
	}
}

func addDynamicNestedDynlistReferenceFixtures(t *testing.T, client *ldap.Conn) {
	t.Helper()
	addDynlistGroupsOU(t, client)
	childDN := "cn=Dynamic Child,ou=groups,dc=example,dc=com"
	child := ldap.NewAddRequest(childDN, nil)
	child.Attribute("objectClass", []string{"groupOfURLs"})
	child.Attribute("cn", []string{"Dynamic Child"})
	child.Attribute(
		"memberURL",
		[]string{
			"ldap:///ou=people,dc=example,dc=com??sub?(uid=alice)",
		},
	)
	if err := client.Add(child); err != nil {
		t.Fatalf("Add(dynamic child): %v", err)
	}
	parent := ldap.NewAddRequest(
		"cn=Dynamic Parent,ou=groups,dc=example,dc=com",
		nil,
	)
	parent.Attribute("objectClass", []string{"groupOfURLs"})
	parent.Attribute("cn", []string{"Dynamic Parent"})
	parent.Attribute(
		"memberURL",
		[]string{
			"ldap:///ou=groups,dc=example,dc=com??sub?(cn=Dynamic Child)",
		},
	)
	if err := client.Add(parent); err != nil {
		t.Fatalf("Add(dynamic parent): %v", err)
	}
}

func runDynamicNestedDynlistReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
) dynlistReferenceOutcome {
	t.Helper()
	parentDN := "cn=Dynamic Parent,ou=groups,dc=example,dc=com"
	direct := searchDynlistEntry(
		t,
		client,
		parentDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"member"},
		nil,
	)
	recursive := searchDynlistEntry(
		t,
		client,
		parentDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"member", "dgMemberOf"},
		nil,
	)
	filtered := searchDynlist(
		t,
		client,
		parentDN,
		ldap.ScopeBaseObject,
		"(member="+ldap.EscapeFilter(testDynlistAliceDN)+")",
		[]string{"member"},
		nil,
	)
	alice := searchDynlistEntry(
		t,
		client,
		testDynlistAliceDN,
		ldap.ScopeBaseObject,
		"(objectClass=inetOrgPerson)",
		[]string{"dgMemberOf"},
		nil,
	)
	matched, err := client.Compare(parentDN, "member", testDynlistAliceDN)
	if err != nil {
		t.Fatalf("Compare(recursive member): %v", err)
	}
	return dynlistReferenceOutcome{
		values:   dynlistSortedStrings(direct.GetAttributeValues("member")),
		managed:  dynlistSortedStrings(recursive.GetAttributeValues("member")),
		filtered: sortedLDAPEntryDNs(filtered.Entries),
		memberOf: dynlistSortedStrings(alice.GetAttributeValues("dgMemberOf")),
		compares: []bool{matched},
	}
}

func addDynlistURLMetadataReferenceFixtures(t *testing.T, client *ldap.Conn) {
	t.Helper()
	ensureDynlistReferenceBob(t, client)
	addDynlistGroupsOU(t, client)
	for _, fixture := range []struct {
		dn  string
		url string
	}{
		{
			dn: "cn=URL Attributes,ou=groups,dc=example,dc=com",
			url: "ldap:///ou=people,dc=example,dc=com?mail?sub?" +
				"(uid=alice)",
		},
		{
			dn: "cn=URL Extensions,ou=groups,dc=example,dc=com",
			url: "ldap:///ou=people,dc=example,dc=com??sub?" +
				"(uid=bob)?x-test=ignored",
		},
	} {
		group := ldap.NewAddRequest(fixture.dn, nil)
		group.Attribute("objectClass", []string{"groupOfURLs"})
		group.Attribute("cn", []string{fixture.dn[3:strings.Index(fixture.dn, ",")]})
		group.Attribute("memberURL", []string{fixture.url})
		if err := client.Add(group); err != nil {
			t.Fatalf("Add(%s): %v", fixture.dn, err)
		}
	}
}

func ensureDynlistReferenceBob(t *testing.T, client *ldap.Conn) {
	t.Helper()
	_, err := client.Search(ldap.NewSearchRequest(
		testDynlistBobDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		bob := ldap.NewAddRequest(testDynlistBobDN, nil)
		bob.Attribute("objectClass", []string{"inetOrgPerson"})
		bob.Attribute("uid", []string{"bob"})
		bob.Attribute("cn", []string{"Bob Example"})
		bob.Attribute("sn", []string{"Example"})
		if err := client.Add(bob); err != nil {
			t.Fatalf("Add(URL metadata Bob): %v", err)
		}
	} else if err != nil {
		t.Fatalf("Search(URL metadata Bob): %v", err)
	}
}

func runDynlistURLMetadataReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
) dynlistReferenceOutcome {
	t.Helper()
	attributesGroupDN := "cn=URL Attributes,ou=groups,dc=example,dc=com"
	extensionsGroupDN := "cn=URL Extensions,ou=groups,dc=example,dc=com"
	attributesGroup := searchDynlistEntry(
		t,
		client,
		attributesGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"member"},
		nil,
	)
	extensionsGroup := searchDynlistEntry(
		t,
		client,
		extensionsGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"member"},
		nil,
	)
	alice := searchDynlistEntry(
		t,
		client,
		testDynlistAliceDN,
		ldap.ScopeBaseObject,
		"(objectClass=inetOrgPerson)",
		[]string{"dgMemberOf"},
		nil,
	)
	bob := searchDynlistEntry(
		t,
		client,
		testDynlistBobDN,
		ldap.ScopeBaseObject,
		"(objectClass=inetOrgPerson)",
		[]string{"dgMemberOf"},
		nil,
	)
	attributesCompare, err := client.Compare(
		attributesGroupDN,
		"member",
		testDynlistAliceDN,
	)
	if err != nil {
		t.Fatalf("Compare(URL attributes member): %v", err)
	}
	extensionsCompare, err := client.Compare(
		extensionsGroupDN,
		"member",
		testDynlistBobDN,
	)
	if err != nil {
		t.Fatalf("Compare(URL extensions member): %v", err)
	}
	return dynlistReferenceOutcome{
		values:  dynlistSortedStrings(attributesGroup.GetAttributeValues("member")),
		managed: dynlistSortedStrings(extensionsGroup.GetAttributeValues("member")),
		memberOf: dynlistSortedStrings(append(
			append([]string(nil), alice.GetAttributeValues("dgMemberOf")...),
			bob.GetAttributeValues("dgMemberOf")...,
		)),
		compares: []bool{attributesCompare, extensionsCompare},
	}
}

func addMappedDNDynlistReferenceFixtures(t *testing.T, client *ldap.Conn) {
	t.Helper()
	ensureDynlistReferenceBob(t, client)
	alice := ldap.NewModifyRequest(testDynlistAliceDN, nil)
	alice.Add("objectClass", []string{"extensibleObject"})
	alice.Add("seeAlso", []string{testDynlistBobDN})
	if err := client.Modify(alice); err != nil {
		t.Fatalf("Modify(mapped DN Alice): %v", err)
	}
	addDynlistGroupsOU(t, client)
	group := ldap.NewAddRequest(testDynlistGroupDN, nil)
	group.Attribute("objectClass", []string{"groupOfURLs"})
	group.Attribute("cn", []string{"Dynamic Group"})
	group.Attribute(
		"memberURL",
		[]string{
			"ldap:///ou=people,dc=example,dc=com?seeAlso?sub?(uid=alice)",
			"ldap:///ou=people,dc=example,dc=com??sub?(uid=alice)",
		},
	)
	if err := client.Add(group); err != nil {
		t.Fatalf("Add(mapped DN group): %v", err)
	}
}

func runMappedDNDynlistReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
) dynlistReferenceOutcome {
	t.Helper()
	group := searchDynlistEntry(
		t,
		client,
		testDynlistGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"member"},
		nil,
	)
	bobFiltered := searchDynlist(
		t,
		client,
		"ou=groups,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(member="+ldap.EscapeFilter(testDynlistBobDN)+")",
		[]string{"cn"},
		nil,
	)
	aliceFiltered := searchDynlist(
		t,
		client,
		"ou=groups,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(member="+ldap.EscapeFilter(testDynlistAliceDN)+")",
		[]string{"cn"},
		nil,
	)
	alice := searchDynlistEntry(
		t,
		client,
		testDynlistAliceDN,
		ldap.ScopeBaseObject,
		"(objectClass=inetOrgPerson)",
		[]string{"dgMemberOf"},
		nil,
	)
	bob := searchDynlistEntry(
		t,
		client,
		testDynlistBobDN,
		ldap.ScopeBaseObject,
		"(objectClass=inetOrgPerson)",
		[]string{"dgMemberOf"},
		nil,
	)
	bobCompare, err := client.Compare(testDynlistGroupDN, "member", testDynlistBobDN)
	if err != nil {
		t.Fatalf("Compare(mapped DN Bob): %v", err)
	}
	aliceCompare, err := client.Compare(
		testDynlistGroupDN,
		"member",
		testDynlistAliceDN,
	)
	if err != nil {
		t.Fatalf("Compare(mapped DN Alice): %v", err)
	}
	return dynlistReferenceOutcome{
		values: dynlistSortedStrings(group.GetAttributeValues("member")),
		filtered: []string{
			"alice=" + strings.Join(sortedLDAPEntryDNs(aliceFiltered.Entries), ","),
			"bob=" + strings.Join(sortedLDAPEntryDNs(bobFiltered.Entries), ","),
		},
		memberOf: []string{
			"alice=" + strings.Join(dynlistSortedStrings(alice.GetAttributeValues("dgMemberOf")), ","),
			"bob=" + strings.Join(dynlistSortedStrings(bob.GetAttributeValues("dgMemberOf")), ","),
		},
		compares: []bool{bobCompare, aliceCompare},
	}
}

func addOpenLDAPDynlistIdentityFixtures(t *testing.T, client *ldap.Conn) {
	t.Helper()
	for _, fixture := range []struct {
		dn       string
		password string
	}{
		{dn: testDynlistAliceDN, password: "alice-secret"},
		{dn: testDynlistBobDN, password: "bob-secret"},
	} {
		modify := ldap.NewModifyRequest(fixture.dn, nil)
		modify.Add("userPassword", []string{fixture.password})
		if err := client.Modify(modify); err != nil {
			t.Fatalf("Modify(OpenLDAP identity password): %v", err)
		}
	}
	addDynlistIdentityGroup(t, client)
}

func addLDAPGoDynlistIdentityFixtures(t *testing.T, client *ldap.Conn) {
	t.Helper()
	alicePassword := ldap.NewModifyRequest(testDynlistAliceDN, nil)
	alicePassword.Replace("userPassword", []string{"alice-secret"})
	if err := client.Modify(alicePassword); err != nil {
		t.Fatalf("Modify(ldap-go Alice password): %v", err)
	}
	bob := ldap.NewAddRequest(testDynlistBobDN, nil)
	bob.Attribute("objectClass", []string{"inetOrgPerson"})
	bob.Attribute("uid", []string{"bob"})
	bob.Attribute("cn", []string{"Bob Example"})
	bob.Attribute("sn", []string{"Example"})
	bob.Attribute("userPassword", []string{"bob-secret"})
	if err := client.Add(bob); err != nil {
		t.Fatalf("Add(ldap-go identity Bob): %v", err)
	}
	addDynlistIdentityGroup(t, client)
}

func addDynlistIdentityGroup(t *testing.T, client *ldap.Conn) {
	t.Helper()
	addDynlistGroupsOU(t, client)
	group := ldap.NewAddRequest(testDynlistGroupDN, nil)
	group.Attribute("objectClass", []string{"groupOfURLs"})
	group.Attribute("cn", []string{"Dynamic Group"})
	group.Attribute(
		"memberURL",
		[]string{
			"ldap:///ou=people,dc=example,dc=com??sub?" +
				"(|(uid=alice)(uid=bob))",
		},
	)
	if err := client.Add(group); err != nil {
		t.Fatalf("Add(identity dynamic group): %v", err)
	}
}

func runDynlistIdentityReferenceScenario(
	t *testing.T,
	admin *ldap.Conn,
	uri string,
) dynlistIdentityReferenceOutcome {
	t.Helper()
	anonymous, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(anonymous): %v", err)
	}
	defer anonymous.Close()
	readMembers := func(client *ldap.Conn) []string {
		entry := searchDynlistEntry(
			t,
			client,
			testDynlistGroupDN,
			ldap.ScopeBaseObject,
			"(objectClass=groupOfURLs)",
			[]string{"member"},
			nil,
		)
		return dynlistSortedStrings(entry.GetAttributeValues("member"))
	}
	outcome := dynlistIdentityReferenceOutcome{
		anonymousBefore: readMembers(anonymous),
	}
	identity := ldap.NewModifyRequest(testDynlistGroupDN, nil)
	identity.Add("objectClass", []string{"dgIdentityAux"})
	identity.Add("dgIdentity", []string{testDynlistAliceDN})
	if err := admin.Modify(identity); err != nil {
		t.Fatalf("Modify(reference dgIdentity): %v", err)
	}
	outcome.withIdentity = readMembers(anonymous)
	authorization := ldap.NewModifyRequest(testDynlistGroupDN, nil)
	authorization.Add("dgAuthz", []string{"dn:" + testDynlistBobDN})
	if err := admin.Modify(authorization); err != nil {
		t.Fatalf("Modify(reference dgAuthz): %v", err)
	}
	outcome.anonymousDenied = readMembers(anonymous)
	outcome.anonymousCompare = overlayCompareResultCode(
		t,
		anonymous,
		testDynlistGroupDN,
		"member",
		testDynlistAliceDN,
	)
	bob, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(Bob): %v", err)
	}
	defer bob.Close()
	if err := bob.Bind(testDynlistBobDN, "bob-secret"); err != nil {
		t.Fatalf("Bind(Bob): %v", err)
	}
	outcome.authorized = readMembers(bob)
	outcome.authorizedCompare = overlayCompareResultCode(
		t,
		bob,
		testDynlistGroupDN,
		"member",
		testDynlistAliceDN,
	)
	return outcome
}

func addLegacyDynlistReferenceFixture(t *testing.T, client *ldap.Conn) {
	t.Helper()
	addDynlistGroupsOU(t, client)
	group := ldap.NewAddRequest(testDynlistGroupDN, nil)
	group.Attribute("objectClass", []string{"groupOfURLs"})
	group.Attribute("cn", []string{"Dynamic Group"})
	group.Attribute(
		"memberURL",
		[]string{
			"ldap:///ou=people,dc=example,dc=com??sub?" +
				"(objectClass=inetOrgPerson)",
		},
	)
	if err := client.Add(group); err != nil {
		t.Fatalf("Add(reference legacy dynamic group): %v", err)
	}
}

func runLegacyDynlistReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
) dynlistReferenceOutcome {
	t.Helper()
	matched, err := client.Compare(
		testDynlistGroupDN,
		"member",
		testDynlistAliceDN,
	)
	if err != nil {
		t.Fatalf("Compare(legacy dynamic group): %v", err)
	}
	group := searchDynlistEntry(
		t,
		client,
		testDynlistGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"member"},
		nil,
	)
	return dynlistReferenceOutcome{
		values:   dynlistSortedStrings(group.GetAttributeValues("member")),
		compares: []bool{matched},
	}
}

func addDynlistGroupsOU(t *testing.T, client *ldap.Conn) {
	t.Helper()
	groups := ldap.NewAddRequest("ou=groups,dc=example,dc=com", nil)
	groups.Attribute("objectClass", []string{"organizationalUnit"})
	groups.Attribute("ou", []string{"groups"})
	if err := client.Add(groups); err != nil {
		t.Fatalf("Add(reference groups OU): %v", err)
	}
}

func sortedLDAPEntryDNs(entries []*ldap.Entry) []string {
	values := make([]string, len(entries))
	for index := range entries {
		values[index] = entries[index].DN
	}
	return dynlistSortedStrings(values)
}

func dynlistSortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
