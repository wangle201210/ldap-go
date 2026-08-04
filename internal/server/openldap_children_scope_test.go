package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	childrenScopeFeatureOID = "1.3.6.1.4.1.4203.666.8.1"
	childrenScopeSuffix     = "dc=example,dc=com"
	childrenScopePeopleDN   = "ou=people," + childrenScopeSuffix
	childrenScopeAliasesDN  = "ou=aliases," + childrenScopeSuffix
	childrenScopeBaseAlias  = "cn=baseAlias," + childrenScopeSuffix
	childrenScopeReferralDN = "ou=ref," + childrenScopeSuffix
)

type childrenScopeEntryObservation struct {
	dn         string
	attributes map[string][]string
}

type childrenScopeSearchObservation struct {
	resultCode int64
	matchedDN  string
	entries    []childrenScopeEntryObservation
	references []string
	referrals  []string
	controls   map[string][]byte
}

type childrenScopePagingObservation struct {
	resultCodes  []int64
	pageSizes    []int
	cookieExists []bool
	entries      []string
}

func TestOpenLDAPReferenceChildrenScopeDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		"access to * by * read",
		childrenScopeOpenLDAPExtraData,
	)
	defer stopReference()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedChildrenScopeDifferentialDirectory(t, store)
	localAddress, stopLocal := startServer(t, store, Config{
		RootDN:       "cn=admin," + childrenScopeSuffix,
		RootPassword: []byte("secret"),
	})
	defer stopLocal()

	referenceAddress := strings.TrimPrefix(referenceURI, "ldap://")

	t.Run("stable feature OID is not advertised", func(t *testing.T) {
		request := rawChildrenScopeSearchRequest(
			t,
			"",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			"(objectClass=*)",
			[]string{"supportedFeatures"},
		)
		reference := observeChildrenScopeSearch(
			t,
			referenceAddress,
			request,
		)
		local := observeChildrenScopeSearch(
			t,
			localAddress,
			rawChildrenScopeSearchRequest(
				t,
				"",
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				0,
				"(objectClass=*)",
				[]string{"supportedFeatures"},
			),
		)
		assertChildrenScopeEquivalent(t, reference, local)
		assertChildrenScopeResult(t, reference, ldap.LDAPResultSuccess, "", []string{""}, nil, nil)
		for _, endpoint := range []struct {
			name        string
			observation childrenScopeSearchObservation
		}{
			{name: "OpenLDAP 2.6.13", observation: reference},
			{name: "ldap-go", observation: local},
		} {
			features := endpoint.observation.entries[0].attributes["supportedfeatures"]
			if slices.Contains(features, childrenScopeFeatureOID) {
				t.Fatalf("%s advertised children-scope feature OID %s", endpoint.name, childrenScopeFeatureOID)
			}
		}
	})

	peopleChildren := childrenScopePeopleChildrenDNs()
	aliasRows := []struct {
		name  string
		base  string
		deref int
		want  []string
	}{
		{name: "aliases never", base: childrenScopeAliasesDN, deref: ldap.NeverDerefAliases, want: childrenScopeAliasDNs()},
		{name: "aliases searching", base: childrenScopeAliasesDN, deref: ldap.DerefInSearching, want: peopleChildren},
		{name: "aliases finding", base: childrenScopeAliasesDN, deref: ldap.DerefFindingBaseObj, want: childrenScopeAliasDNs()},
		{name: "aliases always", base: childrenScopeAliasesDN, deref: ldap.DerefAlways, want: peopleChildren},
		{name: "base alias never", base: childrenScopeBaseAlias, deref: ldap.NeverDerefAliases},
		{name: "base alias searching", base: childrenScopeBaseAlias, deref: ldap.DerefInSearching},
		{name: "base alias finding", base: childrenScopeBaseAlias, deref: ldap.DerefFindingBaseObj, want: peopleChildren},
		{name: "base alias always", base: childrenScopeBaseAlias, deref: ldap.DerefAlways, want: peopleChildren},
	}
	for _, test := range aliasRows {
		t.Run("alias matrix/"+test.name, func(t *testing.T) {
			reference := observeChildrenScopeSearch(
				t,
				referenceAddress,
				rawChildrenScopeSearchRequest(
					t,
					test.base,
					ldap.ScopeChildren,
					test.deref,
					0,
					"(objectClass=*)",
					[]string{"1.1"},
				),
			)
			local := observeChildrenScopeSearch(
				t,
				localAddress,
				rawChildrenScopeSearchRequest(
					t,
					test.base,
					ldap.ScopeChildren,
					test.deref,
					0,
					"(objectClass=*)",
					[]string{"1.1"},
				),
			)
			assertChildrenScopeEquivalent(t, reference, local)
			assertChildrenScopeResult(t, reference, ldap.LDAPResultSuccess, "", test.want, nil, nil)
		})
	}

	t.Run("referrals and ManageDsaIT", func(t *testing.T) {
		tests := []struct {
			name        string
			base        string
			filter      string
			manage      bool
			wantCode    uint16
			wantMatched string
			wantEntries []string
			wantRefs    []string
			wantDone    []string
		}{
			{
				name:        "base referral",
				base:        childrenScopeReferralDN,
				filter:      "(objectClass=*)",
				wantCode:    ldap.LDAPResultReferral,
				wantMatched: childrenScopeReferralDN,
				wantDone: []string{
					"ldap://ref.example/dc=remote,dc=example??subordinate",
				},
			},
			{
				name:     "base referral managed",
				base:     childrenScopeReferralDN,
				filter:   "(objectClass=*)",
				manage:   true,
				wantCode: ldap.LDAPResultSuccess,
			},
			{
				name:     "continuation referral",
				base:     childrenScopeSuffix,
				filter:   "(objectClass=referral)",
				wantCode: ldap.LDAPResultSuccess,
				wantRefs: []string{
					"ldap://ref.example/dc=remote,dc=example??sub",
				},
			},
			{
				name:        "continuation referral managed",
				base:        childrenScopeSuffix,
				filter:      "(objectClass=referral)",
				manage:      true,
				wantCode:    ldap.LDAPResultSuccess,
				wantEntries: []string{childrenScopeReferralDN},
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				controls := []*ber.Packet(nil)
				if test.manage {
					controls = []*ber.Packet{rawManageDsaITControl()}
				}
				reference := observeChildrenScopeSearchWithControls(
					t,
					referenceAddress,
					rawChildrenScopeSearchRequest(
						t,
						test.base,
						ldap.ScopeChildren,
						ldap.NeverDerefAliases,
						0,
						test.filter,
						[]string{"1.1"},
					),
					controls,
				)
				local := observeChildrenScopeSearchWithControls(
					t,
					localAddress,
					rawChildrenScopeSearchRequest(
						t,
						test.base,
						ldap.ScopeChildren,
						ldap.NeverDerefAliases,
						0,
						test.filter,
						[]string{"1.1"},
					),
					controls,
				)
				assertChildrenScopeEquivalent(t, reference, local)
				assertChildrenScopeResult(
					t,
					reference,
					test.wantCode,
					test.wantMatched,
					test.wantEntries,
					test.wantRefs,
					test.wantDone,
				)
			})
		}
	})

	t.Run("paged children search", func(t *testing.T) {
		reference := observeChildrenScopePaging(t, referenceAddress)
		local := observeChildrenScopePaging(t, localAddress)
		assertChildrenScopePaging(t, "OpenLDAP 2.6.13", reference)
		assertChildrenScopePaging(t, "ldap-go", local)
		if !reflect.DeepEqual(reference, local) {
			t.Fatalf("paged children mismatch\nOpenLDAP: %#v\nldap-go:  %#v", reference, local)
		}
	})

	t.Run("request size limit", func(t *testing.T) {
		request := func() *ber.Packet {
			return rawChildrenScopeSearchRequest(
				t,
				"ou=limit,"+childrenScopeSuffix,
				ldap.ScopeChildren,
				ldap.NeverDerefAliases,
				2,
				"(objectClass=*)",
				[]string{"1.1"},
			)
		}
		reference := observeChildrenScopeSearch(t, referenceAddress, request())
		local := observeChildrenScopeSearch(t, localAddress, request())
		assertChildrenScopeEquivalent(t, reference, local)
		assertChildrenScopeResult(
			t,
			reference,
			ldap.LDAPResultSizeLimitExceeded,
			"",
			[]string{
				"uid=limit-a,ou=limit," + childrenScopeSuffix,
				"uid=limit-b,ou=limit," + childrenScopeSuffix,
			},
			nil,
			nil,
		)
	})

	t.Run("OpenLDAP 2.6.13 glue omission is reference-only", func(t *testing.T) {
		assertOpenLDAPChildrenScopeGlueOmission(t, tools)
	})
}

func rawChildrenScopeSearchRequest(
	t *testing.T,
	baseDN string,
	scope,
	derefAliases,
	sizeLimit int,
	filter string,
	attributes []string,
) *ber.Packet {
	t.Helper()
	request := rawSyncSearchRequestFor(t, baseDN, scope, derefAliases, filter)
	request.Children[3] = ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(sizeLimit),
		"sizeLimit",
	)
	attributeList := ber.NewSequence("attributes")
	for _, attribute := range attributes {
		attributeList.AppendChild(rawOctetString([]byte(attribute)))
	}
	request.Children[7] = attributeList
	children := append([]*ber.Packet(nil), request.Children...)
	request.Data.Reset()
	request.Children = request.Children[:0]
	for _, child := range children {
		request.AppendChild(child)
	}
	return request
}

func observeChildrenScopeSearch(
	t *testing.T,
	address string,
	request *ber.Packet,
) childrenScopeSearchObservation {
	t.Helper()
	return observeChildrenScopeSearchWithControls(t, address, request, nil)
}

func observeChildrenScopeSearchWithControls(
	t *testing.T,
	address string,
	request *ber.Packet,
	controls []*ber.Packet,
) childrenScopeSearchObservation {
	t.Helper()
	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,"+childrenScopeSuffix,
		"secret",
	)
	defer connection.Close()
	writeRawLDAPRequest(t, connection, 2, request, controls...)
	return readChildrenScopeSearchResponse(t, connection)
}

func readChildrenScopeSearchResponse(
	t *testing.T,
	connection net.Conn,
) childrenScopeSearchObservation {
	t.Helper()
	var observation childrenScopeSearchObservation
	for {
		packet, err := ber.ReadPacket(connection)
		if err != nil {
			t.Fatalf("read children-scope search response: %v", err)
		}
		if len(packet.Children) < 2 {
			t.Fatalf("malformed children-scope response: %#v", packet)
		}
		operation := packet.Children[1]
		switch uint64(operation.Tag) {
		case ldapwire.ApplicationSearchResultEntry:
			observation.entries = append(
				observation.entries,
				decodeChildrenScopeEntry(t, operation),
			)
		case ldapwire.ApplicationSearchResultReference:
			for _, child := range operation.Children {
				observation.references = append(
					observation.references,
					string(child.Data.Bytes()),
				)
			}
		case ldapwire.ApplicationSearchResultDone:
			observation.resultCode = rawLDAPResultCode(t, operation)
			if len(operation.Children) > 1 {
				observation.matchedDN = string(operation.Children[1].Data.Bytes())
			}
			for _, child := range operation.Children[3:] {
				if child.ClassType != ber.ClassContext || child.Tag != 3 {
					continue
				}
				for _, referral := range child.Children {
					observation.referrals = append(
						observation.referrals,
						string(referral.Data.Bytes()),
					)
				}
			}
			observation.controls = rawLDAPResponseControls(packet)
			slices.SortFunc(observation.entries, func(a, b childrenScopeEntryObservation) int {
				return strings.Compare(a.dn, b.dn)
			})
			slices.Sort(observation.references)
			slices.Sort(observation.referrals)
			return observation
		default:
			t.Fatalf("unexpected children-scope response tag %d", operation.Tag)
		}
	}
}

func decodeChildrenScopeEntry(
	t *testing.T,
	operation *ber.Packet,
) childrenScopeEntryObservation {
	t.Helper()
	if len(operation.Children) != 2 {
		t.Fatalf("malformed children-scope entry: %#v", operation)
	}
	entry := childrenScopeEntryObservation{
		dn:         string(operation.Children[0].Data.Bytes()),
		attributes: make(map[string][]string),
	}
	for _, attribute := range operation.Children[1].Children {
		if len(attribute.Children) != 2 {
			t.Fatalf("malformed children-scope attribute: %#v", attribute)
		}
		description := strings.ToLower(string(attribute.Children[0].Data.Bytes()))
		for _, value := range attribute.Children[1].Children {
			entry.attributes[description] = append(
				entry.attributes[description],
				string(value.Data.Bytes()),
			)
		}
		slices.Sort(entry.attributes[description])
	}
	return entry
}

func assertChildrenScopeEquivalent(
	t *testing.T,
	reference,
	local childrenScopeSearchObservation,
) {
	t.Helper()
	referenceComparable := childrenScopeComparableObservation(reference)
	localComparable := childrenScopeComparableObservation(local)
	if referenceComparable.resultCode != localComparable.resultCode ||
		referenceComparable.matchedDN != localComparable.matchedDN ||
		!slices.Equal(referenceComparable.entries, localComparable.entries) ||
		!slices.Equal(referenceComparable.references, localComparable.references) ||
		!slices.Equal(referenceComparable.referrals, localComparable.referrals) {
		t.Fatalf(
			"children-scope mismatch\nOpenLDAP: %#v\nldap-go:  %#v",
			referenceComparable,
			localComparable,
		)
	}
}

func childrenScopeComparableObservation(
	observation childrenScopeSearchObservation,
) struct {
	resultCode int64
	matchedDN  string
	entries    []string
	references []string
	referrals  []string
} {
	return struct {
		resultCode int64
		matchedDN  string
		entries    []string
		references []string
		referrals  []string
	}{
		resultCode: observation.resultCode,
		matchedDN:  observation.matchedDN,
		entries:    childrenScopeEntryDNs(observation),
		references: observation.references,
		referrals:  observation.referrals,
	}
}

func assertChildrenScopeResult(
	t *testing.T,
	observation childrenScopeSearchObservation,
	wantCode uint16,
	wantMatched string,
	wantEntries,
	wantReferences,
	wantReferrals []string,
) {
	t.Helper()
	slices.Sort(wantEntries)
	slices.Sort(wantReferences)
	slices.Sort(wantReferrals)
	gotEntries := childrenScopeEntryDNs(observation)
	if observation.resultCode != int64(wantCode) ||
		observation.matchedDN != wantMatched ||
		!slices.Equal(gotEntries, wantEntries) ||
		!slices.Equal(observation.references, wantReferences) ||
		!slices.Equal(observation.referrals, wantReferrals) {
		t.Fatalf(
			"children-scope result = code %d matched %q entries %q references %q referrals %q; want code %d matched %q entries %q references %q referrals %q",
			observation.resultCode,
			observation.matchedDN,
			gotEntries,
			observation.references,
			observation.referrals,
			wantCode,
			wantMatched,
			wantEntries,
			wantReferences,
			wantReferrals,
		)
	}
}

func childrenScopeEntryDNs(
	observation childrenScopeSearchObservation,
) []string {
	result := make([]string, len(observation.entries))
	for index, entry := range observation.entries {
		result[index] = entry.dn
	}
	return result
}

func observeChildrenScopePaging(
	t *testing.T,
	address string,
) childrenScopePagingObservation {
	t.Helper()
	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,"+childrenScopeSuffix,
		"secret",
	)
	defer connection.Close()

	var result childrenScopePagingObservation
	var cookie []byte
	for page := 0; page < 10; page++ {
		control := encodeRawLDAPControl(ldapwire.Control{
			OID: pagedResultsControlOID,
			Value: ldapwire.EncodePagedResultsValue(
				2,
				cookie,
			),
			HasValue: true,
		})
		writeRawLDAPRequest(
			t,
			connection,
			int64(page+2),
			rawChildrenScopeSearchRequest(
				t,
				childrenScopePeopleDN,
				ldap.ScopeChildren,
				ldap.NeverDerefAliases,
				0,
				"(objectClass=*)",
				[]string{"1.1"},
			),
			control,
		)
		observation := readChildrenScopeSearchResponse(t, connection)
		result.resultCodes = append(result.resultCodes, observation.resultCode)
		result.pageSizes = append(result.pageSizes, len(observation.entries))
		for _, entry := range observation.entries {
			result.entries = append(result.entries, entry.dn)
		}
		value, ok := observation.controls[pagedResultsControlOID]
		if !ok {
			t.Fatalf("page %d omitted paged-results response control", page+1)
		}
		_, nextCookie, err := ldapwire.DecodePagedResultsValue(value)
		if err != nil {
			t.Fatalf("decode page %d response control: %v", page+1, err)
		}
		result.cookieExists = append(result.cookieExists, len(nextCookie) > 0)
		if len(nextCookie) == 0 {
			slices.Sort(result.entries)
			return result
		}
		cookie = nextCookie
	}
	t.Fatal("paged children search did not terminate after 10 pages")
	return childrenScopePagingObservation{}
}

func assertChildrenScopePaging(
	t *testing.T,
	name string,
	observation childrenScopePagingObservation,
) {
	t.Helper()
	wantCodes := []int64{0, 0, 0, 0}
	wantPageSizes := []int{2, 2, 2, 2}
	wantCookies := []bool{true, true, true, false}
	wantEntries := childrenScopePeopleChildrenDNs()
	slices.Sort(wantEntries)
	if !reflect.DeepEqual(observation.resultCodes, wantCodes) ||
		!reflect.DeepEqual(observation.pageSizes, wantPageSizes) ||
		!reflect.DeepEqual(observation.cookieExists, wantCookies) ||
		!reflect.DeepEqual(observation.entries, wantEntries) {
		t.Fatalf(
			"%s paging = codes %v page sizes %v cookies %v entries %q; want %v, %v, %v, %q",
			name,
			observation.resultCodes,
			observation.pageSizes,
			observation.cookieExists,
			observation.entries,
			wantCodes,
			wantPageSizes,
			wantCookies,
			wantEntries,
		)
	}
}

func seedChildrenScopeDifferentialDirectory(
	t *testing.T,
	store storage.Store,
) {
	t.Helper()
	entries := childrenScopeDifferentialEntries()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{childrenScopeSuffix})
	}); err != nil {
		t.Fatalf("seed children-scope differential fixture: %v", err)
	}
}

func childrenScopeDifferentialEntries() []directory.Entry {
	entries := []directory.Entry{
		{
			DN: childrenScopeSuffix,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "domain")},
				{Description: "dc", Values: stringValues("example")},
			},
		},
		childrenScopeOU(childrenScopePeopleDN, "people"),
		childrenScopePerson("uid=carol,"+childrenScopePeopleDN, "carol", "Carol"),
		childrenScopePerson("uid=alice,"+childrenScopePeopleDN, "alice", "Alice"),
		childrenScopePerson("uid=bob,"+childrenScopePeopleDN, "bob", "Bob"),
		childrenScopePerson("uid=dave,"+childrenScopePeopleDN, "dave", "Dave"),
		childrenScopePerson("uid=erin,"+childrenScopePeopleDN, "erin", "Erin"),
		childrenScopePerson("uid=frank,"+childrenScopePeopleDN, "frank", "Frank"),
		childrenScopeOU("ou=team,"+childrenScopePeopleDN, "team"),
		childrenScopePerson("uid=grace,ou=team,"+childrenScopePeopleDN, "grace", "Grace"),
		childrenScopeOU(childrenScopeAliasesDN, "aliases"),
		aliasTestEntry(
			"cn=aliceAlias,"+childrenScopeAliasesDN,
			"cn",
			"aliceAlias",
			"uid=alice,"+childrenScopePeopleDN,
			"",
		),
		aliasTestEntry(
			"cn=peopleAlias,"+childrenScopeAliasesDN,
			"cn",
			"peopleAlias",
			childrenScopePeopleDN,
			"",
		),
		aliasTestEntry(
			childrenScopeBaseAlias,
			"cn",
			"baseAlias",
			childrenScopePeopleDN,
			"",
		),
		{
			DN: childrenScopeReferralDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "referral", "extensibleObject")},
				{Description: "ou", Values: stringValues("ref")},
				{Description: "ref", Values: stringValues("ldap://ref.example/dc=remote,dc=example")},
			},
		},
		childrenScopeOU("ou=limit,"+childrenScopeSuffix, "limit"),
		childrenScopePerson("uid=limit-a,ou=limit,"+childrenScopeSuffix, "limit-a", "Limit A"),
		childrenScopePerson("uid=limit-b,ou=limit,"+childrenScopeSuffix, "limit-b", "Limit B"),
		childrenScopePerson("uid=limit-c,ou=limit,"+childrenScopeSuffix, "limit-c", "Limit C"),
	}
	return entries
}

func childrenScopeOU(dn, value string) directory.Entry {
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("top", "organizationalUnit")},
			{Description: "ou", Values: stringValues(value)},
		},
	}
}

func childrenScopePerson(dn, uid, commonName string) directory.Entry {
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("top", "person", "organizationalPerson", "inetOrgPerson")},
			{Description: "uid", Values: stringValues(uid)},
			{Description: "cn", Values: stringValues(commonName)},
			{Description: "sn", Values: stringValues(commonName)},
		},
	}
}

func childrenScopePeopleChildrenDNs() []string {
	return []string{
		"ou=team," + childrenScopePeopleDN,
		"uid=alice," + childrenScopePeopleDN,
		"uid=bob," + childrenScopePeopleDN,
		"uid=carol," + childrenScopePeopleDN,
		"uid=dave," + childrenScopePeopleDN,
		"uid=erin," + childrenScopePeopleDN,
		"uid=frank," + childrenScopePeopleDN,
		"uid=grace,ou=team," + childrenScopePeopleDN,
	}
}

func childrenScopeAliasDNs() []string {
	return []string{
		"cn=aliceAlias," + childrenScopeAliasesDN,
		"cn=peopleAlias," + childrenScopeAliasesDN,
	}
}

func assertOpenLDAPChildrenScopeGlueOmission(
	t *testing.T,
	tools openLDAPReferenceTools,
) {
	t.Helper()
	subordinateDirectory := t.TempDir()
	globalConfig := fmt.Sprintf(`
database mdb
maxsize 1073741824
suffix "ou=branch,dc=example,dc=com"
rootdn "cn=admin,ou=branch,dc=example,dc=com"
rootpw secret
directory %s
index objectClass eq
subordinate advertise
access to * by * read
`, filepath.Clean(subordinateDirectory))
	wrapper := filepath.Join(t.TempDir(), "slapadd-parent")
	if err := os.WriteFile(
		wrapper,
		[]byte("#!/bin/sh\nexec \"$OPENLDAP_REAL_SLAPADD\" -b \"dc=example,dc=com\" \"$@\"\n"),
		0o700,
	); err != nil {
		t.Fatalf("write OpenLDAP parent slapadd wrapper: %v", err)
	}
	t.Setenv("OPENLDAP_REAL_SLAPADD", tools.slapadd)
	glueTools := tools
	glueTools.slapadd = wrapper
	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		glueTools,
		nil,
		globalConfig,
		"access to * by * read",
		"",
	)
	defer stop()
	seedOpenLDAPChildrenScopeSubordinate(t, uri)
	address := strings.TrimPrefix(uri, "ldap://")

	subtree := observeChildrenScopeSearch(
		t,
		address,
		rawChildrenScopeSearchRequest(
			t,
			childrenScopeSuffix,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			"(objectClass=*)",
			[]string{"1.1"},
		),
	)
	assertChildrenScopeResult(
		t,
		subtree,
		ldap.LDAPResultSuccess,
		"",
		[]string{
			childrenScopeSuffix,
			childrenScopePeopleDN,
			"uid=alice," + childrenScopePeopleDN,
			"uid=bob," + childrenScopePeopleDN,
			"uid=carol," + childrenScopePeopleDN,
			"ou=branch," + childrenScopeSuffix,
			"uid=branch-a,ou=branch," + childrenScopeSuffix,
			"ou=deep,ou=branch," + childrenScopeSuffix,
			"uid=branch-b,ou=deep,ou=branch," + childrenScopeSuffix,
		},
		nil,
		nil,
	)

	children := observeChildrenScopeSearch(
		t,
		address,
		rawChildrenScopeSearchRequest(
			t,
			childrenScopeSuffix,
			ldap.ScopeChildren,
			ldap.NeverDerefAliases,
			0,
			"(objectClass=*)",
			[]string{"1.1"},
		),
	)
	assertChildrenScopeResult(
		t,
		children,
		ldap.LDAPResultSuccess,
		"",
		[]string{
			childrenScopePeopleDN,
			"uid=alice," + childrenScopePeopleDN,
			"uid=bob," + childrenScopePeopleDN,
			"uid=carol," + childrenScopePeopleDN,
		},
		nil,
		nil,
	)
	t.Log("OpenLDAP 2.6.13 scope=3 omits the glued subordinate database; ldap-go is intentionally not required to copy this defect")
}

func seedOpenLDAPChildrenScopeSubordinate(t *testing.T, uri string) {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial OpenLDAP glue fixture: %v", err)
	}
	defer client.Close()
	if err := client.Bind(
		"cn=admin,ou=branch,"+childrenScopeSuffix,
		"secret",
	); err != nil {
		t.Fatalf("bind OpenLDAP subordinate root: %v", err)
	}
	entries := []struct {
		dn         string
		attributes map[string][]string
	}{
		{
			dn: "ou=branch," + childrenScopeSuffix,
			attributes: map[string][]string{
				"objectClass": {"top", "organizationalUnit"},
				"ou":          {"branch"},
			},
		},
		{
			dn: "uid=branch-a,ou=branch," + childrenScopeSuffix,
			attributes: map[string][]string{
				"objectClass": {"top", "inetOrgPerson"},
				"uid":         {"branch-a"},
				"cn":          {"Branch A"},
				"sn":          {"Branch A"},
			},
		},
		{
			dn: "ou=deep,ou=branch," + childrenScopeSuffix,
			attributes: map[string][]string{
				"objectClass": {"top", "organizationalUnit"},
				"ou":          {"deep"},
			},
		},
		{
			dn: "uid=branch-b,ou=deep,ou=branch," + childrenScopeSuffix,
			attributes: map[string][]string{
				"objectClass": {"top", "inetOrgPerson"},
				"uid":         {"branch-b"},
				"cn":          {"Branch B"},
				"sn":          {"Branch B"},
			},
		},
	}
	for _, entry := range entries {
		request := ldap.NewAddRequest(entry.dn, nil)
		for description, values := range entry.attributes {
			request.Attribute(description, values)
		}
		if err := client.Add(request); err != nil {
			t.Fatalf("add OpenLDAP subordinate entry %q: %v", entry.dn, err)
		}
	}
}

const childrenScopeOpenLDAPExtraData = `
dn: uid=dave,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: dave
cn: Dave
sn: Dave

dn: uid=erin,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: erin
cn: Erin
sn: Erin

dn: uid=frank,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: frank
cn: Frank
sn: Frank

dn: ou=team,ou=people,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: team

dn: uid=grace,ou=team,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: grace
cn: Grace
sn: Grace

dn: ou=aliases,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: aliases

dn: cn=aliceAlias,ou=aliases,dc=example,dc=com
objectClass: top
objectClass: alias
objectClass: extensibleObject
cn: aliceAlias
aliasedObjectName: uid=alice,ou=people,dc=example,dc=com

dn: cn=peopleAlias,ou=aliases,dc=example,dc=com
objectClass: top
objectClass: alias
objectClass: extensibleObject
cn: peopleAlias
aliasedObjectName: ou=people,dc=example,dc=com

dn: cn=baseAlias,dc=example,dc=com
objectClass: top
objectClass: alias
objectClass: extensibleObject
cn: baseAlias
aliasedObjectName: ou=people,dc=example,dc=com

dn: ou=ref,dc=example,dc=com
objectClass: top
objectClass: referral
objectClass: extensibleObject
ou: ref
ref: ldap://ref.example/dc=remote,dc=example

dn: ou=limit,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: limit

dn: uid=limit-a,ou=limit,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: limit-a
cn: Limit A
sn: Limit A

dn: uid=limit-b,ou=limit,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: limit-b
cn: Limit B
sn: Limit B

dn: uid=limit-c,ou=limit,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: limit-c
cn: Limit C
sn: Limit C
`
