package server

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	sortVLVExactOID = "1.3.6.1.4.1.99999.941.1"
	sortVLVFoldOID  = "1.3.6.1.4.1.99999.941.2"
	sortVLVValueOID = "1.3.6.1.4.1.99999.941.3"

	sortVLVBaseDN  = "sortVLVExactName=Group+sortVLVFoldName=People,dc=example,dc=com"
	sortVLVUpperDN = "sortVLVExactName=Alice+sortVLVFoldName=Team," +
		sortVLVBaseDN
	sortVLVLowerDN = "sortVLVExactName=alice+sortVLVFoldName=Team," +
		sortVLVBaseDN
	sortVLVCarolDN = "sortVLVExactName=Carol+sortVLVFoldName=Team," +
		sortVLVBaseDN
	sortVLVBobDN = "sortVLVExactName=Bob+sortVLVFoldName=Team," +
		sortVLVBaseDN
)

const sortVLVConfigLDIF = `dn: cn=config
objectClass: olcGlobal
cn: config

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: cn={9}sortvlvdn,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}sortvlvdn
olcAttributeTypes: ( 1.3.6.1.4.1.99999.941.1 NAME ( 'sortVLVExactName' 'sortVLVExactAlias' ) EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.99999.941.2 NAME ( 'sortVLVFoldName' 'sortVLVFoldAlias' ) EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.99999.941.3 NAME ( 'sortVLVValue' 'sortVLVAlias' ) EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.99999.941.4 NAME 'sortVLVIdentity' SUP top AUXILIARY MAY ( sortVLVExactName $ sortVLVFoldName $ sortVLVValue ) )

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcRootDN: cn=config
olcRootPW: config-secret

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: dc=example,dc=com
olcRootDN: cn=admin,dc=example,dc=com
olcRootPW: admin-secret
olcAccess: {0}to * by * read

dn: olcOverlay={0}sssvlv,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
olcOverlay: {0}sssvlv

`

const sortVLVContentLDIF = `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: sortVLVExactName=Group+sortVLVFoldName=People,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
objectClass: sortVLVIdentity
ou: People
sortVLVExactName: Group
sortVLVFoldName: People

dn: sortVLVExactName=Alice+sortVLVFoldName=Team,sortVLVExactName=Group+sortVLVFoldName=People,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
objectClass: sortVLVIdentity
uid: sort-upper
cn: Upper
sn: Upper
sortVLVExactName: Alice
sortVLVFoldName: Team
sortVLVValue: Same

dn: sortVLVExactName=alice+sortVLVFoldName=Team,sortVLVExactName=Group+sortVLVFoldName=People,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
objectClass: sortVLVIdentity
uid: sort-lower
cn: Lower
sn: Lower
sortVLVExactName: alice
sortVLVFoldName: Team
sortVLVValue: Same

dn: sortVLVExactName=Carol+sortVLVFoldName=Team,sortVLVExactName=Group+sortVLVFoldName=People,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
objectClass: sortVLVIdentity
uid: sort-carol
cn: Carol
sn: Carol
sortVLVExactName: Carol
sortVLVFoldName: Team
sortVLVValue: Alpha

dn: sortVLVExactName=Bob+sortVLVFoldName=Team,sortVLVExactName=Group+sortVLVFoldName=People,dc=example,dc=com
objectClass: top
objectClass: inetOrgPerson
objectClass: sortVLVIdentity
uid: sort-bob
cn: Bob
sn: Bob
sortVLVExactName: Bob
sortVLVFoldName: Team

`

func TestDNIdentityServerSideSortTieBreak(t *testing.T) {
	registry := newSortVLVDNIdentityRegistry(t)
	context := &serverSideSortContext{
		result: ldapwire.ResultSuccess,
		keys: []resolvedSortKey{{
			attribute:    "sortVLVAlias",
			orderingRule: "caseignoreorderingmatch",
		}},
	}
	candidates := []searchCandidate{
		newSortVLVCandidate(sortVLVLowerDN, "same", true),
		newSortVLVCandidate(sortVLVBobDN, "", false),
		newSortVLVCandidate(sortVLVUpperDN, "SAME", true),
		newSortVLVCandidate(sortVLVCarolDN, "alpha", true),
	}
	if err := sortSearchCandidates(registry, context, candidates); err != nil {
		t.Fatalf("sortSearchCandidates(): %v", err)
	}
	want := sortVLVExpectedUIDs(t, registry)
	if got := sortVLVCandidateUIDs(candidates); !equalSortVLVStrings(got, want) {
		t.Fatalf("ascending candidate order = %v, want %v", got, want)
	}
	if candidates[1].identityKey == candidates[2].identityKey {
		t.Fatal("caseExact sibling DNs collapsed to one sort identity")
	}
	for _, candidate := range candidates {
		if candidate.cursorKey == "" || candidate.identityKey == "" {
			t.Fatalf("candidate cursor identity is absent: %#v", candidate)
		}
		if strings.Contains(candidate.dn, "sortVLVExactAlias") ||
			strings.Contains(candidate.dn, sortVLVExactOID) {
			t.Fatalf("candidate DN was not canonicalized: %q", candidate.dn)
		}
	}

	reverse := append([]searchCandidate(nil), candidates...)
	context.keys[0].reverse = true
	if err := sortSearchCandidates(registry, context, reverse); err != nil {
		t.Fatalf("reverse sortSearchCandidates(): %v", err)
	}
	wantReverse := append([]string{"sort-bob"}, want[1:3]...)
	wantReverse = append(wantReverse, "sort-carol")
	if got := sortVLVCandidateUIDs(reverse); !equalSortVLVStrings(got, wantReverse) {
		t.Fatalf("reverse candidate order = %v, want %v", got, wantReverse)
	}
}

func TestDNIdentityServerSideSortAndVLV(t *testing.T) {
	for _, backend := range []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{name: "memory", open: func(*testing.T) storage.Store { return storage.NewMemory() }},
		{name: "bolt", open: func(t *testing.T) storage.Store {
			store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	} {
		t.Run(backend.name, func(t *testing.T) {
			testDNIdentityServerSideSortAndVLV(t, backend.open(t))
		})
	}
}

func testDNIdentityServerSideSortAndVLV(t *testing.T, store storage.Store) {
	t.Helper()
	t.Cleanup(func() { _ = store.Close() })
	importSortVLVDNIdentityFixture(t, store)
	registry := newSortVLVDNIdentityRegistry(t)

	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	client := bindSortVLVClient(t, address, "cn=admin,dc=example,dc=com", "admin-secret")

	want := sortVLVExpectedUIDs(t, registry)
	for run := 0; run < 3; run++ {
		result, err := client.Search(sortVLVSearchRequest(
			sortVLVBaseDN,
			newSortControl(ldap.SortKey{
				AttributeType: "sortVLVAlias",
				MatchingRule:  "caseIgnoreOrderingMatch",
			}),
		))
		if err != nil {
			t.Fatalf("stable sorted Search(run=%d): %v", run, err)
		}
		assertSortVLVUIDs(t, result, want)
	}

	paged, err := client.SearchWithPaging(sortVLVSearchRequest(
		sortVLVEquivalentBaseDN(),
		newSortControl(ldap.SortKey{
			AttributeType: sortVLVValueOID,
			MatchingRule:  "caseIgnoreOrderingMatch",
		}),
	), 2)
	if err != nil {
		t.Fatalf("schema-aware sorted paging: %v", err)
	}
	assertSortVLVUIDs(t, paged, want)

	reverse, err := client.Search(sortVLVSearchRequest(
		sortVLVEquivalentBaseDN(),
		newSortControl(ldap.SortKey{
			AttributeType: "sortVLVValue",
			MatchingRule:  "caseIgnoreOrderingMatch",
			Reverse:       true,
		}),
	))
	if err != nil {
		t.Fatalf("reverse sorted Search(): %v", err)
	}
	wantReverse := append([]string{"sort-bob"}, want[1:3]...)
	wantReverse = append(wantReverse, "sort-carol")
	assertSortVLVUIDs(t, reverse, wantReverse)

	combined := sortVLVSearchRequest(
		sortVLVEquivalentBaseDN(),
		newSortControl(ldap.SortKey{
			AttributeType: "sortVLVValue",
			MatchingRule:  "caseIgnoreOrderingMatch",
		}),
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			ByOffset: true,
			Offset:   1,
		}),
		ldap.NewControlPaging(1),
	)
	_, err = client.Search(combined)
	assertLDAPResultCode(t, err, ldap.LDAPResultUnwillingToPerform)

	upperOffset := sortVLVUIDOffset(t, want, "sort-upper")
	lowerOffset := sortVLVUIDOffset(t, want, "sort-lower")
	upperContext := startSortVLVContext(t, client, sortVLVBaseDN, "sortVLVValue", upperOffset)
	lowerContext := startSortVLVContext(t, client, sortVLVBaseDN, "sortVLVValue", lowerOffset)
	replaceSortVLVDNIdentities(t, store, registry)

	upper := continueSortVLVContext(
		t,
		client,
		sortVLVEquivalentBaseDN(),
		sortVLVValueOID,
		upperOffset,
		upperContext,
	)
	if len(upper.Entries) != 0 {
		t.Fatalf("deleted caseExact identity resumed as %v", sortVLVResultUIDs(upper))
	}
	if response := decodeVirtualListViewResponse(t, upper); response.ContentCount != 4 {
		t.Fatalf("caseExact continuation content count = %d, want 4", response.ContentCount)
	}

	lower := continueSortVLVContext(
		t,
		client,
		sortVLVEquivalentBaseDN(),
		"sortVLVAlias",
		lowerOffset,
		lowerContext,
	)
	assertSortVLVUIDs(t, lower, []string{"sort-lower-replaced"})
	if response := decodeVirtualListViewResponse(t, lower); response.ContentCount != 4 {
		t.Fatalf("equivalent continuation content count = %d, want 4", response.ContentCount)
	}

	stale := startSortVLVContext(t, client, sortVLVEquivalentBaseDN(), sortVLVValueOID, 1)
	configClient := bindSortVLVClient(t, address, "cn=config", "config-secret")
	modify := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	modify.Replace("olcReadOnly", []string{"TRUE"})
	if err := configClient.Modify(modify); err != nil {
		t.Fatalf("enable olcReadOnly: %v", err)
	}
	_, err = client.Search(sortVLVRequestWithContext(
		sortVLVEquivalentBaseDN(),
		"sortVLVAlias",
		1,
		stale,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultVirtualListViewErrorOrControlError)
}

func newSortVLVCandidate(dn, value string, present bool) searchCandidate {
	entry := directory.Entry{Attributes: []directory.Attribute{{
		Description: "uid",
		Values:      stringValues(sortVLVUIDForDN(dn)),
	}}}
	if present {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "sortVLVValue",
			Values:      stringValues(value),
		})
	}
	return searchCandidate{dn: dn, selected: entry, readable: entry, route: 0}
}

func newSortVLVDNIdentityRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, description := range []string{
		"( " + sortVLVExactOID + " NAME ( 'sortVLVExactName' 'sortVLVExactAlias' ) " +
			"EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch " +
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
		"( " + sortVLVFoldOID + " NAME ( 'sortVLVFoldName' 'sortVLVFoldAlias' ) " +
			"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch " +
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
		"( " + sortVLVValueOID + " NAME ( 'sortVLVValue' 'sortVLVAlias' ) " +
			"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch " +
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
	} {
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(): %v", err)
		}
	}
	return registry
}

func importSortVLVDNIdentityFixture(t *testing.T, store storage.Store) {
	t.Helper()
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(sortVLVConfigLDIF),
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
		strings.NewReader(sortVLVContentLDIF),
		migration.ImportOptions{Database: "1", Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(content): %v", err)
	}
}

func bindSortVLVClient(t *testing.T, address, dn, password string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind(dn, password); err != nil {
		t.Fatalf("Bind(%q): %v", dn, err)
	}
	return client
}

func sortVLVSearchRequest(base string, controls ...ldap.Control) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		base,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=sort-*)",
		[]string{"uid", "sortVLVValue"},
		controls,
	)
}

func sortVLVEquivalentBaseDN() string {
	return sortVLVFoldOID + `=\20PEOPLE\20+sortVLVExactAlias=Group,DC=EXAMPLE,DC=COM`
}

func startSortVLVContext(
	t *testing.T,
	client *ldap.Conn,
	base,
	attribute string,
	offset int,
) []byte {
	t.Helper()
	result, err := client.Search(sortVLVSearchRequest(
		base,
		newSortControl(ldap.SortKey{
			AttributeType: attribute,
			MatchingRule:  "caseIgnoreOrderingMatch",
		}),
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			ByOffset:     true,
			Offset:       int64(offset),
			ContentCount: 4,
		}),
	))
	if err != nil {
		t.Fatalf("start VLV context(offset=%d): %v", offset, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("initial VLV entries(offset=%d) = %d, want 1", offset, len(result.Entries))
	}
	return decodeVirtualListViewResponse(t, result).ContextID
}

func continueSortVLVContext(
	t *testing.T,
	client *ldap.Conn,
	base,
	attribute string,
	offset int,
	contextID []byte,
) *ldap.SearchResult {
	t.Helper()
	result, err := client.Search(sortVLVRequestWithContext(
		base,
		attribute,
		offset,
		contextID,
	))
	if err != nil {
		t.Fatalf("continue VLV context(offset=%d): %v", offset, err)
	}
	return result
}

func sortVLVRequestWithContext(
	base,
	attribute string,
	offset int,
	contextID []byte,
) *ldap.SearchRequest {
	return sortVLVSearchRequest(
		base,
		newSortControl(ldap.SortKey{
			AttributeType: attribute,
			MatchingRule:  "caseIgnoreOrderingMatch",
		}),
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			ByOffset:     true,
			Offset:       int64(offset),
			ContentCount: 4,
			ContextID:    contextID,
			HasContextID: true,
		}),
	)
}

func replaceSortVLVDNIdentities(
	t *testing.T,
	store storage.Store,
	registry *schema.Registry,
) {
	t.Helper()
	replacementDN := sortVLVFoldOID + `=\20TEAM\20+sortVLVExactAlias=alice,` +
		sortVLVEquivalentBaseDN()
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		tx := storage.WriterInPartitionWithNormalizer(
			writer,
			configuredDatabasePartition("{1}mdb"),
			registry,
		)
		for _, raw := range []string{sortVLVUpperDN, sortVLVLowerDN} {
			dn, err := registry.NormalizeDN(raw)
			if err != nil {
				return err
			}
			if err := tx.Delete(dn); err != nil {
				return err
			}
		}
		return tx.Put(directory.Entry{
			DN: replacementDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "inetOrgPerson", "sortVLVIdentity")},
				{Description: "uid", Values: stringValues("sort-lower-replaced")},
				{Description: "cn", Values: stringValues("Lower replacement")},
				{Description: "sn", Values: stringValues("Lower")},
				{Description: "sortVLVExactName", Values: stringValues("alice")},
				{Description: "sortVLVFoldName", Values: stringValues("TEAM")},
				{Description: "sortVLVValue", Values: stringValues("Same")},
			},
		}, false)
	})
	if err != nil {
		t.Fatalf("replace VLV identities: %v", err)
	}
}

func sortVLVExpectedUIDs(t *testing.T, registry *schema.Registry) []string {
	t.Helper()
	type ordered struct {
		uid string
		key string
	}
	tied := []ordered{
		{uid: "sort-upper", key: sortVLVReaderOrderKey(t, registry, sortVLVUpperDN)},
		{uid: "sort-lower", key: sortVLVReaderOrderKey(t, registry, sortVLVLowerDN)},
	}
	sort.Slice(tied, func(left, right int) bool { return tied[left].key < tied[right].key })
	return []string{"sort-carol", tied[0].uid, tied[1].uid, "sort-bob"}
}

func sortVLVReaderOrderKey(
	t *testing.T,
	registry *schema.Registry,
	raw string,
) string {
	t.Helper()
	dn, err := registry.NormalizeDN(raw)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", raw, err)
	}
	legacy, err := directory.ParseDN(dn.String())
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", dn.String(), err)
	}
	return legacy.Key() + "\x00" + dn.Key()
}

func sortVLVUIDOffset(t *testing.T, values []string, uid string) int {
	t.Helper()
	for index, value := range values {
		if value == uid {
			return index + 1
		}
	}
	t.Fatalf("UID %q is absent from %v", uid, values)
	return 0
}

func sortVLVUIDForDN(dn string) string {
	switch dn {
	case sortVLVUpperDN:
		return "sort-upper"
	case sortVLVLowerDN:
		return "sort-lower"
	case sortVLVCarolDN:
		return "sort-carol"
	case sortVLVBobDN:
		return "sort-bob"
	default:
		return ""
	}
}

func sortVLVCandidateUIDs(candidates []searchCandidate) []string {
	values := make([]string, len(candidates))
	for index := range candidates {
		uid := candidates[index].selected.Values("uid")
		if len(uid) != 0 {
			values[index] = string(uid[0])
		}
	}
	return values
}

func sortVLVResultUIDs(result *ldap.SearchResult) []string {
	values := make([]string, len(result.Entries))
	for index := range result.Entries {
		values[index] = result.Entries[index].GetAttributeValue("uid")
	}
	return values
}

func assertSortVLVUIDs(
	t *testing.T,
	result *ldap.SearchResult,
	want []string,
) {
	t.Helper()
	got := sortVLVResultUIDs(result)
	if !equalSortVLVStrings(got, want) {
		t.Fatalf("result UIDs = %v, want %v", got, want)
	}
}

func equalSortVLVStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
