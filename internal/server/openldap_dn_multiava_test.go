package server

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	dnMultiAVAExactOID = "1.3.6.1.4.1.99999.916.1"
	dnMultiAVAFoldOID  = "1.3.6.1.4.1.99999.916.2"
)

const dnMultiAVASchema = `attributetype ( 1.3.6.1.4.1.99999.916.1 NAME ( 'exactName' 'exactAlias' ) EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 1.3.6.1.4.1.99999.916.2 NAME ( 'foldName' 'foldAlias' ) EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
objectclass ( 1.3.6.1.4.1.99999.916.3 NAME 'dnMultiAVAEntry' SUP top STRUCTURAL MUST cn MAY ( exactName $ foldName ) )`

const dnMultiAVAConfigLDIF = `dn: cn=config
objectClass: olcGlobal
cn: config

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: cn={9}dnmultiava,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}dnmultiava
olcAttributeTypes: ( 1.3.6.1.4.1.99999.916.1 NAME ( 'exactName' 'exactAlias' ) EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
olcAttributeTypes: ( 1.3.6.1.4.1.99999.916.2 NAME ( 'foldName' 'foldAlias' ) EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
olcObjectClasses: ( 1.3.6.1.4.1.99999.916.3 NAME 'dnMultiAVAEntry' SUP top STRUCTURAL MUST cn MAY ( exactName $ foldName ) )

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
olcRootPW: secret

`

const dnMultiAVAContentLDIF = `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: exactName=Alice+foldName=Engineering,dc=example,dc=com
objectClass: top
objectClass: dnMultiAVAEntry
cn: Exact Upper
exactName: Alice
foldName: Engineering

dn: exactName=alice+foldName=engineering,dc=example,dc=com
objectClass: top
objectClass: dnMultiAVAEntry
cn: Exact Lower
exactName: alice
foldName: engineering

dn: exactName=Bob+foldName=Operations,dc=example,dc=com
objectClass: top
objectClass: dnMultiAVAEntry
cn: Exact Bob
exactName: Bob
foldName: Operations
`

func TestDNMultiAVASchemaAwareIdentity(t *testing.T) {
	registry := newDNMultiAVARegistry(t)

	for _, test := range []struct {
		name string
		dn   string
	}{
		{
			name: "primary name and alias",
			dn:   "exactName=Alice+exactAlias=Other,dc=example,dc=com",
		},
		{
			name: "alias and numeric OID",
			dn:   "exactAlias=Alice+" + dnMultiAVAExactOID + "=Other,dc=example,dc=com",
		},
		{
			name: "repeated primary name",
			dn:   "exactName=Alice+exactName=Other,dc=example,dc=com",
		},
		{
			name: "different options on the same type",
			dn: "exactName;lang-en=Alice+exactAlias;lang-fr=Other," +
				"dc=example,dc=com",
		},
	} {
		t.Run("reject duplicate canonical attribute/"+test.name, func(t *testing.T) {
			if _, err := registry.NormalizeDN(test.dn); err == nil {
				t.Fatalf("NormalizeDN(%q) accepted duplicate canonical AVAs", test.dn)
			}
		})
	}

	canonical, err := registry.NormalizeDN(
		"foldAlias=ENGINEERING+exactAlias=Alice,dc=example,dc=com",
	)
	if err != nil {
		t.Fatalf("NormalizeDN(canonical multi-AVA): %v", err)
	}
	if got, want := canonical.String(),
		"exactName=Alice+foldName=ENGINEERING,dc=example,dc=com"; got != want {
		t.Fatalf("schema-aware pretty DN = %q, want %q", got, want)
	}

	reordered, err := registry.NormalizeDN(
		dnMultiAVAExactOID + "=Alice+" + dnMultiAVAFoldOID +
			"=engineering,dc=example,dc=com",
	)
	if err != nil {
		t.Fatalf("NormalizeDN(reordered OID multi-AVA): %v", err)
	}
	if !canonical.Equal(reordered) || canonical.Key() != reordered.Key() {
		t.Fatalf(
			"AVA order, aliases, or caseIgnore value changed identity:\n%s\n%s",
			canonical.Key(),
			reordered.Key(),
		)
	}

	exactCaseVariant, err := registry.NormalizeDN(
		"foldName=engineering+exactName=alice,dc=example,dc=com",
	)
	if err != nil {
		t.Fatalf("NormalizeDN(caseExact variant): %v", err)
	}
	if canonical.Equal(exactCaseVariant) || canonical.Key() == exactCaseVariant.Key() {
		t.Fatal("caseExact AVA value was folded inside a mixed multi-AVA RDN")
	}
}

func TestDNMultiAVANormalizedString(t *testing.T) {
	registry := newDNMultiAVARegistry(t)

	exact, err := registry.NormalizeDN(
		"exactAlias=Alice  Smith,dc=EXAMPLE,dc=COM",
	)
	if err != nil {
		t.Fatalf("NormalizeDN(caseExact): %v", err)
	}
	if got, want := exact.NormalizedString(),
		"exactName=Alice Smith,dc=example,dc=com"; got != want {
		t.Fatalf("caseExact normalized DN = %q, want %q", got, want)
	}
	multiAVA, err := registry.NormalizeDN(
		"foldAlias=ENGINEERING  TEAM+" + dnMultiAVAExactOID +
			"=Alice  Smith,domainComponent=EXAMPLE," +
			"0.9.2342.19200300.100.1.25=COM",
	)
	if err != nil {
		t.Fatalf("NormalizeDN(alias/OID multi-AVA): %v", err)
	}
	const wantMultiAVA = "exactName=Alice Smith+foldName=engineering team," +
		"dc=example,dc=com"
	if got := multiAVA.NormalizedString(); got != wantMultiAVA {
		t.Fatalf("alias/OID normalized DN = %q, want %q", got, wantMultiAVA)
	}
	if multiAVA.NormalizedString() == multiAVA.Key() ||
		!strings.HasPrefix(multiAVA.Key(), "dn:v2:") {
		t.Fatalf(
			"normalized text and identity key are not separated: text=%q key=%q",
			multiAVA.NormalizedString(),
			multiAVA.Key(),
		)
	}

	localName, err := registry.NormalizeDN(
		"foldAlias=RESEARCH+exactAlias=Alice Renamed",
	)
	if err != nil {
		t.Fatalf("NormalizeDN(local multi-AVA): %v", err)
	}
	superior, err := registry.NormalizeDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("NormalizeDN(superior): %v", err)
	}
	composed, err := directory.ComposeLocalName(localName, superior)
	if err != nil {
		t.Fatalf("ComposeLocalName(): %v", err)
	}
	if got, want := composed.NormalizedString(),
		"exactName=Alice Renamed+foldName=research,dc=example,dc=com"; got != want {
		t.Fatalf("composed normalized DN = %q, want %q", got, want)
	}

	legacy, err := directory.ParseDN("CN=Alice,DC=Example,DC=COM")
	if err != nil {
		t.Fatalf("ParseDN(legacy): %v", err)
	}
	if got, want := legacy.NormalizedString(), legacy.Key(); got != want {
		t.Fatalf("legacy normalized DN = %q, want existing key %q", got, want)
	}
}

func TestDNMultiAVARuntimeOpenLDAPSemantics(t *testing.T) {
	backends := []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{
			name: "memory",
			open: func(*testing.T) storage.Store {
				return storage.NewMemory()
			},
		},
		{
			name: "bolt",
			open: func(t *testing.T) storage.Store {
				t.Helper()
				store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
				if err != nil {
					t.Fatalf("OpenBolt(): %v", err)
				}
				return store
			},
		},
	}

	for _, backend := range backends {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			client := startDNMultiAVALocalServer(t, backend.open)
			assertDNMultiAVAObservations(
				t,
				runDNMultiAVAScenario(t, client),
				openLDAPDNMultiAVAExpectedObservations(),
			)
		})
	}
}

func TestOpenLDAPReferenceDNMultiAVADifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		dnMultiAVASchema,
		"",
		"\n"+dnMultiAVAOpenLDAPExtraData(),
	)
	defer stopOpenLDAP()

	openLDAPClient := dialDNMultiAVAClient(t, openLDAPURI)
	reference := runDNMultiAVAScenario(t, openLDAPClient)
	assertDNMultiAVAObservations(
		t,
		reference,
		openLDAPDNMultiAVAExpectedObservations(),
	)

	ldapGoClient := startDNMultiAVALocalServer(t, func(*testing.T) storage.Store {
		return storage.NewMemory()
	})
	implementation := runDNMultiAVAScenario(t, ldapGoClient)
	assertDNMultiAVAObservations(t, implementation, reference)
}

type dnMultiAVAObservation struct {
	name    string
	code    uint16
	entries []dnMultiAVAEntryObservation
}

type dnMultiAVAEntryObservation struct {
	dn         string
	exactNames []string
	foldNames  []string
}

func runDNMultiAVAScenario(
	t *testing.T,
	client *ldap.Conn,
) []dnMultiAVAObservation {
	t.Helper()
	const suffix = "dc=example,dc=com"

	var observations []dnMultiAVAObservation
	observeOperation := func(name string, err error) {
		observations = append(observations, dnMultiAVAObservation{
			name: name,
			code: dnMultiAVALDAPResultCode(err),
		})
	}

	observeOperation(
		"search duplicate canonical attribute through alias and OID",
		dnMultiAVABaseSearchError(
			client,
			"exactAlias=Alice+"+dnMultiAVAExactOID+"=Alice+"+
				"foldName=Engineering,"+suffix,
		),
	)

	primaryAlias := newDNMultiAVAAdd(
		"exactName=DupPrimary+exactAlias=DupAlias+foldName=one,"+suffix,
		"Duplicate Primary Alias",
		map[string][]string{
			"exactName":  {"DupPrimary"},
			"exactAlias": {"DupAlias"},
			"foldName":   {"one"},
		},
	)
	observeOperation(
		"add duplicate canonical attribute through primary name and alias",
		client.Add(primaryAlias),
	)

	aliasOID := newDNMultiAVAAdd(
		"exactAlias=DupAliasOID+"+dnMultiAVAExactOID+"=DupOID+"+
			"foldName=two,"+suffix,
		"Duplicate Alias OID",
		map[string][]string{
			"exactAlias":       {"DupAliasOID"},
			dnMultiAVAExactOID: {"DupOID"},
			"foldName":         {"two"},
		},
	)
	observeOperation(
		"add duplicate canonical attribute through alias and OID",
		client.Add(aliasOID),
	)

	repeated := newDNMultiAVAAdd(
		"exactName=DupFirst+exactName=DupSecond+foldName=three,"+suffix,
		"Duplicate Primary Name",
		map[string][]string{
			"exactName": {"DupFirst", "DupSecond"},
			"foldName":  {"three"},
		},
	)
	observeOperation(
		"add repeated primary attribute in one RDN",
		client.Add(repeated),
	)

	validAdd := newDNMultiAVAAdd(
		"foldAlias=Platform+exactAlias=Carol,"+suffix,
		"Sorted Add",
		map[string][]string{
			"exactAlias": {"Carol"},
			"foldAlias":  {"Platform"},
		},
	)
	observeOperation("add reordered alias multi-AVA", client.Add(validAdd))
	observations = append(observations, observeDNMultiAVAEntries(
		t,
		client,
		"entry after reordered alias add",
		suffix,
		ldap.ScopeWholeSubtree,
		"(cn=Sorted Add)",
	))
	observations = append(observations, observeDNMultiAVAEntries(
		t,
		client,
		"base search through reordered OID and caseIgnore AVA",
		"foldName=PLATFORM+"+dnMultiAVAExactOID+"=Carol,"+suffix,
		ldap.ScopeBaseObject,
		"(objectClass=*)",
	))

	exactDistinct := newDNMultiAVAAdd(
		"foldName=platform+exactName=carol,"+suffix,
		"Exact Lower Add",
		map[string][]string{
			"exactName": {"carol"},
			"foldName":  {"platform"},
		},
	)
	observeOperation(
		"add distinct caseExact AVA with equivalent caseIgnore AVA",
		client.Add(exactDistinct),
	)
	observations = append(observations, observeDNMultiAVAEntries(
		t,
		client,
		"distinct caseExact entry",
		suffix,
		ldap.ScopeWholeSubtree,
		"(cn=Exact Lower Add)",
	))

	caseIgnoreDuplicate := newDNMultiAVAAdd(
		"exactAlias=Carol+foldAlias=PLATFORM,"+suffix,
		"Case Ignore Duplicate",
		map[string][]string{
			"exactAlias": {"Carol"},
			"foldAlias":  {"PLATFORM"},
		},
	)
	observeOperation(
		"reject equivalent caseIgnore multi-AVA identity",
		client.Add(caseIgnoreDuplicate),
	)

	observeOperation(
		"modifyDN to reordered alias and OID multi-AVA",
		client.ModifyDN(ldap.NewModifyDNRequest(
			"exactName=Alice+foldName=Engineering,"+suffix,
			"foldAlias=Research+"+dnMultiAVAExactOID+"=Alice Renamed",
			true,
			"",
		)),
	)
	observations = append(observations, observeDNMultiAVAEntries(
		t,
		client,
		"entry after valid multi-AVA modifyDN",
		suffix,
		ldap.ScopeWholeSubtree,
		"(cn=Exact Upper)",
	))

	observeOperation(
		"modifyDN duplicate canonical attribute through primary name and alias",
		client.ModifyDN(ldap.NewModifyDNRequest(
			"exactName=alice+foldName=engineering,"+suffix,
			"exactName=Lower Renamed+exactAlias=Duplicate",
			true,
			"",
		)),
	)
	observations = append(observations, observeDNMultiAVAEntries(
		t,
		client,
		"source after rejected primary and alias modifyDN",
		suffix,
		ldap.ScopeWholeSubtree,
		"(cn=Exact Lower)",
	))

	observeOperation(
		"modifyDN duplicate canonical attribute through alias and OID",
		client.ModifyDN(ldap.NewModifyDNRequest(
			"exactName=Bob+foldName=Operations,"+suffix,
			"exactAlias=Bob Renamed+"+dnMultiAVAExactOID+"=Duplicate",
			true,
			"",
		)),
	)
	observations = append(observations, observeDNMultiAVAEntries(
		t,
		client,
		"source after rejected alias and OID modifyDN",
		suffix,
		ldap.ScopeWholeSubtree,
		"(cn=Exact Bob)",
	))

	return observations
}

func openLDAPDNMultiAVAExpectedObservations() []dnMultiAVAObservation {
	const suffix = "dc=example,dc=com"
	return []dnMultiAVAObservation{
		{
			name: "search duplicate canonical attribute through alias and OID",
			code: ldap.LDAPResultInvalidDNSyntax,
		},
		{
			name: "add duplicate canonical attribute through primary name and alias",
			code: ldap.LDAPResultInvalidDNSyntax,
		},
		{
			name: "add duplicate canonical attribute through alias and OID",
			code: ldap.LDAPResultInvalidDNSyntax,
		},
		{
			name: "add repeated primary attribute in one RDN",
			code: ldap.LDAPResultInvalidDNSyntax,
		},
		{name: "add reordered alias multi-AVA", code: ldap.LDAPResultSuccess},
		{
			name: "entry after reordered alias add",
			code: ldap.LDAPResultSuccess,
			entries: []dnMultiAVAEntryObservation{{
				dn:         "exactName=Carol+foldName=Platform," + suffix,
				exactNames: []string{"Carol"},
				foldNames:  []string{"Platform"},
			}},
		},
		{
			name: "base search through reordered OID and caseIgnore AVA",
			code: ldap.LDAPResultSuccess,
			entries: []dnMultiAVAEntryObservation{{
				dn:         "exactName=Carol+foldName=Platform," + suffix,
				exactNames: []string{"Carol"},
				foldNames:  []string{"Platform"},
			}},
		},
		{
			name: "add distinct caseExact AVA with equivalent caseIgnore AVA",
			code: ldap.LDAPResultSuccess,
		},
		{
			name: "distinct caseExact entry",
			code: ldap.LDAPResultSuccess,
			entries: []dnMultiAVAEntryObservation{{
				dn:         "exactName=carol+foldName=platform," + suffix,
				exactNames: []string{"carol"},
				foldNames:  []string{"platform"},
			}},
		},
		{
			name: "reject equivalent caseIgnore multi-AVA identity",
			code: ldap.LDAPResultEntryAlreadyExists,
		},
		{
			name: "modifyDN to reordered alias and OID multi-AVA",
			code: ldap.LDAPResultSuccess,
		},
		{
			name: "entry after valid multi-AVA modifyDN",
			code: ldap.LDAPResultSuccess,
			entries: []dnMultiAVAEntryObservation{{
				dn:         "exactName=Alice Renamed+foldName=Research," + suffix,
				exactNames: []string{"Alice Renamed"},
				foldNames:  []string{"Research"},
			}},
		},
		{
			name: "modifyDN duplicate canonical attribute through primary name and alias",
			code: ldap.LDAPResultInvalidDNSyntax,
		},
		{
			name: "source after rejected primary and alias modifyDN",
			code: ldap.LDAPResultSuccess,
			entries: []dnMultiAVAEntryObservation{{
				dn:         "exactName=alice+foldName=engineering," + suffix,
				exactNames: []string{"alice"},
				foldNames:  []string{"engineering"},
			}},
		},
		{
			name: "modifyDN duplicate canonical attribute through alias and OID",
			code: ldap.LDAPResultInvalidDNSyntax,
		},
		{
			name: "source after rejected alias and OID modifyDN",
			code: ldap.LDAPResultSuccess,
			entries: []dnMultiAVAEntryObservation{{
				dn:         "exactName=Bob+foldName=Operations," + suffix,
				exactNames: []string{"Bob"},
				foldNames:  []string{"Operations"},
			}},
		},
	}
}

func newDNMultiAVARegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, description := range strings.Split(dnMultiAVASchema, "\n")[:2] {
		description = strings.TrimSpace(strings.TrimPrefix(description, "attributetype"))
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", description, err)
		}
	}
	return registry
}

func startDNMultiAVALocalServer(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) *ldap.Conn {
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
	return dialDNMultiAVAClient(t, "ldap://"+address)
}

func dialDNMultiAVAClient(t *testing.T, uri string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(root at %s): %v", uri, err)
	}
	return client
}

func dnMultiAVAOpenLDAPExtraData() string {
	return strings.TrimPrefix(dnMultiAVAContentLDIF, `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

`)
}

func newDNMultiAVAAdd(
	dn string,
	commonName string,
	attributes map[string][]string,
) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"top", "dnMultiAVAEntry"})
	request.Attribute("cn", []string{commonName})
	names := make([]string, 0, len(attributes))
	for name := range attributes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		request.Attribute(name, attributes[name])
	}
	return request
}

func dnMultiAVABaseSearchError(client *ldap.Conn, dn string) error {
	_, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	return err
}

func observeDNMultiAVAEntries(
	t *testing.T,
	client *ldap.Conn,
	name,
	base string,
	scope int,
	filter string,
) dnMultiAVAObservation {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		base,
		scope,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"*"},
		nil,
	))
	observation := dnMultiAVAObservation{
		name: name,
		code: dnMultiAVALDAPResultCode(err),
	}
	if err != nil {
		return observation
	}
	for _, entry := range result.Entries {
		observation.entries = append(
			observation.entries,
			dnMultiAVAEntryObservation{
				dn: entry.DN,
				exactNames: dnMultiAVAAttributeValues(
					entry,
					"exactName",
					"exactAlias",
					dnMultiAVAExactOID,
				),
				foldNames: dnMultiAVAAttributeValues(
					entry,
					"foldName",
					"foldAlias",
					dnMultiAVAFoldOID,
				),
			},
		)
	}
	sort.Slice(observation.entries, func(left, right int) bool {
		return observation.entries[left].dn < observation.entries[right].dn
	})
	return observation
}

func dnMultiAVAAttributeValues(entry *ldap.Entry, names ...string) []string {
	seen := make(map[string]struct{})
	var values []string
	for _, name := range names {
		for _, value := range entry.GetAttributeValues(name) {
			if _, exists := seen[value]; exists {
				continue
			}
			seen[value] = struct{}{}
			values = append(values, value)
		}
	}
	sort.Strings(values)
	return values
}

func dnMultiAVALDAPResultCode(err error) uint16 {
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return ldapErr.ResultCode
	}
	return ldap.ErrorNetwork
}

func assertDNMultiAVAObservations(
	t *testing.T,
	got,
	want []dnMultiAVAObservation,
) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("observation count = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if reflect.DeepEqual(got[index], want[index]) {
			continue
		}
		t.Errorf(
			"%s mismatch\n got: %#v\nwant: %#v",
			want[index].name,
			got[index],
			want[index],
		)
	}
}
