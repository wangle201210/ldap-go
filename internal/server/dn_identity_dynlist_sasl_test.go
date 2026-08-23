package server

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const dnIdentityDynlistSASLPartition = "dn-identity-dynlist-sasl"

type dnIdentityDynlistSASLStoreFactory struct {
	name string
	open func(*testing.T) storage.Store
}

func TestDNIdentityDynlistAndSASLAuthorization(t *testing.T) {
	for _, backend := range dnIdentityDynlistSASLStoreFactories() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			registry := dnIdentityDynlistSASLRegistry(t)
			store := backend.open(t)
			t.Cleanup(func() { _ = store.Close() })
			seedDNIdentityDynlistSASL(t, store, registry)
			instance, runtime, database := dnIdentityDynlistSASLRuntime(
				t,
				store,
				registry,
			)

			t.Run("dynlist and dyngroup", func(t *testing.T) {
				testDNIdentityDynlistProjection(
					t,
					instance,
					runtime,
					database,
					store,
				)
			})
			t.Run("authorization rules", func(t *testing.T) {
				testDNIdentitySASLAuthorizationRules(
					t,
					instance,
					runtime,
				)
			})
			t.Run("delegated reader fallback", func(t *testing.T) {
				testDNIdentityDelegatedReaderFallback(
					t,
					store,
					registry,
					database,
				)
			})
		})
	}
}

func dnIdentityDynlistSASLStoreFactories() []dnIdentityDynlistSASLStoreFactory {
	return []dnIdentityDynlistSASLStoreFactory{
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
}

func dnIdentityDynlistSASLRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, description := range []string{
		"( 1.3.6.1.4.1.99999.918.1 NAME 'dynExactName' EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 1.3.6.1.4.1.99999.918.2 NAME 'dynFoldName' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	} {
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", description, err)
		}
	}
	return registry
}

func seedDNIdentityDynlistSASL(
	t *testing.T,
	store storage.Store,
	registry *schema.Registry,
) {
	t.Helper()
	entries := []directory.Entry{
		{DN: "dc=example,dc=com", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("domain")},
			{Description: "dc", Values: stringValues("example")},
		}},
		{DN: "dynExactName=People,dc=example,dc=com", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("organizationalUnit")},
			{Description: "ou", Values: stringValues("People")},
		}},
		{DN: "dynExactName=people,dc=example,dc=com", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("organizationalUnit")},
			{Description: "ou", Values: stringValues("people")},
		}},
		{DN: "cn=Upper,dynExactName=People,dc=example,dc=com", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("person")},
			{Description: "cn", Values: stringValues("Upper")},
			{Description: "sn", Values: stringValues("Upper")},
		}},
		{DN: "cn=Upper,dynExactName=people,dc=example,dc=com", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("person")},
			{Description: "cn", Values: stringValues("Upper")},
			{Description: "sn", Values: stringValues("Exact sibling")},
		}},
		{DN: "dynFoldName=Alice Smith,dc=example,dc=com", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("person")},
			{Description: "cn", Values: stringValues("Folded")},
			{Description: "sn", Values: stringValues("Folded")},
		}},
		{DN: "cn=Exact Dynamic,dc=example,dc=com", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("groupOfURLs")},
			{Description: "cn", Values: stringValues("Exact Dynamic")},
			{Description: "memberURL", Values: stringValues("ldap:///dynExactName=People,dc=example,dc=com??sub?(objectClass=person)")},
		}},
		{DN: "cn=Fold Dynamic,dc=example,dc=com", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("groupOfURLs")},
			{Description: "cn", Values: stringValues("Fold Dynamic")},
			{Description: "memberURL", Values: stringValues("ldap:///dynFoldName=Alice%20Smith,dc=example,dc=com??base?(objectClass=person)")},
		}},
		{DN: "cn=Static Exact,dc=example,dc=com", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("groupOfNames")},
			{Description: "cn", Values: stringValues("Static Exact")},
			{Description: "member", Values: stringValues("cn=Upper,dynExactName=People,dc=example,dc=com")},
		}},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		partition := storage.WriterInPartitionWithNormalizer(
			writer,
			dnIdentityDynlistSASLPartition,
			registry,
		)
		for _, entry := range entries {
			if err := partition.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed schema-aware dynlist/SASL entries: %v", err)
	}
}

func dnIdentityDynlistSASLRuntime(
	t *testing.T,
	store storage.Store,
	registry *schema.Registry,
) (*Server, *runtimeState, runtimeDatabase) {
	t.Helper()
	suffix := mustDNIdentityDynlistSASLDN(t, registry, "dc=example,dc=com")
	database := runtimeDatabase{
		name:         "{1}mdb",
		partition:    dnIdentityDynlistSASLPartition,
		suffixes:     []directory.DN{suffix},
		dnNormalizer: registry,
		dynlist: &dynlistRuntimeConfiguration{attributeSets: []dynlistAttributeSet{{
			objectClass:  "groupOfURLs",
			urlAttribute: "memberURL",
			mappings: []dynlistAttributeMapping{{
				memberAttribute:   "member",
				memberOfAttribute: "dgMemberOf",
			}},
		}}},
		dyngroup: &dynamicGroupRuntimeConfiguration{pairs: []dynamicGroupAttributePair{{
			memberAttribute: "member",
			urlAttribute:    "memberURL",
		}}},
	}
	runtime := &runtimeState{
		schema:    registry,
		access:    acl.DefaultPolicy(),
		databases: []runtimeDatabase{database},
	}
	return &Server{config: Config{Store: store}}, runtime, database
}

func testDNIdentityDynlistProjection(
	t *testing.T,
	instance *Server,
	runtime *runtimeState,
	database runtimeDatabase,
	store storage.Store,
) {
	t.Helper()
	assertedUpper := mustDNIdentityDynlistSASLLegacyDN(
		t,
		"cn=Upper,dynExactName=People,dc=example,dc=com",
	)
	assertedLower := mustDNIdentityDynlistSASLLegacyDN(
		t,
		"cn=Upper,dynExactName=people,dc=example,dc=com",
	)
	assertedFold := mustDNIdentityDynlistSASLLegacyDN(
		t,
		`dynFoldName=\20ALICE\20\20SMITH\20,DC=EXAMPLE,DC=COM`,
	)

	if err := store.View(context.Background(), func(reader storage.Reader) error {
		cache := newDynlistProjectionCache(
			context.Background(),
			instance,
			runtime,
			reader,
			"",
			dynlistProjectionRequest{attributes: []string{"member", "dgMemberOf"}},
		)
		project := func(rawDN string) (directory.Entry, error) {
			dn := mustDNIdentityDynlistSASLLegacyDN(t, rawDN)
			entry, err := readerForDatabase(reader, database).Get(dn)
			if err != nil {
				return directory.Entry{}, err
			}
			projected, _, err := cache.apply(database, entry)
			return projected, err
		}

		exact, err := project("cn=Exact Dynamic,dc=example,dc=com")
		if err != nil {
			return err
		}
		assertDNIdentityDynlistValues(
			t,
			exact.Values("member"),
			"cn=Upper,dynExactName=People,dc=example,dc=com",
		)

		fold, err := project("cn=Fold Dynamic,dc=example,dc=com")
		if err != nil {
			return err
		}
		assertDNIdentityDynlistValues(
			t,
			fold.Values("member"),
			"dynFoldName=Alice Smith,dc=example,dc=com",
		)

		upper, err := project(assertedUpper.String())
		if err != nil {
			return err
		}
		assertDNIdentityDynlistValues(
			t,
			upper.Values("dgMemberOf"),
			"cn=Exact Dynamic,dc=example,dc=com",
		)
		lower, err := project(assertedLower.String())
		if err != nil {
			return err
		}
		if values := lower.Values("dgMemberOf"); len(values) != 0 {
			t.Fatalf("caseExact sibling dgMemberOf = %q, want none", byteStrings(values))
		}

		exactRestriction, err := parseDynlistLDAPURL(
			"ldap:///dynExactName=People,dc=example,dc=com??sub?(objectClass=*)",
		)
		if err != nil {
			return err
		}
		applies, err := dynlistAttributeSetApplies(
			runtime.schema,
			dynlistAttributeSet{
				objectClass: "person",
				restriction: &exactRestriction,
			},
			lower,
		)
		if err != nil {
			return err
		}
		if applies {
			t.Fatal("caseExact sibling matched dynlist attrset restriction")
		}
		foldRestriction, err := parseDynlistLDAPURL(
			"ldap:///dynFoldName=Alice%20Smith,dc=example,dc=com??base?(objectClass=*)",
		)
		if err != nil {
			return err
		}
		applies, err = dynlistAttributeSetApplies(
			runtime.schema,
			dynlistAttributeSet{
				objectClass: "person",
				restriction: &foldRestriction,
			},
			directory.Entry{
				DN: foldEquivalentDN(),
				Attributes: []directory.Attribute{{
					Description: "objectClass",
					Values:      stringValues("person"),
				}},
			},
		)
		if err != nil {
			return err
		}
		if !applies {
			t.Fatal("caseIgnore-equivalent DN missed dynlist attrset restriction")
		}

		for _, test := range []struct {
			name      string
			entryDN   string
			assertion directory.DN
			want      bool
		}{
			{name: "dynlist exact hit", entryDN: "cn=Exact Dynamic,dc=example,dc=com", assertion: assertedUpper, want: true},
			{name: "dynlist exact sibling miss", entryDN: "cn=Exact Dynamic,dc=example,dc=com", assertion: assertedLower},
			{name: "dynlist fold equivalent", entryDN: "cn=Fold Dynamic,dc=example,dc=com", assertion: assertedFold, want: true},
		} {
			entry, err := readerForDatabase(reader, database).Get(
				mustDNIdentityDynlistSASLLegacyDN(t, test.entryDN),
			)
			if err != nil {
				return err
			}
			handled, matched, err := cache.dynamicGroupCompare(
				database,
				entry,
				"member",
				[]byte(test.assertion.String()),
			)
			if err != nil {
				return err
			}
			if !handled || matched != test.want {
				t.Fatalf("%s = handled %t matched %t, want true/%t", test.name, handled, matched, test.want)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("dynlist schema-aware projection: %v", err)
	}
}

func testDNIdentityDelegatedReaderFallback(
	t *testing.T,
	store storage.Store,
	registry *schema.Registry,
	database runtimeDatabase,
) {
	t.Helper()
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		delegated := storage.ReaderInPartition(
			reader,
			dnIdentityDynlistSASLPartition,
		)
		upper, err := normalizeRuntimeReaderDN(
			delegated,
			database,
			mustDNIdentityDynlistSASLLegacyDN(
				t,
				"cn=Upper,dynExactName=People,dc=example,dc=com",
			),
		)
		if err != nil {
			return err
		}
		lower, err := normalizeRuntimeReaderDN(
			delegated,
			database,
			mustDNIdentityDynlistSASLLegacyDN(
				t,
				"cn=Upper,dynExactName=people,dc=example,dc=com",
			),
		)
		if err != nil {
			return err
		}
		if upper.Equal(lower) {
			t.Fatal("delegated reader fallback collapsed caseExact DNs")
		}
		folded, err := normalizeRuntimeReaderDN(
			delegated,
			database,
			mustDNIdentityDynlistSASLLegacyDN(t, foldEquivalentDN()),
		)
		if err != nil {
			return err
		}
		canonical, err := directory.ParseDNWithNormalizer(
			"dynFoldName=Alice Smith,dc=example,dc=com",
			registry,
		)
		if err != nil {
			return err
		}
		if !folded.Equal(canonical) {
			t.Fatal("delegated reader fallback missed caseIgnore-equivalent DN")
		}

		readerWithIdentity := storage.ReaderInPartitionWithNormalizer(
			reader,
			dnIdentityDynlistSASLPartition,
			registry,
		)
		databaseWithoutNormalizer := database
		databaseWithoutNormalizer.dnNormalizer = nil
		readerNormalized, err := normalizeRuntimeReaderDN(
			readerWithIdentity,
			databaseWithoutNormalizer,
			mustDNIdentityDynlistSASLLegacyDN(
				t,
				"cn=Upper,dynExactName=People,dc=example,dc=com",
			),
		)
		if err != nil {
			return err
		}
		if readerNormalized.Key() != upper.Key() {
			t.Fatal("database fallback discarded delegated reader DN identity")
		}
		return nil
	}); err != nil {
		t.Fatalf("delegated reader fallback: %v", err)
	}
}

func testDNIdentitySASLAuthorizationRules(
	t *testing.T,
	instance *Server,
	runtime *runtimeState,
) {
	t.Helper()
	authenticationDN := mustDNIdentityDynlistSASLLegacyDN(
		t,
		"cn=Upper,dynExactName=People,dc=example,dc=com",
	)
	exactSibling := mustDNIdentityDynlistSASLLegacyDN(
		t,
		"cn=Upper,dynExactName=people,dc=example,dc=com",
	)
	foldEquivalent := mustDNIdentityDynlistSASLLegacyDN(
		t,
		`dynFoldName=\20ALICE\20\20SMITH\20,DC=EXAMPLE,DC=COM`,
	)

	for _, test := range []struct {
		name      string
		rule      string
		asserted  directory.DN
		wantMatch bool
	}{
		{name: "dn exact", rule: "dn:" + authenticationDN.String(), asserted: authenticationDN, wantMatch: true},
		{name: "dn exact sibling", rule: "dn:" + authenticationDN.String(), asserted: exactSibling},
		{name: "dn.exact", rule: "dn.exact:" + authenticationDN.String(), asserted: authenticationDN, wantMatch: true},
		{name: "dn.exact sibling", rule: "dn.exact:" + authenticationDN.String(), asserted: exactSibling},
		{name: "dn onelevel", rule: "dn.onelevel:dynExactName=People,dc=example,dc=com", asserted: authenticationDN, wantMatch: true},
		{name: "dn onelevel sibling", rule: "dn.onelevel:dynExactName=People,dc=example,dc=com", asserted: exactSibling},
		{name: "dn children", rule: "dn.children:dynExactName=People,dc=example,dc=com", asserted: authenticationDN, wantMatch: true},
		{name: "dn children sibling", rule: "dn.children:dynExactName=People,dc=example,dc=com", asserted: exactSibling},
		{name: "dn children excludes base", rule: "dn.children:dynExactName=People,dc=example,dc=com", asserted: mustDNIdentityDynlistSASLLegacyDN(t, "dynExactName=People,dc=example,dc=com")},
		{name: "dn subtree", rule: "dn.subtree:dynExactName=People,dc=example,dc=com", asserted: authenticationDN, wantMatch: true},
		{name: "dn subtree sibling", rule: "dn.subtree:dynExactName=People,dc=example,dc=com", asserted: exactSibling},
		{name: "dn subtree fold", rule: "dn.subtree:dynFoldName=Alice Smith,dc=example,dc=com", asserted: foldEquivalent, wantMatch: true},
		{name: "bare exact", rule: authenticationDN.String(), asserted: authenticationDN, wantMatch: true},
		{name: "bare exact sibling", rule: authenticationDN.String(), asserted: exactSibling},
		{name: "group member", rule: "group/groupOfNames/member:cn=Static Exact,dc=example,dc=com", asserted: authenticationDN, wantMatch: true},
		{name: "group DN fold", rule: `group/groupOfNames/member:cn=\20STATIC\20\20EXACT\20,DC=EXAMPLE,DC=COM`, asserted: authenticationDN, wantMatch: true},
		{name: "group member sibling", rule: "group/groupOfNames/member:cn=Static Exact,dc=example,dc=com", asserted: exactSibling},
		{name: "LDAP URL", rule: "ldap:///dynExactName=People,dc=example,dc=com??sub?(objectClass=person)", asserted: authenticationDN, wantMatch: true},
		{name: "LDAP URL sibling", rule: "ldap:///dynExactName=People,dc=example,dc=com??sub?(objectClass=person)", asserted: exactSibling},
		{name: "LDAP URL fold", rule: "ldap:///dynFoldName=Alice%20Smith,dc=example,dc=com??base?(objectClass=person)", asserted: foldEquivalent, wantMatch: true},
		{name: "regex textual DN", rule: `dn.regex:^cn=upper,dynexactname=people,dc=example,dc=com$`, asserted: authenticationDN, wantMatch: true},
		{name: "regex normalized caseIgnore value", rule: `dn.regex:^dynfoldname=alice smith,dc=example,dc=com$`, asserted: foldEquivalent, wantMatch: true},
		{name: "regex never sees v2 key", rule: `dn.regex:^dn:v2:`, asserted: authenticationDN},
	} {
		t.Run(test.name, func(t *testing.T) {
			matched, err := instance.authorizationRuleMatches(
				context.Background(),
				runtime,
				authenticationDN,
				test.rule,
				test.asserted,
			)
			if err != nil {
				t.Fatalf("authorizationRuleMatches(%q): %v", test.rule, err)
			}
			if matched != test.wantMatch {
				t.Fatalf("authorizationRuleMatches(%q) = %t, want %t", test.rule, matched, test.wantMatch)
			}
		})
	}

	var authzRegexps []saslAuthzRegexp
	for _, raw := range []string{
		`^uid=folded,cn=authz,cn=auth$ "dynFoldName=Alice Smith,dc=example,dc=com"`,
		`^uid=urlfolded,cn=authz,cn=auth$ ldap:///dynFoldName=%5C20ALICE%5C20%5C20SMITH%5C20,DC=EXAMPLE,DC=COM??base?(objectClass=person)`,
	} {
		rule, err := parseSASLAuthzRegexp(raw)
		if err != nil {
			t.Fatalf("parseSASLAuthzRegexp(%q): %v", raw, err)
		}
		authzRegexps = append(authzRegexps, rule)
	}
	runtime.sasl.authzRegexps = authzRegexps
	for _, user := range []string{"folded", "urlfolded"} {
		matched, err := instance.authorizationRuleMatches(
			context.Background(),
			runtime,
			authenticationDN,
			"u:"+user,
			foldEquivalent,
		)
		if err != nil || !matched {
			t.Fatalf("u:%s caseIgnore mapping = %t, %v, want true", user, matched, err)
		}
	}
}

func mustDNIdentityDynlistSASLDN(
	t *testing.T,
	registry *schema.Registry,
	value string,
) directory.DN {
	t.Helper()
	dn, err := directory.ParseDNWithNormalizer(value, registry)
	if err != nil {
		t.Fatalf("ParseDNWithNormalizer(%q): %v", value, err)
	}
	return dn
}

func mustDNIdentityDynlistSASLLegacyDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}

func assertDNIdentityDynlistValues(t *testing.T, values [][]byte, want ...string) {
	t.Helper()
	got := byteStrings(values)
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("DN values = %q, want %q", got, want)
	}
}

func byteStrings(values [][]byte) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = string(values[index])
	}
	return result
}

func foldEquivalentDN() string {
	return `dynFoldName=\20ALICE\20\20SMITH\20,DC=EXAMPLE,DC=COM`
}
