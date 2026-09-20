package server

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const configurationSchemaReferenceCommit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

func configurationSchemaReferenceTools(t *testing.T) (openLDAPReferenceTools, string) {
	t.Helper()
	tools := requireSyntaxPublicationReference(t)
	source, err := os.ReadFile(filepath.Join(os.Getenv("OPENLDAP_SOURCE"), "servers", "slapd", "bconfig.c"))
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(source)) != "901a7da3d3b0440ae09799da56682f9083c3b3e4a06117fcd79e02f217e1811b" {
		t.Fatalf("bconfig.c must match %s: %v", configurationSchemaReferenceCommit, err)
	}
	return tools, string(source)
}

func configurationSchemaReferenceClient(t *testing.T, uri string, authenticated bool) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	client.SetTimeout(5 * time.Second)
	if authenticated {
		if err := client.Bind("cn=config", "config-secret"); err != nil {
			t.Fatalf("configuration bind: LDAP result %d", configurationSchemaReferenceCode(t, err))
		}
	}
	return client
}

func TestOpenLDAPConfigurationSchemaReference(t *testing.T) {
	tools, source := configurationSchemaReferenceTools(t)
	attributes, classes := configurationSchemaReferenceSource(t, source)
	nativeURI := startOpenLDAPDynamicConfigReferralServer(t, tools)
	native := configurationSchemaReferenceClient(t, nativeURI, true)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	for _, setting := range [][3]string{
		{"cn=config", "olcThreads", "16"},
		{"cn=config", "olcSizeLimit", "500"},
		{"olcDatabase={1}mdb,cn=config", "olcSizeLimit", "500"},
		{"olcDatabase={1}mdb,cn=config", "olcReadOnly", "FALSE"},
	} {
		setUnsupportedRuntimeConfigurationAttribute(t, store, setting[0], setting[1], setting[2])
		request := ldap.NewModifyRequest(setting[0], nil)
		request.Replace(setting[1], []string{setting[2]})
		if code := configurationSchemaReferenceCode(t, native.Modify(request)); code != 0 {
			t.Fatalf("native fixture setting %s: result %d", setting[1], code)
		}
	}
	setUnsupportedRuntimeConfigurationAttribute(t, store, "olcDatabase={1}mdb,cn=config", "olcRootDN", "cn=admin,dc=example,dc=com")
	setUnsupportedRuntimeConfigurationAttribute(t, store, "olcDatabase={1}mdb,cn=config", "olcRootPW", "secret")
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	goURI := "ldap://" + address
	client := configurationSchemaReferenceClient(t, goURI, true)

	t.Run("metadata", func(t *testing.T) {
		configurationSchemaReferenceMetadata(t, nativeURI, goURI, attributes, classes)
	})
	t.Run("queries", func(t *testing.T) {
		configurationSchemaReferenceQueries(t, nativeURI, goURI, attributes, classes)
	})
	t.Run("assertion-boundaries", func(t *testing.T) {
		configurationSchemaReferenceAssertionBoundaries(t, native, client)
	})
	t.Run("schema-selectors", func(t *testing.T) {
		configurationSchemaReferenceSelectors(t, nativeURI, goURI, attributes, classes)
	})
	t.Run("class-selection", func(t *testing.T) {
		configurationSchemaReferenceClassSelection(t, native, client, classes)
	})
	t.Run("mutations", func(t *testing.T) {
		configurationSchemaReferenceMutations(t, native, client)
	})
	t.Run("tagged-runtime", func(t *testing.T) {
		configurationSchemaReferenceTaggedRuntime(t, nativeURI, goURI, native, client)
	})
}

func configurationSchemaReferenceCode(t *testing.T, err error) uint16 {
	t.Helper()
	if err == nil {
		return 0
	}
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) || ldapError.ResultCode >= 200 {
		t.Fatal("unexpected LDAP transport or client failure")
	}
	return ldapError.ResultCode
}

// This independent metadata representation deliberately does not use the Go
// schema parser whose publication is under test. NAME preserves canonical order;
// the sets in SUP, MUST and MAY ignore only insignificant member ordering.
type configurationSchemaReferenceDescription struct {
	OID    string
	Fields map[string][]string
}

func configurationSchemaReferenceParse(t *testing.T, value string, class bool) configurationSchemaReferenceDescription {
	t.Helper()
	if strings.HasPrefix(value, "{") {
		end := strings.IndexByte(value, '}')
		if end < 2 {
			t.Fatal("invalid schema value index")
		}
		if _, err := strconv.Atoi(value[1:end]); err != nil {
			t.Fatal("invalid schema value index")
		}
		value = value[end+1:]
	}
	tokens := matchingRulesReferenceTokens.FindAllString(value, -1)
	if len(tokens) < 5 || tokens[0] != "(" || tokens[len(tokens)-1] != ")" {
		t.Fatal("invalid configuration schema description")
	}
	description := configurationSchemaReferenceDescription{OID: tokens[1], Fields: map[string][]string{}}
	tokens = tokens[2 : len(tokens)-1]
	for len(tokens) > 0 {
		key := tokens[0]
		tokens = tokens[1:]
		if _, duplicate := description.Fields[key]; duplicate {
			t.Fatalf("duplicate schema field %s for %s", key, description.OID)
		}
		switch key {
		case "ABSTRACT", "STRUCTURAL", "AUXILIARY", "OBSOLETE", "SINGLE-VALUE", "COLLECTIVE", "NO-USER-MODIFICATION":
			description.Fields[key] = []string{}
			continue
		case "NAME", "DESC", "SUP", "EQUALITY", "ORDERING", "SUBSTR", "SYNTAX", "USAGE", "MUST", "MAY":
		default:
			if !strings.HasPrefix(key, "X-") {
				t.Fatalf("unknown schema field %s for %s", key, description.OID)
			}
		}
		var values []string
		if len(tokens) == 0 {
			t.Fatalf("missing schema field %s", key)
		}
		if tokens[0] == "(" {
			tokens = tokens[1:]
			for len(tokens) > 0 && tokens[0] != ")" {
				if tokens[0] != "$" {
					values = append(values, strings.Trim(tokens[0], "'"))
				}
				tokens = tokens[1:]
			}
			if len(tokens) == 0 {
				t.Fatal("unterminated configuration schema list")
			}
			tokens = tokens[1:]
		} else {
			values = []string{strings.Trim(tokens[0], "'")}
			tokens = tokens[1:]
		}
		if key == "SUP" || key == "MUST" || key == "MAY" {
			slices.Sort(values)
		}
		description.Fields[key] = values
	}
	if class {
		if _, found := description.Fields["SUP"]; !found {
			description.Fields["SUP"] = []string{"top"}
		}
	} else if _, found := description.Fields["USAGE"]; !found {
		description.Fields["USAGE"] = []string{"userApplications"}
	}
	return description
}

func configurationSchemaReferenceSource(t *testing.T, source string) (map[string]configurationSchemaReferenceDescription, map[string]configurationSchemaReferenceDescription) {
	t.Helper()
	start := strings.Index(source, "static ConfigTable config_back_cf_table[]")
	end := strings.Index(source, "typedef struct ServerID")
	if start < 0 || end <= start {
		t.Fatal("pinned configuration schema tables not found")
	}
	quoted := regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	adjacent := regexp.MustCompile(`"(?:[^"\\]|\\.)*"(?:\s*"(?:[^"\\]|\\.)*")*`)
	expand := strings.NewReplacer(
		"OLcfgGlAt:", "1.3.6.1.4.1.4203.1.12.2.3.0.",
		"OLcfgDbAt:", "1.3.6.1.4.1.4203.1.12.2.3.2.",
		"OLcfgGlOc:", "1.3.6.1.4.1.4203.1.12.2.4.0.",
		"OMsDirectoryString", "1.3.6.1.4.1.1466.115.121.1.15",
		"OMsBoolean", "1.3.6.1.4.1.1466.115.121.1.7",
		"OMsInteger", "1.3.6.1.4.1.1466.115.121.1.27",
		"OMsOctetString", "1.3.6.1.4.1.1466.115.121.1.40",
		"OMsDN", "1.3.6.1.4.1.1466.115.121.1.12",
	)
	attributes := map[string]configurationSchemaReferenceDescription{}
	classes := map[string]configurationSchemaReferenceDescription{}
	for _, literal := range adjacent.FindAllString(source[start:end], -1) {
		var value strings.Builder
		for _, part := range quoted.FindAllString(literal, -1) {
			decoded, err := strconv.Unquote(part)
			if err != nil {
				t.Fatal("invalid pinned C string literal")
			}
			value.WriteString(decoded)
		}
		definition := value.String()
		if !strings.HasPrefix(definition, "( OLcfg") {
			continue
		}
		class := strings.HasPrefix(definition, "( OLcfgGlOc:")
		parsed := configurationSchemaReferenceParse(t, expand.Replace(definition), class)
		catalog := attributes
		if class {
			catalog = classes
		}
		if old, duplicate := catalog[parsed.OID]; duplicate && !reflect.DeepEqual(old, parsed) {
			t.Fatalf("conflicting pinned description %s", parsed.OID)
		}
		catalog[parsed.OID] = parsed
	}
	if len(attributes) != 111 || len(classes) != 9 {
		t.Fatalf("pinned core schema count: %d attributes, %d classes; want 111, 9", len(attributes), len(classes))
	}
	return attributes, classes
}

func configurationSchemaReferenceRead(t *testing.T, client *ldap.Conn, base, filter string, attrs []string, typesOnly bool) (*ldap.SearchResult, uint16) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(base, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, typesOnly, filter, attrs, nil))
	if result == nil {
		result = &ldap.SearchResult{}
	}
	return result, configurationSchemaReferenceCode(t, err)
}

func configurationSchemaReferenceMutations(t *testing.T, native, client *ldap.Conn) {
	t.Helper()
	for _, test := range []struct {
		name, base, attribute, value string
		wantNative, wantGo           uint16
	}{
		{"limit-name", "cn=config", "olcSizeLimit", "123", 0, 0},
		{"limit-oid", "cn=config", "1.3.6.1.4.1.4203.1.12.2.3.0.60", "124", 0, 0},
		{"limit-case", "cn=config", "OLCSIZELIMIT", "125", 0, 0},
		{"limit-language", "cn=config", "olcSizeLimit;lang-en", "126", 0, 0},
		{"limit-unknown-option", "cn=config", "olcSizeLimit;unknown-option", "127", 17, 17},
		{"limit-binary", "cn=config", "olcSizeLimit;binary", "128", 17, 17},
		{"threads-name", "cn=config", "olcThreads", "32", 0, 19},
		{"threads-oid", "cn=config", "1.3.6.1.4.1.4203.1.12.2.3.0.66", "24", 0, 19},
		{"pending-name", "cn=config", "olcConnMaxPending", "31", 0, 0},
		{"pending-oid", "cn=config", "1.3.6.1.4.1.4203.1.12.2.3.0.11", "32", 0, 0},
		{"database-limit-name", "olcDatabase={1}mdb,cn=config", "olcSizeLimit", "321", 0, 0},
		{"database-limit-oid", "olcDatabase={1}mdb,cn=config", "1.3.6.1.4.1.4203.1.12.2.3.0.60", "322", 0, 0},
		{"ordered-limits", "olcDatabase={1}mdb,cn=config", "olcLimits", "users size=unlimited", 0, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			for i, connection := range []*ldap.Conn{native, client} {
				label, want := "native", test.wantNative
				if i == 1 {
					label, want = "go", test.wantGo
				}
				readAttributes := []string{"olcSizeLimit", "olcThreads", "olcLimits", "olcConnMaxPending"}
				before, beforeCode := configurationSchemaReferenceRead(t, connection, test.base, "(objectClass=*)", readAttributes, false)
				if beforeCode != 0 || len(before.Entries) != 1 {
					t.Fatal("configuration mutation fixture is not readable")
				}
				request := ldap.NewModifyRequest(test.base, nil)
				request.Replace(test.attribute, []string{test.value})
				code := configurationSchemaReferenceCode(t, connection.Modify(request))
				t.Logf("%s Modify %s: result=%d (expected %d)", label, test.attribute, code, want)
				if code != want {
					t.Errorf("%s result=%d, want %d", label, code, want)
				}
				result, readCode := configurationSchemaReferenceRead(t, connection, test.base, "(objectClass=*)", readAttributes, false)
				if readCode != 0 || len(result.Entries) != 1 {
					t.Fatalf("%s configuration read: code=%d entries=%d", label, readCode, len(result.Entries))
				}
				if want != 0 {
					if !reflect.DeepEqual(configurationSchemaReferenceValues(t, before), configurationSchemaReferenceValues(t, result)) {
						t.Errorf("%s rejected configuration mutation changed stored values", label)
					}
					continue
				}
				attribute := strings.ToLower(test.attribute)
				switch attribute {
				case "1.3.6.1.4.1.4203.1.12.2.3.0.60":
					attribute = "olcsizelimit"
				case "1.3.6.1.4.1.4203.1.12.2.3.0.66":
					attribute = "olcthreads"
				case "1.3.6.1.4.1.4203.1.12.2.3.0.11":
					attribute = "olcconnmaxpending"
				}
				value := test.value
				if attribute == "olclimits" {
					value = "{0}" + value
				}
				wantValues := configurationSchemaReferenceValues(t, before)
				wantValues[strings.ToLower(test.base)+"\n"+attribute] = []string{value}
				if !reflect.DeepEqual(configurationSchemaReferenceValues(t, result), wantValues) {
					t.Errorf("%s configuration mutation did not preserve other values or canonical readback", label)
				}
			}
		})
	}
}

func configurationSchemaReferenceMetadata(t *testing.T, nativeURI, goURI string, attributes, classes map[string]configurationSchemaReferenceDescription) {
	t.Helper()
	for _, authenticated := range []bool{true, false} {
		for _, base := range []string{"cn=Subschema", "cn=config", "cn=schema,cn=config"} {
			t.Run(fmt.Sprintf("admin=%t/%s", authenticated, base), func(t *testing.T) {
				for i, uri := range []string{nativeURI, goURI} {
					label := []string{"native", "go"}[i]
					client := configurationSchemaReferenceClient(t, uri, authenticated)
					attributeName, className := "attributeTypes", "objectClasses"
					if base != "cn=Subschema" {
						attributeName, className = "olcAttributeTypes", "olcObjectClasses"
					}
					result, code := configurationSchemaReferenceRead(t, client, base, "(objectClass=*)", []string{attributeName, className}, false)
					t.Logf("%s schema read: code=%d entries=%d", label, code, len(result.Entries))
					if !authenticated && base != "cn=Subschema" {
						if code != 32 || len(result.Entries) != 0 {
							t.Errorf("%s anonymous config visibility: code=%d entries=%d", label, code, len(result.Entries))
						}
						continue
					}
					if code != 0 || len(result.Entries) != 1 {
						t.Errorf("%s schema read failed: code=%d entries=%d", label, code, len(result.Entries))
						continue
					}
					for _, group := range []struct {
						attribute string
						class     bool
						want      map[string]configurationSchemaReferenceDescription
					}{{attributeName, false, attributes}, {className, true, classes}} {
						got := map[string]configurationSchemaReferenceDescription{}
						for _, value := range result.Entries[0].GetAttributeValues(group.attribute) {
							parsed := configurationSchemaReferenceParse(t, value, group.class)
							if _, relevant := group.want[parsed.OID]; relevant {
								if _, duplicate := got[parsed.OID]; duplicate {
									t.Errorf("%s duplicate schema OID %s", label, parsed.OID)
								}
								got[parsed.OID] = parsed
							}
						}
						t.Logf("%s core %s count=%d", label, group.attribute, len(got))
						if base != "cn=Subschema" {
							if len(got) != 0 {
								t.Errorf("%s config entry contains %d core definitions; native stores these only in subschema", label, len(got))
							}
							continue
						}
						for oid, want := range group.want {
							if !reflect.DeepEqual(got[oid], want) {
								t.Errorf("%s %s metadata mismatch: got=%v want=%v", label, oid, got[oid], want)
							}
						}
					}
				}
			})
		}
	}
}

// Compare values without ever including entry content (which may contain root
// credentials or private keys) in errors. These snapshots stay in memory only.
func configurationSchemaReferenceValues(t *testing.T, result *ldap.SearchResult) map[string][]string {
	t.Helper()
	values := map[string][]string{}
	for _, entry := range result.Entries {
		for _, attribute := range entry.Attributes {
			key := strings.ToLower(entry.DN + "\n" + attribute.Name)
			if _, duplicate := values[key]; duplicate {
				t.Fatal("duplicate search attribute")
			}
			values[key] = slices.Clone(attribute.Values)
			slices.Sort(values[key])
		}
	}
	return values
}

func configurationSchemaReferenceQueries(t *testing.T, nativeURI, goURI string, attributes, classes map[string]configurationSchemaReferenceDescription) {
	t.Helper()
	for _, authenticated := range []bool{true, false} {
		t.Run(fmt.Sprintf("admin=%t", authenticated), func(t *testing.T) {
			connections := []*ldap.Conn{
				configurationSchemaReferenceClient(t, nativeURI, authenticated),
				configurationSchemaReferenceClient(t, goURI, authenticated),
			}
			for _, group := range []struct {
				attribute, oid string
				catalog        map[string]configurationSchemaReferenceDescription
			}{
				{"attributeTypes", "2.5.21.5", attributes},
				{"objectClasses", "2.5.21.6", classes},
			} {
				var oids []string
				for oid := range group.catalog {
					oids = append(oids, oid)
				}
				slices.Sort(oids)
				for _, oid := range oids {
					definition := group.catalog[oid]
					for _, assertion := range append([]string{oid}, definition.Fields["NAME"]...) {
						t.Run(group.attribute+"/"+assertion, func(t *testing.T) {
							for i, connection := range connections {
								label := []string{"native", "go"}[i]
								for _, description := range []string{group.attribute, group.oid} {
									matches, err := connection.Compare("cn=Subschema", description, assertion)
									if code := configurationSchemaReferenceCode(t, err); code != 0 || !matches {
										t.Errorf("%s Compare %s: code=%d matches=%t", label, description, code, matches)
									}
									result, code := configurationSchemaReferenceRead(t, connection, "cn=Subschema", "("+description+"="+ldap.EscapeFilter(assertion)+")", []string{"1.1"}, false)
									if code != 0 || len(result.Entries) != 1 || len(configurationSchemaReferenceValues(t, result)) != 0 {
										t.Errorf("%s schema equality filter %s: code=%d entries=%d", label, description, code, len(result.Entries))
									}
								}
							}
						})
					}
				}
			}
			for _, base := range []string{"cn=config", "olcDatabase={1}mdb,cn=config"} {
				for _, definition := range attributes {
					for _, name := range definition.Fields["NAME"] {
						t.Run(base+"/"+name, func(t *testing.T) {
							for i, connection := range connections {
								label := []string{"native", "go"}[i]
								for _, typesOnly := range []bool{false, true} {
									byName, nameCode := configurationSchemaReferenceRead(t, connection, base, "("+name+"=*)", []string{name}, typesOnly)
									byOID, oidCode := configurationSchemaReferenceRead(t, connection, base, "("+definition.OID+"=*)", []string{definition.OID}, typesOnly)
									if nameCode != oidCode || len(byName.Entries) != len(byOID.Entries) || !reflect.DeepEqual(configurationSchemaReferenceValues(t, byName), configurationSchemaReferenceValues(t, byOID)) {
										t.Errorf("%s config name/OID query differs (typesOnly=%t): codes=%d/%d", label, typesOnly, nameCode, oidCode)
									}
									if !authenticated && (nameCode != 32 || len(byName.Entries) != 0) {
										t.Errorf("%s anonymous configuration query is visible", label)
									}
								}
							}
						})
					}
				}
			}
		})
	}
}

func configurationSchemaReferenceAssertionBoundaries(t *testing.T, native, client *ldap.Conn) {
	t.Helper()
	type observation struct {
		compare, search, notSearch uint16
		entries, notEntries        int
	}
	for _, group := range []struct{ attribute, oid, known string }{
		{"attributeTypes", "2.5.21.5", "olcSizeLimit"},
		{"objectClasses", "2.5.21.6", "olcDatabaseConfig"},
	} {
		// Five assertions per schema attribute, with Compare, equality and
		// NOT in the same case. Unknown numeric OIDs are distinct from
		// unknown descriptors under the native three-valued filter logic.
		for _, test := range []struct {
			name, assertion string
			compare         uint16
			notEntries      int
		}{
			{"unknown-name", "configurationReferenceUnknown", ldap.LDAPResultCompareFalse, 0},
			{"unknown-oid", "1.3.6.1.4.1.4203.666.11.99.999999", ldap.LDAPResultCompareFalse, 1},
			{"embedded-space", "bad rule", ldap.LDAPResultInvalidAttributeSyntax, 0},
			{"surrounding-space", " " + group.known + " ", ldap.LDAPResultInvalidAttributeSyntax, 0},
			{"malformed-oid", "1..2", ldap.LDAPResultInvalidAttributeSyntax, 0},
		} {
			t.Run(group.attribute+"/"+test.name, func(t *testing.T) {
				for _, attribute := range []string{group.attribute, group.oid} {
					var reference observation
					for i, connection := range []*ldap.Conn{native, client} {
						label := []string{"native", "go"}[i]
						matched, err := connection.Compare("cn=Subschema", attribute, test.assertion)
						got := observation{compare: configurationSchemaReferenceCode(t, err)}
						if err == nil {
							got.compare = ldap.LDAPResultCompareFalse
							if matched {
								got.compare = ldap.LDAPResultCompareTrue
							}
						}
						filter := "(" + attribute + "=" + ldap.EscapeFilter(test.assertion) + ")"
						result, code := configurationSchemaReferenceRead(t, connection, "cn=Subschema", filter, []string{"1.1"}, false)
						got.search, got.entries = code, len(result.Entries)
						negated, code := configurationSchemaReferenceRead(t, connection, "cn=Subschema", "(!"+filter+")", []string{"1.1"}, false)
						got.notSearch, got.notEntries = code, len(negated.Entries)
						if len(configurationSchemaReferenceValues(t, result)) != 0 || len(configurationSchemaReferenceValues(t, negated)) != 0 {
							t.Errorf("%s boundary query returned unrequested attributes", label)
						}
						if i == 0 {
							reference = got
							want := observation{compare: test.compare, notEntries: test.notEntries}
							if got != want {
								t.Errorf("native %s boundary: got=%+v want=%+v", attribute, got, want)
							}
						} else if got != reference {
							t.Errorf("Go %s boundary: got=%+v native=%+v", attribute, got, reference)
						}
						t.Logf("%s %s: Compare=%d equality=%d/%d NOT=%d/%d", label, attribute, got.compare, got.search, got.entries, got.notSearch, got.notEntries)
					}
				}
			})
		}
	}
}

func configurationSchemaReferenceClassSelection(t *testing.T, native, client *ldap.Conn, classes map[string]configurationSchemaReferenceDescription) {
	t.Helper()
	byName := map[string]configurationSchemaReferenceDescription{}
	for _, class := range classes {
		for _, name := range class.Fields["NAME"] {
			byName[name] = class
		}
	}
	var allowed func(string) []string
	allowed = func(name string) []string {
		if name == "top" {
			return []string{"objectClass"}
		}
		class, found := byName[name]
		if !found {
			t.Fatalf("missing pinned class %s", name)
		}
		attributes := append(slices.Clone(class.Fields["MUST"]), class.Fields["MAY"]...)
		for _, parent := range class.Fields["SUP"] {
			attributes = append(attributes, allowed(parent)...)
		}
		return attributes
	}
	for _, base := range []string{"cn=config", "olcDatabase={1}mdb,cn=config"} {
		for _, name := range []string{"olcGlobal", "olcDatabaseConfig"} {
			for _, selector := range []string{"@" + name, "@" + byName[name].OID} {
				for _, typesOnly := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/typesOnly=%t", base, selector, typesOnly), func(t *testing.T) {
						var nativeShared map[string][]string
						for i, connection := range []*ldap.Conn{native, client} {
							label := []string{"native", "go"}[i]
							selected, code := configurationSchemaReferenceRead(t, connection, base, "(objectClass=*)", []string{selector}, typesOnly)
							explicit, explicitCode := configurationSchemaReferenceRead(t, connection, base, "(objectClass=*)", allowed(name), typesOnly)
							if code != 0 || explicitCode != 0 || len(selected.Entries) != 1 || len(explicit.Entries) != 1 || !reflect.DeepEqual(configurationSchemaReferenceValues(t, selected), configurationSchemaReferenceValues(t, explicit)) {
								t.Errorf("%s @class selection differs from inherited MUST/MAY attributes: codes=%d/%d", label, code, explicitCode)
							}
							// Native emits many process defaults that are not stored
							// in this Go fixture. Compare every selected attribute to
							// the independent class closure above, then compare the
							// explicitly shared fixture content across endpoints.
							shared := configurationSchemaReferenceValues(t, selected)
							sharedNames := []string{"cn", "olcsizelimit", "olcthreads"}
							if base != "cn=config" {
								sharedNames = []string{"olcsizelimit", "olcdatabase", "olcsuffix", "olcrootdn", "olcrootpw", "olcreadonly"}
							}
							for key := range shared {
								_, attribute, _ := strings.Cut(key, "\n")
								if !slices.Contains(sharedNames, attribute) {
									delete(shared, key)
								}
							}
							if i == 0 {
								nativeShared = shared
							} else if !reflect.DeepEqual(shared, nativeShared) {
								t.Error("Go @class selection differs from native for the shared fixture attributes")
							}
						}
					})
				}
			}
		}
	}
}

func configurationSchemaReferenceSelectors(t *testing.T, nativeURI, goURI string, attributes, classes map[string]configurationSchemaReferenceDescription) {
	t.Helper()
	for _, authenticated := range []bool{true, false} {
		for _, test := range []struct {
			name       string
			attributes []string
			want       []string
		}{
			{"default", nil, nil},
			{"user", []string{"*"}, nil},
			{"none", []string{"1.1"}, nil},
			{"operational", []string{"+"}, []string{"attributeTypes", "objectClasses"}},
			{"all", []string{"*", "+"}, []string{"attributeTypes", "objectClasses"}},
			{"names", []string{"attributeTypes", "objectClasses"}, []string{"attributeTypes", "objectClasses"}},
			{"oids", []string{"2.5.21.5", "2.5.21.6"}, []string{"attributeTypes", "objectClasses"}},
			{"attribute-only", []string{"1.1", "2.5.21.5"}, []string{"attributeTypes"}},
			{"class-only", []string{"OBJECTCLASSES"}, []string{"objectClasses"}},
			{"subschema-class", []string{"@subschema"}, []string{"attributeTypes", "objectClasses"}},
		} {
			for _, typesOnly := range []bool{false, true} {
				t.Run(fmt.Sprintf("admin=%t/%s/typesOnly=%t", authenticated, test.name, typesOnly), func(t *testing.T) {
					for i, uri := range []string{nativeURI, goURI} {
						label := []string{"native", "go"}[i]
						client := configurationSchemaReferenceClient(t, uri, authenticated)
						result, code := configurationSchemaReferenceRead(t, client, "cn=Subschema", "(objectClass=*)", test.attributes, typesOnly)
						if code != 0 || len(result.Entries) != 1 {
							t.Fatalf("%s schema selector: code=%d entries=%d", label, code, len(result.Entries))
						}
						for _, group := range []struct {
							name    string
							class   bool
							catalog map[string]configurationSchemaReferenceDescription
						}{{"attributeTypes", false, attributes}, {"objectClasses", true, classes}} {
							var found *ldap.EntryAttribute
							for _, attribute := range result.Entries[0].Attributes {
								if strings.EqualFold(attribute.Name, group.name) {
									found = attribute
								}
							}
							want := slices.Contains(test.want, group.name)
							if (found != nil) != want {
								t.Errorf("%s selector %s presence=%t want=%t", label, group.name, found != nil, want)
								continue
							}
							if found == nil {
								continue
							}
							if typesOnly {
								if len(found.Values) != 0 {
									t.Errorf("%s typesOnly returned schema values", label)
								}
								continue
							}
							got := map[string]configurationSchemaReferenceDescription{}
							for _, value := range found.Values {
								parsed := configurationSchemaReferenceParse(t, value, group.class)
								if _, core := group.catalog[parsed.OID]; core {
									got[parsed.OID] = parsed
								}
							}
							if !reflect.DeepEqual(got, group.catalog) {
								t.Errorf("%s selector changed the core schema metadata", label)
							}
						}
					}
				})
			}
		}
	}
}

func configurationSchemaReferenceTaggedRuntime(t *testing.T, nativeURI, goURI string, native, client *ldap.Conn) {
	t.Helper()
	const base = "olcDatabase={1}mdb,cn=config"
	const sizeOID = "1.3.6.1.4.1.4203.1.12.2.3.0.60"
	for i, uri := range []string{nativeURI, goURI} {
		label := []string{"native", "go"}[i]
		admin := configurationSchemaReferenceClient(t, uri, false)
		if code := configurationSchemaReferenceCode(t, admin.Bind("cn=admin,dc=example,dc=com", "secret")); code != 0 {
			t.Fatalf("%s data fixture bind: result=%d", label, code)
		}
		for n := range 4 {
			name := fmt.Sprintf("configuration-reference-%d", n)
			request := ldap.NewAddRequest("ou="+name+",dc=example,dc=com", nil)
			request.Attribute("objectClass", []string{"organizationalUnit"})
			request.Attribute("ou", []string{name})
			if code := configurationSchemaReferenceCode(t, admin.Add(request)); code != 0 {
				t.Fatalf("%s add runtime probe: result=%d", label, code)
			}
		}
		anonymous := configurationSchemaReferenceClient(t, uri, false)
		configuration := []*ldap.Conn{native, client}[i]
		for _, test := range []struct {
			name, attribute, value string
			wantCount              int
		}{
			{"base-limit", "olcSizeLimit", "3", 3},
			// The pinned backend preserves tagged values without applying
			// them to the effective size limit.
			{"tagged-name", "olcSizeLimit;lang-en", "1", 3},
			{"tagged-oid", sizeOID + ";lang-en", "2", 3},
			{"base-after-tag", "olcSizeLimit", "3", 3},
		} {
			t.Run(label+"/"+test.name, func(t *testing.T) {
				request := ldap.NewModifyRequest(base, nil)
				request.Replace(test.attribute, []string{test.value})
				if code := configurationSchemaReferenceCode(t, configuration.Modify(request)); code != 0 {
					t.Fatalf("runtime limit Modify: result=%d", code)
				}
				for _, attribute := range []string{"olcSizeLimit", sizeOID, "olcSizeLimit;lang-en", sizeOID + ";lang-en"} {
					result, code := configurationSchemaReferenceRead(t, configuration, base, "(objectClass=*)", []string{attribute}, false)
					if code != 0 || len(result.Entries) != 1 {
						t.Fatalf("tagged readback: code=%d entries=%d", code, len(result.Entries))
					}
					expected := map[string][]string{}
					key := strings.ToLower(base) + "\n"
					if !strings.Contains(attribute, ";") {
						expected[key+"olcsizelimit"] = []string{"3"}
					}
					if test.name != "base-limit" {
						tagged := "2"
						if test.name == "tagged-name" {
							tagged = "1"
						}
						expected[key+"olcsizelimit;lang-en"] = []string{tagged}
					}
					if !reflect.DeepEqual(configurationSchemaReferenceValues(t, result), expected) {
						t.Errorf("%s tagged/base readback for %s differs from the native contract", label, attribute)
					}
				}
				result, err := anonymous.Search(ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
					"(ou=configuration-reference-*)", []string{"1.1"}, nil))
				count := 0
				if result != nil {
					count = len(result.Entries)
				}
				code := configurationSchemaReferenceCode(t, err)
				t.Logf("%s effective limit: result=%d entries=%d", label, code, count)
				if code != ldap.LDAPResultSizeLimitExceeded || count != test.wantCount {
					t.Errorf("effective limit: result=%d entries=%d, want 4/%d", code, count, test.wantCount)
				}
			})
		}
	}
}
