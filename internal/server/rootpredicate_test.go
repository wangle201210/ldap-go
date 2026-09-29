package server

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
)

// Preserve isRoot from 059e82d as the return-value and callback-order oracle.
func (*Server) rootPredicateOriginal(runtime *runtimeState, rawDN, targetDN, attribute string) bool {
	if rawDN == "" {
		return false
	}
	for index := range runtime.databases {
		database := &runtime.databases[index]
		if database.rootDN == nil || !database.rootDN.DisplayEquals(rawDN) {
			continue
		}
		if targetDN == "" {
			if attribute == "children" {
				return true
			}
			continue
		}
		for _, suffix := range database.suffixes {
			if suffix.DisplaySuffixOf(targetDN) {
				return true
			}
		}
	}
	subject, err := parseRuntimeConnectionDN(runtime, rawDN)
	if err != nil {
		return false
	}
	if targetDN == "" {
		return attribute == "children" && isAnyDatabaseRoot(runtime, subject)
	}
	target, err := parseRuntimeConnectionDN(runtime, targetDN)
	if err != nil {
		return false
	}
	database := databaseForDN(runtime, target)
	return database != nil && databaseRootMatches(runtime, *database, subject)
}

const rootPredicateExactOID = "1.3.6.1.4.1.99999.966.1"

func rootPredicateNormalizer(t testing.TB, registry *schema.Registry, mode string) directory.DNAttributeNormalizer {
	t.Helper()
	switch mode {
	case "legacy":
		return nil
	case "registry":
		return registry
	case "indexed":
		return &databaseEqualityIndexNormalizer{registry: registry}
	default:
		t.Fatalf("unknown normalizer %q", mode)
		return nil
	}
}

func rootPredicateDatabase(t testing.TB, normalizer directory.DNAttributeNormalizer, suffix, root string) runtimeDatabase {
	t.Helper()
	database := runtimeDatabase{dnNormalizer: normalizer}
	if suffix != "" {
		dn, err := parseRuntimeDN(suffix, normalizer)
		if err != nil {
			t.Fatal(err)
		}
		database.suffixes = []directory.DN{dn}
	}
	if root != "" {
		dn, err := parseRuntimeDN(root, normalizer)
		if err != nil {
			t.Fatal(err)
		}
		database.rootDN = new(dn)
	}
	return database
}

func newRootPredicateRuntime(t testing.TB, mode string) *runtimeState {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ParseAndRegisterAttributeType("( " + rootPredicateExactOID +
		" NAME ( 'rootExact' 'rootAlias' ) EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"); err != nil {
		t.Fatal(err)
	}
	runtime := &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache()}
	for _, spec := range []struct{ suffix, root string }{
		{"dc=example,dc=com", "cn=Admin,dc=example,dc=com"},
		{"ou=child,dc=example,dc=com", "cn=Child,dc=example,dc=com"},
		{"dc=other,dc=com", "cn=Outside,dc=foreign,dc=com"},
		{"rootExact=Tenant,dc=example,dc=com", "rootExact=Admin+cn=Directory,rootExact=Tenant,dc=example,dc=com"},
		{"dc=hidden,dc=com", "cn=Hidden,dc=hidden,dc=com"},
		{"dc=disabled,dc=com", "cn=Disabled,dc=disabled,dc=com"},
		{"dc=noroot,dc=com", ""},
		{"", "cn=Suffixless,dc=foreign,dc=com"},
	} {
		runtime.databases = append(runtime.databases,
			rootPredicateDatabase(t, rootPredicateNormalizer(t, registry, mode), spec.suffix, spec.root))
	}
	runtime.databases[4].hidden = true
	runtime.databases[5].disabled = true
	runtime.databases = append(runtime.databases, rootPredicateDatabase(t, nil, "cn=config", "cn=admin,cn=config"))
	return runtime
}

func TestRootPredicateReference(t *testing.T) {
	const base = "dc=example,dc=com"
	const exactBase = "rootExact=Tenant," + base
	const aliasRoot = "rootAlias=Admin+2.5.4.3=DIRECTORY,rootAlias=Tenant," + base
	for _, mode := range []string{"legacy", "registry", "indexed"} {
		t.Run(mode, func(t *testing.T) {
			runtime := newRootPredicateRuntime(t, mode)
			if !localProjectionReadOnly(runtime, nil) {
				t.Fatal("fixture must permit the pure guard")
			}
			for _, test := range []struct {
				name, subject, target, attribute string
				want                             bool
			}{
				{"anonymous", "", "uid=user," + base, "entry", false},
				{"nonroot", "uid=reader," + base, "uid=user," + base, "entry", false},
				{"nonroot-unrouted", "uid=reader,dc=foreign,dc=com", "uid=user," + base, "entry", false},
				{"invalid-subject", "not-a-dn", "uid=user," + base, "entry", false},
				{"undefined-subject", "undefinedName=reader," + base, "uid=user," + base, "entry", false},
				{"literal-root", "cn=Admin," + base, "uid=user," + base, "entry", true},
				{"folded-root", "CN=ADMIN,DC=EXAMPLE,DC=COM", "uid=user," + base, "entry", true},
				{"oid-root", "2.5.4.3=ADMIN," + base, "uid=user," + base, "entry", true},
				{"escaped-root", `cn=\41dmin,` + base, "uid=user," + base, "entry", true},
				{"different-database", "CN=ADMIN," + base, "uid=user,dc=other,dc=com", "entry", false},
				{"longest-suffix", "CN=ADMIN," + base, "uid=user,ou=child," + base, "entry", false},
				// The existing literal fast path precedes routing and validation.
				{"literal-parent-root", "cn=Admin," + base, "uid=user,ou=child," + base, "entry", true},
				{"root-in-other-suffix", "CN=CHILD," + base, "uid=user,ou=child," + base, "entry", true},
				{"root-outside-suffixes", "CN=OUTSIDE,dc=foreign,dc=com", "uid=user,dc=other,dc=com", "entry", true},
				{"root-outside-wrong-target", "CN=OUTSIDE,dc=foreign,dc=com", "uid=user," + base, "entry", false},
				{"exact-root-alias-multiava", aliasRoot, "uid=user,rootAlias=Tenant," + base, "entry", true},
				{"exact-root-oid", rootPredicateExactOID + "=Admin+cn=Directory," + exactBase, "uid=user," + exactBase, "entry", true},
				{"exact-value-mismatch", "rootAlias=admin+cn=Directory," + exactBase, "uid=user," + exactBase, "entry", false},
				{"exact-suffix-mismatch", aliasRoot, "uid=user,rootAlias=tenant," + base, "entry", false},
				{"hidden-literal", "cn=Hidden,dc=hidden,dc=com", "uid=user,dc=hidden,dc=com", "entry", true},
				{"hidden-normalized", "CN=HIDDEN,dc=hidden,dc=com", "uid=user,dc=hidden,dc=com", "entry", false},
				{"disabled-literal", "cn=Disabled,dc=disabled,dc=com", "uid=user,dc=disabled,dc=com", "entry", true},
				{"disabled-normalized", "CN=DISABLED,dc=disabled,dc=com", "uid=user,dc=disabled,dc=com", "entry", false},
				{"hidden-root-children", "CN=HIDDEN,dc=hidden,dc=com", "", "children", true},
				{"disabled-root-children", "CN=DISABLED,dc=disabled,dc=com", "", "children", true},
				{"suffixless-root-children", "CN=SUFFIXLESS,dc=foreign,dc=com", "", "children", true},
				{"suffixless-root-target", "CN=SUFFIXLESS,dc=foreign,dc=com", "uid=user," + base, "entry", false},
				{"literal-root-children", "cn=Admin," + base, "", "children", true},
				{"normalized-root-children", "CN=ADMIN," + base, "", "children", true},
				{"alias-root-children", aliasRoot, "", "children", true},
				{"nonroot-children", "uid=reader," + base, "", "children", false},
				{"empty-target-entry", "CN=ADMIN," + base, "", "entry", false},
				{"empty-target-attribute-case", "CN=ADMIN," + base, "", "Children", false},
				{"config-root", "CN=ADMIN,CN=CONFIG", "olcDatabase={1}mdb,cn=config", "entry", true},
				{"config-nonroot", "cn=reader,cn=config", "olcDatabase={1}mdb,cn=config", "entry", false},
				{"missing-database", "CN=ADMIN," + base, "uid=user,dc=missing,dc=com", "entry", false},
				{"database-without-root", "CN=ADMIN," + base, "uid=user,dc=noroot,dc=com", "entry", false},
				{"invalid-target-nonroot", "uid=reader," + base, "not-a-dn", "entry", false},
				{"invalid-target-root", "CN=ADMIN," + base, "not-a-dn", "entry", false},
				{"invalid-prefix-literal-root", "cn=Admin," + base, "broken," + base, "entry", true},
				{"invalid-prefix-normalized-root", "CN=ADMIN," + base, "broken," + base, "entry", false},
				{"schema-invalid-target-nonroot", "uid=reader," + base, "undefinedName=user," + base, "entry", false},
				{"schema-invalid-target-root", "CN=ADMIN," + base, "undefinedName=user," + base, "entry", false},
			} {
				t.Run(test.name, func(t *testing.T) {
					for _, cache := range []*runtimeLegacyDNCache{nil, newRuntimeLegacyDNCache()} {
						runtime.legacyDNs = cache
						for range 2 {
							got := new(Server).isRoot(runtime, test.subject, test.target, test.attribute)
							want := new(Server).rootPredicateOriginal(runtime, test.subject, test.target, test.attribute)
							if got != want || (mode != "legacy" && want != test.want) {
								t.Fatalf("isRoot = %t, original = %t, schema expectation = %t", got, want, test.want)
							}
						}
					}
				})
			}
		})
	}
}

func TestRootPredicateIdentityHintReference(t *testing.T) {
	for _, mode := range []string{"registry", "indexed"} {
		t.Run(mode, func(t *testing.T) {
			runtime := newRootPredicateRuntime(t, mode)
			for _, raw := range []string{
				"CN=ADMIN,DC=EXAMPLE,DC=COM",
				"2.5.4.3=ADMIN,dc=example,dc=com",
				"rootAlias=Admin+2.5.4.3=DIRECTORY,rootAlias=Tenant,dc=example,dc=com",
			} {
				subject, err := parseRuntimeConnectionDN(runtime, raw)
				if err != nil || !rootIdentityMayMatch(runtime, subject) {
					t.Fatalf("normalized root %q must decline the negative scan: %v", raw, err)
				}
			}

			// The owning database uses schema equality, but the root's suffix
			// routes subject parsing through a different, legacy database.
			root, err := parseRuntimeDN("rootExact=Admin,dc=other,dc=com", runtime.databases[0].dnNormalizer)
			if err != nil {
				t.Fatal(err)
			}
			runtime.databases[0].rootDN = new(root)
			runtime.databases[2].dnNormalizer = nil
			if !localProjectionReadOnly(runtime, nil) {
				t.Fatal("mixed identities must still exercise the pure guard")
			}
			for _, test := range []struct {
				name, subject, target string
				hint, anyRoot, want   bool
			}{
				{"matching-root", "rootExact=Admin,dc=other,dc=com", "uid=user,dc=example,dc=com", true, true, true},
				{"alias-hint-miss", "rootAlias=Admin,dc=other,dc=com", "uid=user,dc=example,dc=com", false, true, true},
				{"caseexact-hint-overmatch", "rootExact=admin,dc=other,dc=com", "uid=user,dc=example,dc=com", true, false, false},
				{"wrong-target", "rootExact=Admin,dc=other,dc=com", "uid=user,dc=noroot,dc=com", true, true, false},
				{"invalid-target", "rootExact=Admin,dc=other,dc=com", "not-a-dn", true, true, false},
				{"nonroot", "uid=reader,dc=other,dc=com", "uid=user,dc=example,dc=com", false, false, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					subject, err := parseRuntimeConnectionDN(runtime, test.subject)
					if err != nil {
						t.Fatal(err)
					}
					if hint, anyRoot := rootIdentityMayMatch(runtime, subject), isAnyDatabaseRoot(runtime, subject); hint != test.hint || anyRoot != test.anyRoot {
						t.Fatalf("identity hint/root predicate = %t/%t, want %t/%t", hint, anyRoot, test.hint, test.anyRoot)
					}
					got := new(Server).isRoot(runtime, test.subject, test.target, "entry")
					want := new(Server).rootPredicateOriginal(runtime, test.subject, test.target, "entry")
					if got != want || want != test.want {
						t.Fatalf("isRoot = %t, original = %t, want %t", got, want, test.want)
					}
				})
			}
		})
	}
}

func TestRootPredicateZeroIdentityReference(t *testing.T) {
	for _, mode := range []string{"legacy", "registry", "indexed"} {
		t.Run(mode, func(t *testing.T) {
			runtime := newRootPredicateRuntime(t, mode)
			if !localProjectionReadOnly(runtime, nil) {
				t.Fatal("zero-identity fixture must exercise the pure guard")
			}
			if !rootIdentityMayMatch(runtime, directory.DN{}) {
				t.Fatal("a zero subject must decline the negative scan")
			}
			runtime.databases[0].rootDN = new(directory.DN)
			for _, test := range []struct {
				name, subject, target, attribute string
				want                             bool
			}{
				{"nonempty-subject", "uid=reader,dc=example,dc=com", "uid=user,dc=example,dc=com", "entry", false},
				{"nonempty-invalid-target", "uid=reader,dc=example,dc=com", "not-a-dn", "entry", false},
				{"nonempty-children", "uid=reader,dc=example,dc=com", "", "children", false},
				{"space-subject", " ", "uid=user,dc=example,dc=com", "entry", true},
				{"spaces-subject", "  ", "uid=user,dc=example,dc=com", "entry", true},
				{"space-invalid-target", " ", "not-a-dn", "entry", false},
				{"space-target", " ", " ", "entry", false},
				{"space-children", " ", "", "children", true},
				{"space-empty-target-entry", " ", "", "entry", false},
				{"anonymous", "", "uid=user,dc=example,dc=com", "entry", false},
				{"anonymous-children", "", "", "children", false},
			} {
				t.Run(test.name, func(t *testing.T) {
					subject, err := parseRuntimeConnectionDN(runtime, test.subject)
					if err != nil {
						t.Fatal(err)
					}
					if !rootIdentityMayMatch(runtime, subject) {
						t.Fatal("a zero configured root must decline the negative scan")
					}
					for range 2 {
						want := new(Server).rootPredicateOriginal(runtime, test.subject, test.target, test.attribute)
						got := new(Server).isRoot(runtime, test.subject, test.target, test.attribute)
						if got != want || want != test.want {
							t.Fatalf("isRoot = %t, original = %t, want %t", got, want, test.want)
						}
					}
				})
			}
		})
	}
}

func TestRootPredicateFallbackReference(t *testing.T) {
	for _, mode := range []string{"no-schema", "different-registry", "different-index-registry", "relay", "rwm", "relay-rwm"} {
		t.Run(mode, func(t *testing.T) {
			runtime := newRootPredicateRuntime(t, "legacy")
			switch mode {
			case "no-schema":
				runtime.schema = nil
			case "different-registry":
				runtime.databases[4].dnNormalizer = runtime.schema.Clone()
			case "different-index-registry":
				runtime.databases[5].dnNormalizer = &databaseEqualityIndexNormalizer{registry: runtime.schema.Clone()}
			case "relay", "rwm", "relay-rwm":
				if mode != "rwm" {
					runtime.databases[0].relay = &relayRuntimeConfiguration{targetDatabaseIndex: 2}
				}
				if mode != "relay" {
					runtime.databases[0].rwm = &rwmRuntimeConfiguration{suffix: &rwmSuffixMapping{
						local: staticRuntimeDN("dc=example,dc=com"), remote: staticRuntimeDN("dc=foreign,dc=com"),
					}}
				}
			}
			if localProjectionReadOnly(runtime, nil) {
				t.Fatal("fixture must retain the original path")
			}
			for _, subject := range []string{"", "uid=reader,dc=example,dc=com", "CN=ADMIN,dc=example,dc=com",
				"CN=OUTSIDE,dc=example,dc=com", "CN=OUTSIDE,dc=foreign,dc=com", "not-a-dn"} {
				for _, target := range []string{"", "uid=user,dc=example,dc=com", "uid=user,dc=other,dc=com", "not-a-dn"} {
					for _, attribute := range []string{"entry", "children"} {
						got := new(Server).isRoot(runtime, subject, target, attribute)
						if want := new(Server).rootPredicateOriginal(runtime, subject, target, attribute); got != want {
							t.Fatalf("isRoot(%q, %q, %q) = %t, original = %t", subject, target, attribute, got, want)
						}
					}
				}
			}
		})
	}
}

type rootPredicateCallbackTrace struct {
	calls   []string
	failAt  int
	failure error
}

func (trace *rootPredicateCallbackTrace) record(call string) error {
	trace.calls = append(trace.calls, call)
	if len(trace.calls) == trace.failAt {
		return trace.failure
	}
	return nil
}

type rootPredicateRecordingNormalizer struct {
	*schema.Registry
	trace *rootPredicateCallbackTrace
	name  string
}

func (normalizer rootPredicateRecordingNormalizer) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	if err := normalizer.trace.record(fmt.Sprintf("%s:value:%s=%q", normalizer.name, attribute, value)); err != nil {
		return "", nil, err
	}
	return normalizer.Registry.NormalizeDNAttribute(attribute, value)
}

func (normalizer rootPredicateRecordingNormalizer) CanonicalDNAttributeName(attribute string) (string, error) {
	if err := normalizer.trace.record(normalizer.name + ":name:" + attribute); err != nil {
		return "", err
	}
	return normalizer.Registry.CanonicalDNAttributeName(attribute)
}

type rootPredicateRecordingParser struct {
	rootPredicateRecordingNormalizer
	zeroRaw string
}

func (parser rootPredicateRecordingParser) ParseDNIdentity(raw string) (directory.DN, error) {
	if err := parser.trace.record(parser.name + ":parse:" + raw); err != nil {
		return directory.DN{}, err
	}
	if parser.zeroRaw != "" && raw == parser.zeroRaw {
		return directory.DN{}, nil
	}
	return parser.Registry.NormalizeDN(raw)
}

func TestRootPredicateCallbackTraceAndErrors(t *testing.T) {
	for _, mode := range []string{"attributes", "parser", "zero-parser", "indexed-custom-registry", "hidden-custom", "disabled-custom"} {
		t.Run(mode, func(t *testing.T) {
			runtime := newRootPredicateRuntime(t, "indexed")
			trace := new(rootPredicateCallbackTrace)
			for index := range runtime.databases {
				if (mode == "hidden-custom" && index != 4) || (mode == "disabled-custom" && index != 5) {
					continue
				}
				normalizer := rootPredicateRecordingNormalizer{runtime.schema, trace, fmt.Sprintf("db%d", index)}
				switch mode {
				case "parser", "zero-parser":
					parser := rootPredicateRecordingParser{rootPredicateRecordingNormalizer: normalizer}
					if mode == "zero-parser" {
						// Routing pretty-prints its input; only final subject parsing
						// returns zero. The original rejects the invalid target next.
						parser.zeroRaw = "uid=reader, dc=example, dc=com"
					}
					runtime.databases[index].dnNormalizer = parser
				case "indexed-custom-registry":
					runtime.databases[index].dnNormalizer = &databaseEqualityIndexNormalizer{registry: normalizer}
				default:
					runtime.databases[index].dnNormalizer = normalizer
				}
			}
			if localProjectionReadOnly(runtime, nil) {
				t.Fatal("custom callbacks must disable the guard even in hidden/disabled databases")
			}
			recordedCallbacks := 0
			for _, test := range []struct{ subject, target, attribute string }{
				{"uid=reader,dc=example,dc=com", "uid=target,dc=example,dc=com", "entry"},
				{"CN=ADMIN,dc=example,dc=com", "uid=target,dc=example,dc=com", "entry"},
				{"cn=Admin,dc=example,dc=com", "broken,dc=example,dc=com", "entry"},
				{"CN=HIDDEN,dc=hidden,dc=com", "", "children"},
				{"CN=DISABLED,dc=disabled,dc=com", "", "children"},
				{"uid=reader,dc=example,dc=com", "undefinedName=target,dc=example,dc=com", "entry"},
				{"uid=reader,dc=example,dc=com", "not-a-dn", "entry"},
				{"uid=reader, dc=example, dc=com", "not-a-dn", "entry"},
				{"not-a-dn", "uid=target,dc=example,dc=com", "entry"},
				{"CN=ADMIN,dc=example,dc=com", "", "entry"},
			} {
				*trace = rootPredicateCallbackTrace{}
				new(Server).rootPredicateOriginal(runtime, test.subject, test.target, test.attribute)
				baseline := slices.Clone(trace.calls)
				recordedCallbacks += len(baseline)
				if test.subject == "uid=reader,dc=example,dc=com" && test.target == "uid=target,dc=example,dc=com" {
					if mode == "hidden-custom" || mode == "disabled-custom" {
						if len(baseline) != 0 {
							t.Fatal("original target routing must skip hidden/disabled callbacks")
						}
					} else if !slices.ContainsFunc(baseline, func(call string) bool { return strings.Contains(call, "target") }) {
						t.Fatal("fixture must exercise target normalization callbacks")
					}
				}
				// Fail each original callback in turn, change the error, then recover
				// on the same runtime so warm syntax caches cannot conceal effects.
				for failAt := 0; failAt <= len(baseline); failAt++ {
					for _, failure := range []error{errors.New("first failure"), errors.New("changed failure"), nil} {
						*trace = rootPredicateCallbackTrace{failAt: failAt, failure: failure}
						want := new(Server).rootPredicateOriginal(runtime, test.subject, test.target, test.attribute)
						wantCalls := slices.Clone(trace.calls)
						for range 2 {
							trace.calls = nil
							got := new(Server).isRoot(runtime, test.subject, test.target, test.attribute)
							if got != want || !slices.Equal(trace.calls, wantCalls) {
								t.Fatalf("isRoot(%q, %q, %q), failAt=%d, error=%v: got %t/%v, original %t/%v",
									test.subject, test.target, test.attribute, failAt, failure, got, trace.calls, want, wantCalls)
							}
						}
					}
				}
			}
			if recordedCallbacks == 0 {
				t.Fatal("fixture did not exercise custom callbacks")
			}
		})
	}
}

func TestRootPredicateReevaluatesConfiguration(t *testing.T) {
	runtime := newRootPredicateRuntime(t, "indexed")
	const subject = "UID=READER,dc=example,dc=com"
	const target = "uid=user,dc=example,dc=com"
	original := runtime.databases[0].rootDN
	root, err := parseRuntimeDN(subject, runtime.databases[0].dnNormalizer)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		root *directory.DN
		want bool
	}{{original, false}, {new(root), true}, {nil, false}, {new(root), true}, {original, false}} {
		runtime.databases[0].rootDN = test.root
		for range 2 {
			if got := new(Server).isRoot(runtime, subject, target, "entry"); got != test.want {
				t.Fatalf("isRoot after root configuration change = %t, want %t", got, test.want)
			}
		}
	}
}

func BenchmarkRootPredicate(b *testing.B) {
	for _, mode := range []string{"legacy", "registry", "indexed"} {
		for _, databaseCount := range []int{1, 8, 32} {
			for _, identity := range []string{"nonroot", "root-literal", "root-normalized"} {
				for _, distribution := range []string{"hot", "distributed"} {
					for _, implementation := range []string{"original", "guard"} {
						b.Run(fmt.Sprintf("%s/dbs=%d/%s/%s/%s", mode, databaseCount, identity, distribution, implementation), func(b *testing.B) {
							registry, err := schema.NewBuiltinRegistry()
							if err != nil {
								b.Fatal(err)
							}
							runtime := &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache()}
							for index := range databaseCount {
								suffix := fmt.Sprintf("dc=tenant%d,dc=com", index)
								runtime.databases = append(runtime.databases,
									rootPredicateDatabase(b, rootPredicateNormalizer(b, registry, mode), suffix, "cn=Admin,"+suffix))
							}
							if !localProjectionReadOnly(runtime, nil) {
								b.Fatal("benchmark must exercise the pure guard")
							}
							count := 1
							if distribution == "distributed" {
								count = 1024 // Exceeds both 128-entry DN caches without per-iteration formatting.
							}
							subjects, targets := make([]string, count), make([]string, count)
							for index := range count {
								database := runtime.databases[(databaseCount-1+index)%databaseCount]
								suffix := database.suffixes[0].String()
								switch identity {
								case "nonroot":
									subjects[index] = fmt.Sprintf("uid=reader%d,%s", index, suffix)
								case "root-literal":
									subjects[index] = database.rootDN.String()
								case "root-normalized":
									subjects[index] = strings.ToUpper(database.rootDN.String())
								}
								targets[index] = fmt.Sprintf("uid=target%d,%s", index, suffix)
							}
							server := new(Server)
							predicate := (*Server).rootPredicateOriginal
							if implementation == "guard" {
								predicate = (*Server).isRoot
							}
							want := identity != "nonroot"
							// Each implementation gets its own runtime and identical warmup.
							for index := range count {
								if got := predicate(server, runtime, subjects[index], targets[index], "entry"); got != want {
									b.Fatalf("fixture result = %t, want %t", got, want)
								}
							}
							b.ReportAllocs()
							index := 0
							for b.Loop() {
								if got := predicate(server, runtime, subjects[index], targets[index], "entry"); got != want {
									b.Fatalf("isRoot = %t, want %t", got, want)
								}
								index = (index + 1) % count
							}
						})
					}
				}
			}
		}
	}
}
