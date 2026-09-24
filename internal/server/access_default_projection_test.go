package server

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

// Copy of attributesWithPrivilege before default-policy projection reuse. Keep
// the per-value allowed calls as the oracle, including their observable effects.
func originalAttributesWithPrivilege(
	server *Server,
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
	entry directory.Entry,
	privilege acl.Privilege,
	typesOnly bool,
) directory.Entry {
	subject := accessSubject(reader, subjectDN)
	if server.isRoot(runtime, subject.DN, entry.DN, "") {
		return rootVisibleEntry(entry, typesOnly)
	}
	filtered := directory.Entry{DN: entry.DN}
	for _, attribute := range entry.Attributes {
		if typesOnly {
			if server.allowed(
				runtime,
				reader,
				subjectDN,
				entry,
				attribute.Description,
				nil,
				privilege,
			) {
				filtered.Attributes = append(filtered.Attributes, directory.Attribute{
					Description: attribute.Description,
				})
			}
			continue
		}
		selected := directory.Attribute{Description: attribute.Description}
		for _, value := range attribute.Values {
			if server.allowed(
				runtime,
				reader,
				subjectDN,
				entry,
				attribute.Description,
				value,
				privilege,
			) {
				selected.Values = append(selected.Values, value)
			}
		}
		if len(attribute.Values) == 0 && server.allowed(
			runtime,
			reader,
			subjectDN,
			entry,
			attribute.Description,
			nil,
			privilege,
		) {
			filtered.Attributes = append(filtered.Attributes, selected)
			continue
		}
		if len(selected.Values) > 0 {
			filtered.Attributes = append(filtered.Attributes, selected)
		}
	}
	return filtered
}

func defaultProjectionRuntime(t testing.TB) *runtimeState {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	return &runtimeState{
		schema: registry,
		access: acl.DefaultPolicy(),
		databases: []runtimeDatabase{
			{
				name: "{0}config", suffixes: []directory.DN{staticRuntimeDN("cn=config")},
				rootDN: new(staticRuntimeDN("cn=config")),
			},
			{
				name: "{1}mdb", partition: "projection-test",
				suffixes:     []directory.DN{staticRuntimeDN("dc=example,dc=com")},
				rootDN:       new(staticRuntimeDN("cn=admin,dc=example,dc=com")),
				dnNormalizer: &databaseEqualityIndexNormalizer{registry: registry},
			},
		},
	}
}

func defaultProjectionRules(t testing.TB, raw ...string) []acl.Rule {
	t.Helper()
	rules := make([]acl.Rule, len(raw))
	for index, value := range raw {
		rule, err := acl.ParseRule(value)
		if err != nil {
			t.Fatal(err)
		}
		rules[index] = rule
	}
	return rules
}

func defaultProjectionPolicy(t testing.TB, global []acl.Rule, databases map[string][]acl.Rule) *acl.Policy {
	t.Helper()
	policy, err := acl.NewPolicy(global, databases)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func defaultProjectionEntry() directory.Entry {
	return directory.Entry{
		DN: "cn=projection,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "cn", Values: [][]byte{[]byte("projection")}, RawNormalized: true},
			{Description: "description", Values: [][]byte{[]byte("public"), []byte("classified"), []byte("other")}},
			{Description: "member", Values: [][]byte{[]byte("uid=a,dc=example,dc=com"), []byte("uid=b,dc=example,dc=com")}, RawNormalized: true},
			{Description: "mail", Values: nil},
			{Description: "telephoneNumber", Values: make([][]byte, 0, 3), RawNormalized: true},
			{Description: "description;lang-en", Values: [][]byte{nil, {}, []byte("text")}},
		},
	}.WithNormalizedDNHint(staticRuntimeDN("cn=stale-hint,dc=example,dc=com"), "stale-order")
}

func assertDefaultProjectionEqual(t *testing.T, got, want directory.Entry) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projection differs:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestDefaultProjectionReference(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		t.Run(backend, func(t *testing.T) {
			var store storage.Store
			if backend == "memory" {
				store = storage.NewMemory()
			} else {
				var err error
				store, err = storage.OpenBolt(filepath.Join(t.TempDir(), "projection.db"))
				if err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { _ = store.Close() })
			runtime := defaultProjectionRuntime(t)
			server := &Server{}
			policies := []*acl.Policy{
				acl.DefaultPolicy(),
				defaultProjectionPolicy(t, nil, map[string][]acl.Rule{
					"dc=example,dc=com": {}, "cn=config": nil, "dc=elsewhere": {},
				}),
			}
			check := func(reader storage.Reader) {
				t.Helper()
				for policyIndex, policy := range policies {
					runtime.access = policy
					for _, dn := range []string{
						"cn=projection,dc=example,dc=com", "CN=Projection,DC=EXAMPLE,DC=COM",
						"cn=config", "cn=child,cn=config", "2.5.4.3=config", "",
						"cn=broken,", "cn", "member=broken,dc=com", "cn=\xff",
					} {
						for _, subject := range []string{"", "uid=reader,dc=example,dc=com", "invalid-subject"} {
							for _, privilege := range []acl.Privilege{0, acl.Auth, acl.Compare, acl.Search, acl.Read, acl.Write, acl.Manage, acl.Read | acl.WriteAdd} {
								for _, typesOnly := range []bool{false, true} {
									entry := defaultProjectionEntry()
									entry.DN = dn
									for _, attributes := range [][]directory.Attribute{nil, {}, entry.Attributes} {
										entry.Attributes = attributes
										got := server.attributesWithPrivilege(runtime, reader, subject, entry, privilege, typesOnly)
										want := originalAttributesWithPrivilege(server, runtime, reader, subject, entry, privilege, typesOnly)
										if !reflect.DeepEqual(got, want) {
											t.Fatalf("reader=%T policy=%d DN=%q subject=%q privilege=%d typesOnly=%t\n got: %#v\nwant: %#v", reader, policyIndex, dn, subject, privilege, typesOnly, got, want)
										}
									}
								}
							}
						}
					}
				}
			}
			ctx := withACLSubject(t.Context(), acl.Subject{
				DN: "cn=config", RealDN: "cn=real", SSF: 256, TLSSSF: 128, PeerName: "IP=127.0.0.1",
			})
			if err := store.View(ctx, func(reader storage.Reader) error {
				check(reader)
				contextual := accessReaderFromContext(ctx, reader)
				check(contextual)
				check(storageRevisionReader{Reader: contextual, revision: 3})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.Update(ctx, func(writer storage.Writer) error {
				check(accessWriterFromContext(ctx, writer))
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDefaultProjectionOwnership(t *testing.T) {
	runtime := defaultProjectionRuntime(t)
	entry := defaultProjectionEntry()
	got := (&Server{}).attributesWithPrivilege(runtime, nil, "", entry, acl.Read, false)
	assertDefaultProjectionEqual(t, got, originalAttributesWithPrivilege(&Server{}, runtime, nil, "", entry, acl.Read, false))
	if _, ok := got.DNIdentity(); ok {
		t.Fatal("projection retained DN identity")
	}
	if _, ok := got.NormalizedDNHint(); ok {
		t.Fatal("projection retained normalized DN")
	}
	if _, ok := got.DNOrderKeyHint(); ok {
		t.Fatal("projection retained DN order key")
	}
	for index, attribute := range got.Attributes {
		if attribute.RawNormalized {
			t.Fatal("projection retained RawNormalized")
		}
		if len(entry.Attributes[index].Values) == 0 && attribute.Values != nil {
			t.Fatal("empty value descriptor slice must become nil")
		}
		for valueIndex, value := range attribute.Values {
			original := entry.Attributes[index].Values[valueIndex]
			if len(value) > 0 && &value[0] != &original[0] {
				t.Fatal("projection copied borrowed bytes")
			}
		}
	}
	got.Attributes[0].Description = "changed"
	got.Attributes[0].Values[0] = []byte("replacement")
	if entry.Attributes[0].Description != "cn" || string(entry.Attributes[0].Values[0]) != "projection" {
		t.Fatal("projection shared attribute/value descriptors")
	}
	got.Attributes[1].Values[0][0] = 'P'
	if string(entry.Attributes[1].Values[0]) != "Public" {
		t.Fatal("projection no longer borrows value bytes")
	}
}

func TestDefaultProjectionPolicyProof(t *testing.T) {
	runtime := defaultProjectionRuntime(t)
	rules := defaultProjectionRules(t, "to * by * read")
	for _, test := range []struct {
		name   string
		policy *acl.Policy
		proof  bool
	}{
		{"default", acl.DefaultPolicy(), true},
		{"empty-databases", defaultProjectionPolicy(t, nil, map[string][]acl.Rule{"dc=com": {}, "cn=config": nil}), true},
		{"global", defaultProjectionPolicy(t, rules, nil), false},
		{"matching-database", defaultProjectionPolicy(t, nil, map[string][]acl.Rule{"dc=example,dc=com": rules}), false},
		{"unrelated-database", defaultProjectionPolicy(t, nil, map[string][]acl.Rule{"dc=elsewhere": rules}), false},
		{"shadowed-database", defaultProjectionPolicy(t, nil, map[string][]acl.Rule{"dc=example,dc=com": {}, "dc=com": rules}), false},
		{"nil", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, dn := range []string{"cn=projection,dc=example,dc=com", "cn=config", "cn=child,cn=config", "cn=broken,"} {
				for _, required := range []acl.Privilege{0, acl.Read, acl.Write, acl.Manage} {
					normalizer := aclDNNormalizer{Registry: runtime.schema}
					allowed, applicable := test.policy.DefaultDNAllowed(dn, normalizer, required)
					if applicable != test.proof || !applicable && allowed {
						t.Fatalf("DN=%q: allowed=%t applicable=%t, want proof=%t", dn, allowed, applicable, test.proof)
					}
					if applicable {
						want := test.policy.Allowed(acl.Subject{}, acl.Target{Entry: directory.Entry{DN: dn}, DNNormalizer: normalizer}, required, nil)
						if allowed != want || dn == "cn=broken," && allowed {
							t.Fatalf("DN=%q required=%d: allowed=%t want=%t", dn, required, allowed, want)
						}
					}
				}
			}
		})
	}
}

func TestDefaultProjectionRootAndRootDSE(t *testing.T) {
	runtime := defaultProjectionRuntime(t)
	server := &Server{}
	for _, subject := range []string{"cn=config", "CN=CONFIG", "cn=admin,dc=example,dc=com", "CN=ADMIN,DC=EXAMPLE,DC=COM"} {
		for _, dn := range []string{"cn=config", "cn=child,cn=config", "cn=projection,dc=example,dc=com", ""} {
			for _, typesOnly := range []bool{false, true} {
				entry := defaultProjectionEntry()
				entry.DN = dn
				entry.Attributes = append(entry.Attributes, directory.Attribute{Description: "children"})
				got := server.attributesWithPrivilege(runtime, nil, subject, entry, acl.Write, typesOnly)
				want := originalAttributesWithPrivilege(server, runtime, nil, subject, entry, acl.Write, typesOnly)
				assertDefaultProjectionEqual(t, got, want)
				if dn == "" && (len(got.Attributes) != 1 || got.Attributes[0].Description != "children") {
					t.Fatal("root DSE children exception was lost")
				}
			}
		}
	}
	entry := defaultProjectionEntry()
	got := server.attributesWithPrivilege(runtime, nil, "cn=admin,dc=example,dc=com", entry, acl.Manage, false)
	assertDefaultProjectionEqual(t, got, entry)
	if &got.Attributes[0] != &entry.Attributes[0] {
		t.Fatal("root shortcut no longer returns the original entry")
	}
}

type defaultProjectionContextReader struct {
	storage.Reader
	calls  int
	onCall func(int)
}

func (reader *defaultProjectionContextReader) AccessContext() any {
	reader.calls++
	if reader.onCall != nil {
		reader.onCall(reader.calls)
	}
	return acl.Subject{DN: "cn=config", RealDN: "uid=real,dc=example,dc=com", SSF: reader.calls % 2}
}

func TestDefaultProjectionCustomContextFallback(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		for _, typesOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("wrapped=%t/typesOnly=%t", wrapped, typesOnly), func(t *testing.T) {
				runtime := defaultProjectionRuntime(t)
				deny := defaultProjectionPolicy(t, defaultProjectionRules(t, "to * by * none"), nil)
				entry := defaultProjectionEntry()
				project := func(original bool) (directory.Entry, int) {
					runtime.access = acl.DefaultPolicy()
					custom := &defaultProjectionContextReader{onCall: func(call int) {
						if call == 3 {
							runtime.access = deny
						}
					}}
					var reader storage.Reader = custom
					if wrapped {
						reader = storageRevisionReader{Reader: reader}
					}
					if original {
						return originalAttributesWithPrivilege(&Server{}, runtime, reader, "", entry, acl.Read, typesOnly), custom.calls
					}
					return (&Server{}).attributesWithPrivilege(runtime, reader, "", entry, acl.Read, typesOnly), custom.calls
				}
				want, wantCalls := project(true)
				got, calls := project(false)
				assertDefaultProjectionEqual(t, got, want)
				if calls != wantCalls || calls <= 3 || len(got.Attributes) != 1 {
					t.Fatalf("custom context calls=%d want=%d attributes=%d", calls, wantCalls, len(got.Attributes))
				}
			})
		}
	}
}

type defaultProjectionGroupReader struct {
	storage.Reader
	calls []string
}

func (reader *defaultProjectionGroupReader) Get(dn directory.DN) (directory.Entry, error) {
	reader.calls = append(reader.calls, dn.String())
	members := [][]byte{[]byte("uid=elsewhere,dc=example,dc=com")}
	if len(reader.calls)%2 == 1 {
		members = [][]byte{[]byte("uid=reader,dc=example,dc=com")}
	}
	return directory.Entry{DN: dn.String(), Attributes: []directory.Attribute{
		{Description: "objectClass", Values: [][]byte{[]byte("groupOfNames")}},
		{Description: "member", Values: members},
	}}, nil
}

func TestDefaultProjectionExplicitFallback(t *testing.T) {
	runtime := defaultProjectionRuntime(t)
	server := &Server{}
	entry := defaultProjectionEntry()
	for _, test := range []struct {
		name  string
		rules []acl.Rule
	}{
		{"per-value", defaultProjectionRules(t, `{0}to attrs=description val.regex="^classified$" by * none`, `{1}to * by * read`)},
		{"changing-group", defaultProjectionRules(t, `to * by group.exact="cn=readers,dc=example,dc=com" read by * none`)},
		{"changing-ssf", defaultProjectionRules(t, `to * by ssf=1 read by * none`)},
	} {
		for _, database := range []bool{false, true} {
			for _, typesOnly := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/database=%t/typesOnly=%t", test.name, database, typesOnly), func(t *testing.T) {
					runtime.access = defaultProjectionPolicy(t, test.rules, nil)
					if database {
						runtime.access = defaultProjectionPolicy(t, nil, map[string][]acl.Rule{"dc=example,dc=com": test.rules})
					}
					project := func(original bool) (directory.Entry, []string, int) {
						groups := &defaultProjectionGroupReader{}
						reader := &defaultProjectionContextReader{Reader: groups}
						if original {
							return originalAttributesWithPrivilege(server, runtime, reader, "uid=reader,dc=example,dc=com", entry, acl.Read, typesOnly), groups.calls, reader.calls
						}
						return server.attributesWithPrivilege(runtime, reader, "uid=reader,dc=example,dc=com", entry, acl.Read, typesOnly), groups.calls, reader.calls
					}
					want, wantGroups, wantCalls := project(true)
					got, groups, calls := project(false)
					assertDefaultProjectionEqual(t, got, want)
					if !reflect.DeepEqual(groups, wantGroups) || calls != wantCalls {
						t.Fatalf("fallback calls differ: groups=%v/%v context=%d/%d", groups, wantGroups, calls, wantCalls)
					}
					if test.name == "changing-group" && len(groups) < len(entry.Attributes) {
						t.Fatal("group membership was not read for every decision")
					}
					if test.name == "per-value" && !typesOnly && !reflect.DeepEqual(got.Values("description"), [][]byte{[]byte("public"), []byte("other")}) {
						t.Fatal("per-value deny was lost")
					}
				})
			}
		}
	}
}

type defaultProjectionRemoteReader struct {
	storage.Reader
	trace        []string
	views        int
	failView     bool
	failIdentity bool
}

func (reader *defaultProjectionRemoteReader) AccessContext() any {
	reader.trace = append(reader.trace, "context")
	return acl.Subject{RealDN: "uid=real,dc=example,dc=com"}
}

func (reader *defaultProjectionRemoteReader) remoteACLView(subject string, entry directory.Entry, attribute string, value []byte) (storage.Reader, string, directory.Entry, string, []byte, error) {
	reader.views++
	reader.trace = append(reader.trace, fmt.Sprintf("view:%s:%s:%s:%#v", subject, entry.DN, attribute, value))
	if reader.failView && reader.views == 2 {
		return nil, "", directory.Entry{}, "", nil, errors.New("mapping failed")
	}
	if reader.views%2 == 0 {
		entry.DN = "cn=config"
	}
	return reader.Reader, "uid=mapped,dc=example,dc=com", entry, attribute, value, nil
}

func (reader *defaultProjectionRemoteReader) remoteACLIdentity(subject string) (string, error) {
	reader.trace = append(reader.trace, "identity:"+subject)
	if reader.failIdentity && reader.views == 2 {
		return "", errors.New("identity mapping failed")
	}
	return "uid=mapped-real,dc=example,dc=com", nil
}

func TestDefaultProjectionRemoteFallback(t *testing.T) {
	runtime := defaultProjectionRuntime(t)
	entry := defaultProjectionEntry()
	for _, explicit := range []bool{false, true} {
		for _, typesOnly := range []bool{false, true} {
			for _, failure := range []string{"none", "view", "identity"} {
				t.Run(fmt.Sprintf("explicit=%t/typesOnly=%t/%s", explicit, typesOnly, failure), func(t *testing.T) {
					runtime.access = acl.DefaultPolicy()
					if explicit {
						runtime.access = defaultProjectionPolicy(t, defaultProjectionRules(t, `to * by dn.exact="uid=mapped,dc=example,dc=com" read by * none`), nil)
					}
					project := func(original bool) (directory.Entry, *defaultProjectionRemoteReader) {
						reader := &defaultProjectionRemoteReader{failView: failure == "view", failIdentity: failure == "identity"}
						if original {
							return originalAttributesWithPrivilege(&Server{}, runtime, reader, "uid=reader,dc=example,dc=com", entry, acl.Read, typesOnly), reader
						}
						return (&Server{}).attributesWithPrivilege(runtime, reader, "uid=reader,dc=example,dc=com", entry, acl.Read, typesOnly), reader
					}
					want, wantReader := project(true)
					got, reader := project(false)
					assertDefaultProjectionEqual(t, got, want)
					if !slices.Equal(reader.trace, wantReader.trace) || reader.views != wantReader.views || reader.views < len(entry.Attributes) {
						t.Fatalf("remote callback trace differs:\n got: %v\nwant: %v", reader.trace, wantReader.trace)
					}
				})
			}
		}
	}
}

type defaultProjectionNormalizer struct {
	*schema.Registry
	trace []string
}

func (normalizer *defaultProjectionNormalizer) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	normalizer.trace = append(normalizer.trace, fmt.Sprintf("%s=%q", attribute, value))
	if len(normalizer.trace)%7 == 0 {
		return "", nil, errors.New("changing normalizer failure")
	}
	return normalizer.Registry.NormalizeDNAttribute(attribute, value)
}

func TestDefaultProjectionCustomNormalizerFallback(t *testing.T) {
	for _, indexed := range []bool{false, true} {
		t.Run(fmt.Sprintf("indexed=%t", indexed), func(t *testing.T) {
			runtime := defaultProjectionRuntime(t)
			custom := &defaultProjectionNormalizer{Registry: runtime.schema}
			runtime.databases[1].dnNormalizer = custom
			if indexed {
				runtime.databases[1].dnNormalizer = &databaseEqualityIndexNormalizer{registry: custom}
			}
			entry := defaultProjectionEntry()
			want := originalAttributesWithPrivilege(&Server{}, runtime, nil, "uid=reader,dc=example,dc=com", entry, acl.Read, false)
			wantTrace := slices.Clone(custom.trace)
			custom.trace = nil
			got := (&Server{}).attributesWithPrivilege(runtime, nil, "uid=reader,dc=example,dc=com", entry, acl.Read, false)
			assertDefaultProjectionEqual(t, got, want)
			if len(custom.trace) < 10 || !slices.Equal(custom.trace, wantTrace) {
				t.Fatalf("custom normalizer calls differ: got %v, want %v", custom.trace, wantTrace)
			}
		})
	}
}

func TestDefaultProjectionExplicitRulesWithoutContextCallback(t *testing.T) {
	runtime := defaultProjectionRuntime(t)
	entry := defaultProjectionEntry()
	for _, group := range []bool{false, true} {
		for _, typesOnly := range []bool{false, true} {
			raw := `{0}to attrs=description val.regex="^classified$" by * none`
			rules := defaultProjectionRules(t, raw, `{1}to * by * read`)
			if group {
				rules = defaultProjectionRules(t, `to * by group.exact="cn=readers,dc=example,dc=com" read by * none`)
			}
			runtime.access = defaultProjectionPolicy(t, rules, nil)
			before, after := &defaultProjectionGroupReader{}, &defaultProjectionGroupReader{}
			if _, contextual := any(after).(interface{ AccessContext() any }); contextual {
				t.Fatal("fixture must isolate the explicit-rule guard")
			}
			server := &Server{}
			want := originalAttributesWithPrivilege(server, runtime, before, "uid=reader,dc=example,dc=com", entry, acl.Read, typesOnly)
			got := server.attributesWithPrivilege(runtime, after, "uid=reader,dc=example,dc=com", entry, acl.Read, typesOnly)
			assertDefaultProjectionEqual(t, got, want)
			if !slices.Equal(before.calls, after.calls) || group && len(after.calls) == 0 {
				t.Fatalf("group reads differ: %v / %v", before.calls, after.calls)
			}
			if !group && !typesOnly && len(got.Values("description")) != 2 {
				t.Fatal("per-value denial was skipped")
			}
		}
	}
}

type defaultProjectionRemoteOnlyReader struct {
	storage.Reader
	mapper *defaultProjectionRemoteReader
}

func (reader defaultProjectionRemoteOnlyReader) remoteACLView(subject string, entry directory.Entry, attribute string, value []byte) (storage.Reader, string, directory.Entry, string, []byte, error) {
	return reader.mapper.remoteACLView(subject, entry, attribute, value)
}

func (reader defaultProjectionRemoteOnlyReader) remoteACLIdentity(subject string) (string, error) {
	return reader.mapper.remoteACLIdentity(subject)
}

func TestDefaultProjectionRemoteWithoutContextCallback(t *testing.T) {
	runtime := defaultProjectionRuntime(t)
	entry := defaultProjectionEntry()
	for _, typesOnly := range []bool{false, true} {
		before, after := &defaultProjectionRemoteReader{}, &defaultProjectionRemoteReader{}
		beforeReader := defaultProjectionRemoteOnlyReader{mapper: before}
		afterReader := defaultProjectionRemoteOnlyReader{mapper: after}
		if _, contextual := any(afterReader).(interface{ AccessContext() any }); contextual {
			t.Fatal("fixture must isolate the remote mapping guard")
		}
		server := &Server{}
		want := originalAttributesWithPrivilege(server, runtime, beforeReader, "uid=reader,dc=example,dc=com", entry, acl.Read, typesOnly)
		got := server.attributesWithPrivilege(runtime, afterReader, "uid=reader,dc=example,dc=com", entry, acl.Read, typesOnly)
		assertDefaultProjectionEqual(t, got, want)
		if !slices.Equal(before.trace, after.trace) || after.views < len(entry.Attributes) {
			t.Fatalf("remote callbacks differ: %v / %v", before.trace, after.trace)
		}
	}
}

func TestDefaultProjectionPartitionContextForwarding(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	runtime := defaultProjectionRuntime(t)
	entry := defaultProjectionEntry()
	deny := defaultProjectionPolicy(t, defaultProjectionRules(t, "to * by * none"), nil)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		for _, wrap := range []func(storage.Reader) storage.Reader{
			func(reader storage.Reader) storage.Reader { return storage.ReaderInPartition(reader, "db") },
			func(reader storage.Reader) storage.Reader { return readerForDatabase(reader, runtime.databases[1]) },
			func(reader storage.Reader) storage.Reader {
				return storage.WriterInPartition(reader.(storage.Writer), "db")
			},
			func(reader storage.Reader) storage.Reader {
				return writerForDatabase(reader.(storage.Writer), runtime.databases[1])
			},
		} {
			for _, typesOnly := range []bool{false, true} {
				runtime.access = acl.DefaultPolicy()
				pure := wrap(accessContextWriter{Writer: writer, subject: acl.Subject{SSF: 256}})
				got := (&Server{}).attributesWithPrivilege(runtime, pure, "", entry, acl.Read, typesOnly)
				want := originalAttributesWithPrivilege(&Server{}, runtime, pure, "", entry, acl.Read, typesOnly)
				assertDefaultProjectionEqual(t, got, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, schemaAware := range []bool{false, true} {
		project := func(original bool) (directory.Entry, int) {
			runtime.access = acl.DefaultPolicy()
			custom := &defaultProjectionContextReader{onCall: func(call int) {
				if call == 3 {
					runtime.access = deny
				}
			}}
			var reader storage.Reader = storageRevisionReader{Reader: custom}
			if schemaAware {
				reader = readerForDatabase(reader, runtime.databases[1])
			} else {
				reader = storage.ReaderInPartition(reader, "db")
			}
			if original {
				return originalAttributesWithPrivilege(&Server{}, runtime, reader, "", entry, acl.Read, false), custom.calls
			}
			return (&Server{}).attributesWithPrivilege(runtime, reader, "", entry, acl.Read, false), custom.calls
		}
		want, wantCalls := project(true)
		got, calls := project(false)
		assertDefaultProjectionEqual(t, got, want)
		if calls != wantCalls || calls <= 3 {
			t.Fatalf("partition callback count %d, want %d", calls, wantCalls)
		}
	}
}

func TestDefaultProjectionPolicyAndSchemaChangesAfterWarm(t *testing.T) {
	runtime := defaultProjectionRuntime(t)
	server := &Server{}
	entry := defaultProjectionEntry()
	deny := defaultProjectionPolicy(t, defaultProjectionRules(t, "to * by * none"), nil)
	for _, policy := range []*acl.Policy{acl.DefaultPolicy(), deny, acl.DefaultPolicy()} {
		runtime.access = policy
		for range 3 {
			got := server.attributesWithPrivilege(runtime, nil, "", entry, acl.Read, false)
			want := originalAttributesWithPrivilege(server, runtime, nil, "", entry, acl.Read, false)
			assertDefaultProjectionEqual(t, got, want)
			if (len(got.Attributes) == 0) != (policy == deny) {
				t.Fatal("projection retained a decision from the previous policy")
			}
		}
	}
	entry.DN = "member=broken,dc=example,dc=com"
	if got := server.attributesWithPrivilege(runtime, nil, "", entry, acl.Read, false); len(got.Attributes) != 0 {
		t.Fatal("invalid DN was allowed after warming another entry")
	}
	attribute, ok := runtime.schema.AttributeType("member")
	if !ok {
		t.Fatal("missing member schema")
	}
	attribute.Equality = "caseIgnoreMatch"
	attribute.Syntax = "1.3.6.1.4.1.1466.115.121.1.15"
	if err := runtime.schema.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	got := server.attributesWithPrivilege(runtime, nil, "", entry, acl.Read, false)
	assertDefaultProjectionEqual(t, got, originalAttributesWithPrivilege(server, runtime, nil, "", entry, acl.Read, false))
	if len(got.Attributes) != len(entry.Attributes) {
		t.Fatal("projection retained a denial after schema changed between operations")
	}
}
