package server

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const selectedProjectionSubject = "uid=reader,dc=example,dc=com"

func TestSelectedProjectionDifferentialAndOwnership(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		runtime := defaultProjectionRuntime(t)
		if explicit {
			runtime.access = defaultProjectionPolicy(t, defaultProjectionRules(t,
				"{0}to attrs=member by * none", "{1}to * by users read by * none"), nil)
		}
		if !runtime.access.CanBatchValues() || !localProjectionReadOnly(runtime, nil) {
			t.Fatal("fixture must exercise pure projection")
		}
		for _, test := range []struct {
			name         string
			requested    []string
			descriptions []string
		}{
			{"alias", []string{"LOCALITYNAME"}, []string{"l", "localityName;lang-fr"}},
			{"OID and stored options", []string{"2.5.4.3"}, []string{"cn", "CN;lang-en", "2.5.4.3;lang-fr"}},
			{"subtypes", []string{"name"}, []string{"cn", "l", "localityName;lang-fr", "CN;lang-en", "sn", "2.5.4.3;lang-fr"}},
			{"binary and empty values", []string{"description", "mail", "telephoneNumber", "jpegPhoto"}, []string{"description", "mail", "telephoneNumber", "description;lang-en", "jpegPhoto"}},
			{"no attributes", []string{"1.1"}, nil},
			{"denied only", []string{"member"}, []string{"member"}},
			{"unknown stored options", []string{"X-UNKNOWN"}, []string{"x-unknown;lang-en"}},
			{"duplicates and mixed 1.1", []string{"1.1", "cn", "2.5.4.3", "CN"}, []string{"cn", "CN;lang-en", "2.5.4.3;lang-fr"}},
		} {
			selection, prepared := runtime.schema.PrepareExplicitAttributeSelection(test.requested)
			if !prepared {
				t.Fatalf("selection %v was not prepared", test.requested)
			}
			for _, typesOnly := range []bool{false, true} {
				for _, borrow := range []bool{false, true} {
					t.Run(fmt.Sprintf("explicit=%t/%s/typesOnly=%t/borrow=%t", explicit, test.name, typesOnly, borrow), func(t *testing.T) {
						entry := selectedProjectionEntry()
						server := &Server{}
						full := originalAttributesWithPrivilege(server, runtime, nil, selectedProjectionSubject, entry, acl.Read, typesOnly)
						want := selection.Select(full, typesOnly)
						want.Attributes = slices.Clone(want.Attributes)
						for index := range want.Attributes {
							want.Attributes[index].Values = slices.Clone(want.Attributes[index].Values)
							for valueIndex, value := range want.Attributes[index].Values {
								want.Attributes[index].Values[valueIndex] = bytes.Clone(value)
							}
						}
						readable := server.attributesWithPrivilegeValues(runtime, nil, selectedProjectionSubject, entry, acl.Read, typesOnly, borrow, selection)
						got := selection.Select(readable, typesOnly)
						assertDefaultProjectionEqual(t, got, want)
						descriptions := test.descriptions
						if explicit && test.name == "denied only" {
							descriptions = nil
						}
						if actual := selectedProjectionDescriptions(got); !slices.Equal(actual, descriptions) {
							t.Fatalf("selected descriptions = %v, want %v", actual, descriptions)
						}
						if !slices.Equal(selectedProjectionDescriptions(readable), descriptions) {
							t.Fatal("pure projection retained unrequested attribute descriptors")
						}
						// Reuse both the decoder's descriptor arena and all borrowed payloads.
						for index := range entry.Attributes {
							for valueIndex, value := range entry.Attributes[index].Values {
								clear(value)
								entry.Attributes[index].Values[valueIndex] = []byte("replaced")
							}
							entry.Attributes[index] = directory.Attribute{Description: "replaced"}
						}
						assertDefaultProjectionEqual(t, got, want)
					})
				}
			}
		}
	}
}

func TestSelectedProjectionNilAndEmpty(t *testing.T) {
	runtime := defaultProjectionRuntime(t)
	var absent *schema.PreparedAttributeSelection
	if absent.SelectsAttribute("cn") {
		t.Fatal("nil selection selected an attribute")
	}
	for _, requested := range [][]string{nil, {}, {"*"}, {"+"}, {"@person"}, {"cn;lang-en"}} {
		if _, prepared := runtime.schema.PrepareExplicitAttributeSelection(requested); prepared {
			t.Fatalf("unsupported selection %v was prepared", requested)
		}
	}
	for _, shape := range []string{"values", "nil attributes", "empty attributes", "RootDSE", "invalid DN"} {
		for _, typesOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/typesOnly=%t", shape, typesOnly), func(t *testing.T) {
				entry := selectedProjectionEntry()
				switch shape {
				case "nil attributes":
					entry.Attributes = nil
				case "empty attributes":
					entry.Attributes = []directory.Attribute{}
				case "RootDSE":
					entry.DN = ""
				case "invalid DN":
					entry.DN = "cn=broken,"
				}
				server := &Server{}
				full := originalAttributesWithPrivilege(server, runtime, nil, selectedProjectionSubject, entry, acl.Read, typesOnly)
				unchanged := server.attributesWithPrivilegeValues(runtime, nil, selectedProjectionSubject, entry, acl.Read, typesOnly, true, nil)
				assertDefaultProjectionEqual(t, unchanged, full)
				for _, requested := range [][]string{{"cn"}, {"1.1"}} {
					selection, prepared := runtime.schema.PrepareExplicitAttributeSelection(requested)
					if !prepared {
						t.Fatal("selection was not prepared")
					}
					readable := server.attributesWithPrivilegeValues(runtime, nil, selectedProjectionSubject, entry, acl.Read, typesOnly, true, selection)
					assertDefaultProjectionEqual(t, selection.Select(readable, typesOnly), selection.Select(full, typesOnly))
					if entry.DN == "" {
						assertDefaultProjectionEqual(t, readable, full)
					}
				}
			})
		}
	}
}

func TestSelectedProjectionFullACLTarget(t *testing.T) {
	for _, test := range []struct {
		name  string
		rule  string
		batch bool
	}{
		{"object class attribute selector", "to attrs=@person by users read by * none", true},
		{"target filter", `to attrs=cn filter="(description=classified)" by users read by * none`, false},
		{"DN attribute subject", "to attrs=cn by dnattr=owner read by * none", false},
	} {
		for _, typesOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/typesOnly=%t", test.name, typesOnly), func(t *testing.T) {
				runtime := defaultProjectionRuntime(t)
				runtime.access = defaultProjectionPolicy(t, defaultProjectionRules(t, test.rule), nil)
				if runtime.access.CanBatchValues() != test.batch {
					t.Fatal("fixture does not exercise the intended policy branch")
				}
				entry := selectedProjectionEntry()
				entry.Attributes = append(entry.Attributes, directory.Attribute{
					Description: "owner", Values: stringValues(selectedProjectionSubject),
				})
				selection, prepared := runtime.schema.PrepareExplicitAttributeSelection([]string{"cn"})
				if !prepared {
					t.Fatal("selection was not prepared")
				}
				server := &Server{}
				full := originalAttributesWithPrivilege(server, runtime, nil, selectedProjectionSubject, entry, acl.Read, typesOnly)
				want := selection.Select(full, typesOnly)
				if len(want.Attributes) != 3 {
					t.Fatalf("full target must authorize all three cn descriptions, got %v", selectedProjectionDescriptions(want))
				}
				readable := server.attributesWithPrivilegeValues(runtime, nil, selectedProjectionSubject, entry, acl.Read, typesOnly, true, selection)
				assertDefaultProjectionEqual(t, selection.Select(readable, typesOnly), want)
			})
		}
	}
}

func TestSelectedProjectionFallbackTraces(t *testing.T) {
	for _, mode := range []string{"context", "normalizer", "remote", "remote-view-error", "remote-identity-error", "group", "value"} {
		for _, typesOnly := range []bool{false, true} {
			for _, requested := range []string{"cn", "1.1"} {
				t.Run(fmt.Sprintf("%s/typesOnly=%t/%s", mode, typesOnly, requested), func(t *testing.T) {
					project := func(selected bool) (directory.Entry, directory.Entry, []string) {
						runtime := defaultProjectionRuntime(t)
						entry := defaultProjectionEntry()
						var reader storage.Reader
						var trace []string
						finish := func() {}
						switch mode {
						case "context":
							custom := &defaultProjectionContextReader{onCall: func(call int) {
								trace = append(trace, fmt.Sprint(call))
								if call == 3 {
									runtime.access = defaultProjectionPolicy(t, defaultProjectionRules(t, "to * by * none"), nil)
								}
							}}
							reader = readerForDatabase(storageRevisionReader{Reader: custom}, runtime.databases[1])
						case "normalizer":
							custom := &defaultProjectionNormalizer{Registry: runtime.schema}
							runtime.databases[1].dnNormalizer = custom
							finish = func() { trace = custom.trace }
						case "remote", "remote-view-error", "remote-identity-error":
							custom := &defaultProjectionRemoteReader{failView: mode == "remote-view-error", failIdentity: mode == "remote-identity-error"}
							reader = custom
							finish = func() { trace = custom.trace }
						case "group":
							runtime.access = defaultProjectionPolicy(t, defaultProjectionRules(t,
								`to * by group.exact="cn=readers,dc=example,dc=com" read by * none`), nil)
							custom := &defaultProjectionGroupReader{}
							reader = custom
							finish = func() { trace = custom.calls }
						case "value":
							runtime.access = defaultProjectionPolicy(t, defaultProjectionRules(t,
								`{0}to attrs=description val.regex="^classified$" by * none`, `{1}to * by * read`), nil)
						}
						if localProjectionReadOnly(runtime, reader) && runtime.access.CanBatchValues() {
							t.Fatal("fixture must use the unchanged fallback")
						}
						selection, prepared := runtime.schema.PrepareExplicitAttributeSelection([]string{requested})
						if !prepared {
							t.Fatal("selection was not prepared")
						}
						server := &Server{}
						var readable directory.Entry
						if selected {
							readable = server.attributesWithPrivilegeValues(runtime, reader, selectedProjectionSubject, entry, acl.Read, typesOnly, true, selection)
						} else {
							readable = originalAttributesWithPrivilege(server, runtime, reader, selectedProjectionSubject, entry, acl.Read, typesOnly)
						}
						finish()
						return readable, selection.Select(readable, typesOnly), trace
					}
					wantReadable, want, wantTrace := project(false)
					readable, got, trace := project(true)
					assertDefaultProjectionEqual(t, readable, wantReadable)
					assertDefaultProjectionEqual(t, got, want)
					if !slices.Equal(trace, wantTrace) || mode != "value" && len(trace) == 0 {
						t.Fatalf("fallback callback trace changed:\n got: %v\nwant: %v", trace, wantTrace)
					}
				})
			}
		}
	}
}

func selectedProjectionEntry() directory.Entry {
	entry := defaultProjectionEntry()
	entry.Attributes = append(entry.Attributes,
		directory.Attribute{Description: "l", Values: stringValues("Shanghai")},
		directory.Attribute{Description: "localityName;lang-fr", Values: stringValues("Paris")},
		directory.Attribute{Description: "CN;lang-en", Values: stringValues("English name")},
		directory.Attribute{Description: "sn", Values: stringValues("Family")},
		directory.Attribute{Description: "2.5.4.3;lang-fr", Values: stringValues("French name")},
		directory.Attribute{Description: "jpegPhoto", Values: [][]byte{nil, {}, {0, 255, 1}}, RawNormalized: true},
		directory.Attribute{Description: "x-unknown;lang-en", Values: stringValues("extension")},
		directory.Attribute{Description: "objectClass", Values: stringValues("person")},
	)
	return entry
}

func selectedProjectionDescriptions(entry directory.Entry) []string {
	var descriptions []string
	for _, attribute := range entry.Attributes {
		descriptions = append(descriptions, attribute.Description)
	}
	return descriptions
}
