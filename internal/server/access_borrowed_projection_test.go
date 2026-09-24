package server

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestBorrowedProjectionOwnership(t *testing.T) {
	for _, policy := range []string{"default", "explicit", "denied-member", "denied-all"} {
		for _, typesOnly := range []bool{false, true} {
			for _, shape := range []string{"values", "nil", "empty"} {
				t.Run(fmt.Sprintf("%s/typesOnly=%t/%s", policy, typesOnly, shape), func(t *testing.T) {
					runtime := defaultProjectionRuntime(t)
					switch policy {
					case "explicit":
						runtime.access = defaultProjectionPolicy(t, defaultProjectionRules(t, "to * by users read by * none"), nil)
					case "denied-member":
						runtime.access = defaultProjectionPolicy(t, defaultProjectionRules(t, "{0}to attrs=member by * none", "{1}to * by users read by * none"), nil)
					case "denied-all":
						runtime.access = defaultProjectionPolicy(t, defaultProjectionRules(t, "to * by * none"), nil)
					}
					entry := defaultProjectionEntry()
					entry.Attributes = append(entry.Attributes, directory.Attribute{
						Description: "jpegPhoto", Values: [][]byte{nil, {}, {0, 255, 1}}, RawNormalized: true,
					})
					if shape == "nil" {
						entry.Attributes = nil
					} else if shape == "empty" {
						entry.Attributes = []directory.Attribute{}
					}
					server := &Server{}
					const subject = "uid=reader,dc=example,dc=com"
					wantReadable := originalAttributesWithPrivilege(server, runtime, nil, subject, entry, acl.Read, typesOnly)
					owned := server.attributesWithPrivilege(runtime, nil, subject, entry, acl.Read, typesOnly)
					borrowed := server.attributesWithPrivilegeValues(runtime, nil, subject, entry, acl.Read, typesOnly, true, nil)
					assertDefaultProjectionEqual(t, owned, wantReadable)
					assertDefaultProjectionEqual(t, borrowed, wantReadable)
					for index, attribute := range borrowed.Attributes {
						source := slices.IndexFunc(entry.Attributes, func(a directory.Attribute) bool { return a.Description == attribute.Description })
						if &borrowed.Attributes[index] == &entry.Attributes[source] {
							t.Fatal("projection must own attribute descriptors")
						}
						if len(attribute.Values) == 0 {
							continue
						}
						if &attribute.Values[0] != &entry.Attributes[source].Values[0] ||
							&owned.Attributes[index].Values[0] == &entry.Attributes[source].Values[0] {
							t.Fatal("borrowed/default value descriptor ownership differs from its contract")
						}
						for i, value := range attribute.Values {
							if len(value) > 0 && &value[0] != &entry.Attributes[source].Values[i][0] {
								t.Fatal("projection must continue to borrow value bytes")
							}
						}
					}
					selection, ok := runtime.schema.PrepareExplicitAttributeSelection([]string{
						"2.5.4.3", "description", "member", "mail", "telephoneNumber", "jpegPhoto",
					})
					if !ok {
						t.Fatal("selection must be prepared")
					}
					selected := selection.Select(borrowed, typesOnly)
					want := selection.Select(wantReadable, typesOnly)
					want.Attributes = slices.Clone(want.Attributes)
					for i := range want.Attributes {
						want.Attributes[i].Values = slices.Clone(want.Attributes[i].Values)
						for j, value := range want.Attributes[i].Values {
							want.Attributes[i].Values[j] = bytes.Clone(value)
						}
					}
					assertDefaultProjectionEqual(t, selected, want)
					// Simulate both descriptor arena reuse and destruction of borrowed bytes.
					for i := range entry.Attributes {
						for j, value := range entry.Attributes[i].Values {
							clear(value)
							entry.Attributes[i].Values[j] = []byte("replacement")
						}
						entry.Attributes[i] = directory.Attribute{Description: "replaced"}
					}
					assertDefaultProjectionEqual(t, selected, want)
				})
			}
		}
	}
}

func TestBorrowedProjectionFallbacks(t *testing.T) {
	for _, mode := range []string{"context", "normalizer", "remote", "remote-view-error", "remote-identity-error", "value", "group"} {
		for _, typesOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/typesOnly=%t", mode, typesOnly), func(t *testing.T) {
				project := func(borrow bool) (directory.Entry, []string) {
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
					case "value":
						runtime.access = defaultProjectionPolicy(t, defaultProjectionRules(t,
							`{0}to attrs=description val.regex="^classified$" by * none`, `{1}to * by * read`), nil)
					case "group":
						runtime.access = defaultProjectionPolicy(t, defaultProjectionRules(t,
							`to * by group.exact="cn=readers,dc=example,dc=com" read by * none`), nil)
						custom := &defaultProjectionGroupReader{}
						reader = custom
						finish = func() { trace = custom.calls }
					}
					server := &Server{}
					const subject = "uid=reader,dc=example,dc=com"
					var result directory.Entry
					if borrow {
						result = server.attributesWithPrivilegeValues(runtime, reader, subject, entry, acl.Read, typesOnly, true, nil)
					} else {
						result = originalAttributesWithPrivilege(server, runtime, reader, subject, entry, acl.Read, typesOnly)
					}
					for _, attribute := range result.Attributes {
						index := slices.IndexFunc(entry.Attributes, func(a directory.Attribute) bool { return a.Description == attribute.Description })
						if len(attribute.Values) > 0 && &attribute.Values[0] == &entry.Attributes[index].Values[0] {
							t.Fatal("fallback borrowed value descriptors")
						}
					}
					finish()
					return result, trace
				}
				want, wantTrace := project(false)
				got, trace := project(true)
				assertDefaultProjectionEqual(t, got, want)
				if !slices.Equal(trace, wantTrace) || mode != "value" && len(trace) == 0 {
					t.Fatalf("callback trace differs: %v / %v", trace, wantTrace)
				}
			})
		}
	}
}

func TestSmallNonRootBorrowedProjection(t *testing.T) {
	for _, policy := range []string{"default", "explicit", "denied-member"} {
		t.Run(policy, func(t *testing.T) {
			fixture := newSmallNonRootFixture(t, 4, 1000, 105, 1003, 106)
			if policy == "default" {
				fixture.state.runtime.access = acl.DefaultPolicy()
			} else if policy == "denied-member" {
				smallNonRootPolicy(t, fixture, "{0}to attrs=member by users search by * none", "{1}to * by users read by * none")
			}
			for _, typesOnly := range []bool{false, true} {
				for _, attributes := range [][]string{{"cn"}, {"2.5.4.3", "member", "jpegPhoto"}, {"1.1"}} {
					request := readOnlySearchRequest("(member="+readOnlySearchMember+")", attributes, typesOnly)
					result, err, outcome := smallNonRootDifferential(t, fixture, request, true)
					smallNonRootAssertResult(t, result, err, outcome, 0, 4)
				}
			}
			request := readOnlySearchRequest("(uid=borrowed-groups)", []string{"cn", "member", "jpegPhoto"}, false)
			retained, err, outcome := smallNonRootDifferential(t, fixture, request, true)
			smallNonRootAssertResult(t, retained, err, outcome, 0, 4)
			wire := bytes.Clone(outcome.wire)
			for _, original := range fixture.groups {
				entry := original.Clone()
				entry.ReplaceValues("member", stringValues("uid=replaced,"+smallIndexedPeopleDN))
				entry.ReplaceValues("jpegPhoto", [][]byte{{255, 0}})
				smallIndexedPut(t, fixture.server, fixture.state, entry, true)
			}
			smallNonRootReady(t, fixture)
			updated, err, outcome := smallNonRootDifferential(t, fixture, request, true)
			smallNonRootAssertResult(t, updated, err, outcome, 0, 4)
			if bytes.Equal(wire, outcome.wire) {
				t.Fatal("updated source did not change the response")
			}
			if err := fixture.store.Close(); err != nil {
				t.Fatal(err)
			}
			for _, entry := range retained.Entries {
				i := slices.IndexFunc(fixture.groups, func(group directory.Entry) bool { return group.DN == entry.DN })
				if i < 0 {
					t.Fatalf("unexpected retained DN: %s", entry.DN)
				}
				if !reflect.DeepEqual(entry.GetRawAttributeValues("jpegPhoto"), fixture.groups[i].Values("jpegPhoto")) {
					t.Fatal("retained binary values changed after update and unmap")
				}
				if policy != "denied-member" && !reflect.DeepEqual(entry.GetRawAttributeValues("member"), fixture.groups[i].Values("member")) {
					t.Fatal("retained member values changed after arena reuse, update and unmap")
				}
			}
		})
	}
}
