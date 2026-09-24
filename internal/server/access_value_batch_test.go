package server

import (
	"fmt"
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestValueBatchProjectionReference(t *testing.T) {
	runtime := defaultProjectionRuntime(t)
	server := &Server{}
	entry := defaultProjectionEntry()
	entry.Attributes = append(entry.Attributes,
		directory.Attribute{Description: "userPassword", Values: [][]byte{[]byte("first"), []byte("second")}},
		directory.Attribute{Description: "children", Values: [][]byte{[]byte("first"), []byte("second")}},
	)
	for _, rules := range [][]acl.Rule{
		defaultProjectionRules(t, "{0}to attrs=userPassword by self write by anonymous auth by * none", "{1}to * by users read by * none"),
		defaultProjectionRules(t, "{0}to attrs=description by * =r continue by users +w break", "{1}to * by * +s"),
		defaultProjectionRules(t, `to * by realdn.exact="uid=real,dc=example,dc=com" ssf=128 read by * none`),
		defaultProjectionRules(t, `to dn.regex="^cn=([^,]+),dc=example,dc=com$" by dn.exact,expand="uid=$1,dc=example,dc=com" read by * none`),
	} {
		for _, database := range []bool{false, true} {
			runtime.access = defaultProjectionPolicy(t, rules, nil)
			if database {
				runtime.access = defaultProjectionPolicy(t, nil, map[string][]acl.Rule{"dc=example,dc=com": rules})
			}
			if !runtime.access.CanBatchValues() {
				t.Fatal("fixture must exercise value batching")
			}
			for _, dn := range []string{entry.DN, "cn=config", "cn=broken,", ""} {
				entry.DN = dn
				for _, subject := range []string{"", dn, "uid=projection,dc=example,dc=com", "uid=reader,dc=example,dc=com", "cn=admin,dc=example,dc=com", "cn=config"} {
					for _, privilege := range []acl.Privilege{0, acl.Auth, acl.Read, acl.Search, acl.Write, acl.Manage} {
						for _, typesOnly := range []bool{false, true} {
							for _, ssf := range []int{0, 256} {
								reader := storage.ReaderInPartition(accessContextReader{subject: acl.Subject{RealDN: "uid=real,dc=example,dc=com", SSF: ssf}}, "db")
								want := originalAttributesWithPrivilege(server, runtime, reader, subject, entry, privilege, typesOnly)
								got := server.attributesWithPrivilege(runtime, reader, subject, entry, privilege, typesOnly)
								assertDefaultProjectionEqual(t, got, want)
							}
						}
					}
				}
			}
			entry.DN = "cn=projection,dc=example,dc=com"
		}
	}
}

func TestValueBatchProjectionOwnershipAndPolicyChange(t *testing.T) {
	runtime := defaultProjectionRuntime(t)
	server := &Server{}
	allow := defaultProjectionPolicy(t, defaultProjectionRules(t, "to * by users read by * none"), nil)
	deny := defaultProjectionPolicy(t, defaultProjectionRules(t, "to * by * none"), nil)
	for _, policy := range []*acl.Policy{allow, deny, allow} {
		runtime.access = policy
		entry := defaultProjectionEntry()
		got := server.attributesWithPrivilege(runtime, nil, "uid=reader,dc=example,dc=com", entry, acl.Read, false)
		assertDefaultProjectionEqual(t, got, originalAttributesWithPrivilege(server, runtime, nil, "uid=reader,dc=example,dc=com", entry, acl.Read, false))
		if policy == deny {
			if len(got.Attributes) != 0 {
				t.Fatal("stale authorization survived policy replacement")
			}
			continue
		}
		got.Attributes[0].Description = "changed"
		got.Attributes[0].Values[0][0] = 'P'
		if entry.Attributes[0].Description != "cn" || entry.Attributes[0].Values[0][0] != 'P' {
			t.Fatal("attribute descriptors must be owned while bytes remain borrowed")
		}
		got.Attributes[0].Values[0] = nil
		if entry.Attributes[0].Values[0] == nil {
			t.Fatal("value slice aliases the original")
		}
	}
}

func TestValueBatchProjectionCustomCallbacks(t *testing.T) {
	for _, typesOnly := range []bool{false, true} {
		t.Run(fmt.Sprint(typesOnly), func(t *testing.T) {
			runtime := defaultProjectionRuntime(t)
			runtime.access = defaultProjectionPolicy(t, defaultProjectionRules(t, "to * by ssf=1 read by * none"), nil)
			entry := defaultProjectionEntry()
			before, after := &defaultProjectionContextReader{}, &defaultProjectionContextReader{}
			wrap := func(reader storage.Reader) storage.Reader {
				return readerForDatabase(storageRevisionReader{Reader: reader}, runtime.databases[1])
			}
			want := originalAttributesWithPrivilege(&Server{}, runtime, wrap(before), "uid=reader,dc=example,dc=com", entry, acl.Read, typesOnly)
			got := (&Server{}).attributesWithPrivilege(runtime, wrap(after), "uid=reader,dc=example,dc=com", entry, acl.Read, typesOnly)
			assertDefaultProjectionEqual(t, got, want)
			if before.calls != after.calls || after.calls < len(entry.Attributes) {
				t.Fatalf("context callbacks differ: %d / %d", before.calls, after.calls)
			}

			custom := &defaultProjectionNormalizer{Registry: runtime.schema}
			runtime.databases[1].dnNormalizer = custom
			want = originalAttributesWithPrivilege(&Server{}, runtime, nil, "uid=reader,dc=example,dc=com", entry, acl.Read, typesOnly)
			trace := slices.Clone(custom.trace)
			custom.trace = nil
			got = (&Server{}).attributesWithPrivilege(runtime, nil, "uid=reader,dc=example,dc=com", entry, acl.Read, typesOnly)
			assertDefaultProjectionEqual(t, got, want)
			if !slices.Equal(trace, custom.trace) {
				t.Fatal("normalizer callbacks changed")
			}
		})
	}
}
