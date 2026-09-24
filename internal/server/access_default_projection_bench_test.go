package server

import (
	"fmt"
	"testing"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func defaultProjectionBenchmarkEntry(group bool) directory.Entry {
	if group {
		members := make([][]byte, 1000)
		for index := range members {
			members[index] = fmt.Appendf(nil, "uid=user%d,ou=people,dc=example,dc=com", index)
		}
		return directory.Entry{DN: "cn=benchmarkGroup,dc=example,dc=com", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: [][]byte{[]byte("top"), []byte("groupOfNames")}},
			{Description: "cn", Values: [][]byte{[]byte("benchmarkGroup")}},
			{Description: "member", Values: members},
		}}
	}
	return directory.Entry{DN: "uid=benchmarkUser,dc=example,dc=com", Attributes: []directory.Attribute{
		{Description: "objectClass", Values: [][]byte{[]byte("top"), []byte("person"), []byte("organizationalPerson"), []byte("inetOrgPerson")}},
		{Description: "uid", Values: [][]byte{[]byte("benchmarkUser")}},
		{Description: "cn", Values: [][]byte{[]byte("Benchmark User")}},
		{Description: "sn", Values: [][]byte{[]byte("User")}},
		{Description: "givenName", Values: [][]byte{[]byte("Benchmark")}},
		{Description: "mail", Values: [][]byte{[]byte("benchmark@example.com")}},
		{Description: "telephoneNumber", Values: [][]byte{[]byte("+1 555 0100")}},
		{Description: "title", Values: [][]byte{[]byte("Engineer")}},
		{Description: "ou", Values: [][]byte{[]byte("People")}},
		{Description: "description", Values: [][]byte{[]byte("Benchmark entry")}},
		{Description: "userPassword", Values: [][]byte{[]byte("not-a-real-password")}},
	}}
}

// Projection deliberately precedes attribute selection, as it does in search.
// Selecting cn later still incurs all 1000 member decisions in the original.
func BenchmarkDefaultProjection(b *testing.B) {
	for _, group := range []bool{false, true} {
		name := "ordinary11"
		if group {
			name = "group1000"
		}
		for _, explicit := range []bool{false, true} {
			policyName := "default"
			if explicit {
				policyName = "explicitFallback"
			}
			for _, original := range []bool{false, true} {
				implementation := "optimized"
				if original {
					implementation = "original"
				}
				b.Run(name+"/"+policyName+"/"+implementation, func(b *testing.B) {
					runtime := defaultProjectionRuntime(b)
					runtime.legacyDNs = newRuntimeLegacyDNCache()
					if explicit {
						runtime.access = defaultProjectionPolicy(b, defaultProjectionRules(b, "to * by * read"), nil)
					}
					entry := defaultProjectionBenchmarkEntry(group)
					server := &Server{}
					store := storage.NewMemory()
					b.Cleanup(func() { _ = store.Close() })
					ctx := withACLSubject(b.Context(), acl.Subject{SSF: 256})
					if err := store.View(ctx, func(reader storage.Reader) error {
						reader = storageRevisionReader{Reader: accessReaderFromContext(ctx, reader)}
						reader = readerForDatabase(reader, runtime.databases[1])
						project := server.attributesWithPrivilege
						if original {
							project = func(runtime *runtimeState, reader storage.Reader, subject string, entry directory.Entry, privilege acl.Privilege, typesOnly bool) directory.Entry {
								return originalAttributesWithPrivilege(server, runtime, reader, subject, entry, privilege, typesOnly)
							}
						}
						const subject = "uid=reader,dc=example,dc=com"
						project(runtime, reader, subject, entry, acl.Read, false)
						b.ReportAllocs()
						for b.Loop() {
							project(runtime, reader, subject, entry, acl.Read, false)
						}
						return nil
					}); err != nil {
						b.Fatal(err)
					}
				})
			}
		}
	}
}
