package server

import (
	"fmt"
	"testing"

	"github.com/wangle201210/ldap-go/internal/acl"
)

// Includes ACL projection and the final owning selection, without storage or wire I/O.
func BenchmarkBorrowedProjection(b *testing.B) {
	for _, explicit := range []bool{false, true} {
		for _, requested := range [][]string{{"cn"}, {"cn", "member"}} {
			for _, borrow := range []bool{false, true} {
				b.Run(fmt.Sprintf("explicit=%t/attributes=%v/borrow=%t", explicit, requested, borrow), func(b *testing.B) {
					runtime := defaultProjectionRuntime(b)
					runtime.legacyDNs = newRuntimeLegacyDNCache()
					if explicit {
						runtime.access = defaultProjectionPolicy(b, defaultProjectionRules(b, "to * by users read by * none"), nil)
					}
					selection, ok := runtime.schema.PrepareExplicitAttributeSelection(requested)
					if !ok {
						b.Fatal("selection must be prepared")
					}
					entry := defaultProjectionBenchmarkEntry(true)
					server := &Server{}
					const subject = "uid=reader,dc=example,dc=com"
					server.attributesWithPrivilegeValues(runtime, nil, subject, entry, acl.Read, false, borrow, nil)
					b.ReportAllocs()
					for b.Loop() {
						for range 3 {
							readable := server.attributesWithPrivilegeValues(runtime, nil, subject, entry, acl.Read, false, borrow, nil)
							selected := selection.Select(readable, false)
							if len(selected.Attributes) != len(requested) {
								b.Fatal("unexpected selected attributes")
							}
						}
					}
				})
			}
		}
	}
}
