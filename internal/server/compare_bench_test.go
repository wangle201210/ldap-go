package server

import (
	"fmt"
	"testing"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func BenchmarkLocalCompare(b *testing.B) {
	for _, count := range []int{1, 1024} {
		b.Run(fmt.Sprintf("targets-%d", count), func(b *testing.B) {
			server, state := newSmallIndexedFixture(b, count)
			state.protocolVersion = 3
			requests := make([]ldapwire.CompareRequest, count)
			for i := range requests {
				uid := fmt.Sprintf("person-%05d", i)
				requests[i] = ldapwire.CompareRequest{
					DN:        "uid=" + uid + "," + smallIndexedPeopleDN,
					Attribute: "uid", Assertion: []byte(uid),
				}
			}
			capture := &smallIndexedCapture{}
			for _, request := range requests {
				capture.Reset()
				message := ldapwire.Message{ID: 1, Request: request}
				if err := server.handleCompare(b.Context(), capture, state, message, request); err != nil {
					b.Fatal(err)
				}
				if code, ok := simpleAuditResultCode(capture.Bytes()); !ok || code != int(ldapwire.ResultCompareTrue) {
					b.Fatalf("Compare warmup result = %d, recognized = %v", code, ok)
				}
			}
			index := 0
			b.ReportAllocs()
			for b.Loop() {
				request := requests[index%len(requests)]
				index++
				capture.Reset()
				message := ldapwire.Message{ID: 1, Request: request}
				if err := server.handleCompare(b.Context(), capture, state, message, request); err != nil {
					b.Fatal(err)
				}
			}
			if code, ok := simpleAuditResultCode(capture.Bytes()); !ok || code != int(ldapwire.ResultCompareTrue) {
				b.Fatalf("Compare result = %d, recognized = %v", code, ok)
			}
		})
	}
}
