package server

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func BenchmarkAuditResultDecode(b *testing.B) {
	for _, fixture := range []struct {
		name    string
		encoded []byte
		code    int
		fast    bool
	}{
		{"BindSuccess", ldapwire.EncodeBindResponse(1, ldapwire.Result{}, nil), 0, true},
		{"SearchDone", ldapwire.EncodeSearchResultDone(128, ldapwire.Result{}, nil), 0, true},
		{"CompareTrue", ldapwire.EncodeResultResponse(1, ldapwire.ApplicationCompareResponse, ldapwire.Result{Code: ldapwire.ResultCompareTrue}, nil), 6, true},
		{"CompareFalse", ldapwire.EncodeResultResponse(1, ldapwire.ApplicationCompareResponse, ldapwire.Result{Code: ldapwire.ResultCompareFalse}, nil), 5, true},
		{"DiagnosticFallback", ldapwire.EncodeBindResponse(1, ldapwire.Result{Code: ldapwire.ResultInvalidCredentials, DiagnosticMessage: "invalid credentials"}, nil), 49, false},
		{"ControlsFallback", ldapwire.EncodeSearchResultDone(128, ldapwire.Result{}, []ldapwire.Control{{OID: "1.2.840.113556.1.4.319", HasValue: true, Value: []byte{0x30, 5, 2, 1, 0, 4, 0}}}), 0, false},
	} {
		b.Run(fixture.name, func(b *testing.B) {
			if code, ok := simpleAuditResultCode(fixture.encoded); ok != fixture.fast || (ok && code != fixture.code) {
				b.Fatalf("unexpected fast-path fixture: (%d, %t)", code, ok)
			}
			b.Run("Code/Legacy", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if code, ok := legacyAuditResultCode(fixture.encoded); !ok || code != fixture.code {
						b.Fatal("incorrect result")
					}
				}
			})
			b.Run("Code/Current", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if code, ok := auditLDAPResultCode(fixture.encoded); !ok || code != fixture.code {
						b.Fatal("incorrect result")
					}
				}
			})
			b.Run("Observe/Legacy", func(b *testing.B) {
				observation := &operationAuditObservation{}
				b.ReportAllocs()
				for b.Loop() {
					legacyAuditResultObserveResponse(observation, fixture.encoded)
				}
				if !observation.hasResult || observation.result != fixture.code {
					b.Fatal("incorrect observed result")
				}
			})
			b.Run("Observe/Current", func(b *testing.B) {
				observation := &operationAuditObservation{}
				b.ReportAllocs()
				for b.Loop() {
					observation.observeResponse(fixture.encoded)
				}
				if !observation.hasResult || observation.result != fixture.code {
					b.Fatal("incorrect observed result")
				}
			})
		})
	}
}
