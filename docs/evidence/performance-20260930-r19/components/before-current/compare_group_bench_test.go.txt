package server

import (
	"fmt"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func BenchmarkLocalGroupCompare(b *testing.B) {
	benchmarkLocalGroupCompare(b, 1000)
}

func BenchmarkLocalSmallGroupCompare(b *testing.B) {
	benchmarkLocalGroupCompare(b, 10)
}

func benchmarkLocalGroupCompare(b *testing.B, members int) {
	server, state := newSmallIndexedFixture(b, 8)
	state.protocolVersion = 3
	const groupDN = "cn=group,ou=people,dc=example,dc=com"
	dn, err := parseCoreWriteDN(state.runtime, groupDN)
	if err != nil {
		b.Fatal(err)
	}
	database := databaseForNormalizedDN(state.runtime, dn)
	values := make([][]byte, members)
	for i := range values {
		values[i] = fmt.Appendf(nil, "uid=person-%05d,%s", i, smallIndexedPeopleDN)
	}
	entry := directory.Entry{DN: groupDN, Attributes: []directory.Attribute{
		{Description: "objectClass", Values: stringValues("top", "groupOfNames")},
		{Description: "cn", Values: stringValues("group")},
		{Description: "member", Values: values},
		{Description: "subschemaSubentry", Values: stringValues("cn=Subschema")},
		{Description: "creatorsName", Values: stringValues(smallIndexedRootDN)},
		{Description: "modifiersName", Values: stringValues(smallIndexedRootDN)},
		{Description: "createTimestamp", Values: stringValues("20260930000000Z")},
		{Description: "modifyTimestamp", Values: stringValues("20260930000000Z")},
	}}
	if err := server.config.Store.Update(b.Context(), func(writer storage.Writer) error {
		return writerForDatabase(writer, *database).Put(entry, false)
	}); err != nil {
		b.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		assertion []byte
		code      ldapwire.ResultCode
	}{
		{"first", values[0], ldapwire.ResultCompareTrue},
		{"last", values[len(values)-1], ldapwire.ResultCompareTrue},
		{"missing", []byte("uid=absent," + smallIndexedPeopleDN), ldapwire.ResultCompareFalse},
	} {
		b.Run(test.name, func(b *testing.B) {
			capture := &smallIndexedCapture{}
			request := ldapwire.CompareRequest{DN: groupDN, Attribute: "member", Assertion: test.assertion}
			message := ldapwire.Message{ID: 1, Request: request}
			run := func() {
				capture.Reset()
				if err := server.handleCompare(b.Context(), capture, state, message, request); err != nil {
					b.Fatal(err)
				}
			}
			run()
			if code, ok := simpleAuditResultCode(capture.Bytes()); !ok || code != int(test.code) {
				b.Fatalf("fixture Compare result = %d, recognized = %v", code, ok)
			}
			b.ReportAllocs()
			for b.Loop() {
				run()
			}
			if code, ok := simpleAuditResultCode(capture.Bytes()); !ok || code != int(test.code) {
				b.Fatalf("Compare result = %d, recognized = %v", code, ok)
			}
		})
	}
}
