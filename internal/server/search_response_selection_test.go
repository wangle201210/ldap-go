package server

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
)

func TestResponseSelectionPreservesWireAndBudget(t *testing.T) {
	t.Parallel()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{0, 1, 7, 8, 10, 1000} {
		for _, typesOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("values=%d/typesOnly=%t", count, typesOnly), func(t *testing.T) {
				values := make([][]byte, count)
				for index := range values {
					values[index] = fmt.Appendf(nil, "uid=user%d,ou=people,dc=example,dc=com", index)
				}
				if count >= 8 {
					values[0], values[1] = nil, []byte{}
					values[2] = bytes.Repeat([]byte{'x'}, 4097)
				}
				entry := directory.Entry{DN: "cn=group,dc=example,dc=com", Attributes: []directory.Attribute{
					{Description: "cn", Values: stringValues("group")},
					{Description: "member", Values: values},
					{Description: "member;lang-en", Values: values},
					{Description: "userPassword", Values: stringValues("unselected")},
				}}
				selection, ok := registry.PrepareExplicitAttributeSelection([]string{"cn", "member"})
				if !ok {
					t.Fatal("selection not prepared")
				}
				before := selection.Select(entry, typesOnly)
				after := selection.SelectForResponse(entry, typesOnly)
				if !reflect.DeepEqual(before, after) {
					t.Fatal("response selection changed values, nilness, or attributes")
				}
				wantBytes := searchCandidateRetainedBytes(searchCandidate{selected: before, dn: entry.DN})
				gotBytes := searchCandidateRetainedBytes(searchCandidate{selected: after, dn: entry.DN})
				if gotBytes != wantBytes {
					t.Fatalf("logical budget changed: got %d want %d", gotBytes, wantBytes)
				}
				if !bytes.Equal(ldapwire.EncodeSearchResultEntry(1, before, nil), ldapwire.EncodeSearchResultEntry(1, after, nil)) {
					t.Fatal("encoded LDAP response changed")
				}
			})
		}
	}
}
