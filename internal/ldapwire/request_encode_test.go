package ldapwire

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestEncodeRequestMessageRoundTrips(t *testing.T) {
	t.Parallel()

	filter := directory.Filter{
		Kind: directory.FilterAnd,
		Children: []directory.Filter{
			{
				Kind:      directory.FilterEquality,
				Attribute: "uid",
				Assertion: []byte("alice"),
			},
			{
				Kind:      directory.FilterSubstrings,
				Attribute: "cn",
				Substring: directory.Substring{
					Initial: []byte("Al"),
					Any:     [][]byte{[]byte("ic")},
					Final:   []byte("e"),
				},
			},
			{
				Kind:         directory.FilterExtensible,
				Attribute:    "member",
				MatchingRule: "distinguishedNameMatch",
				Assertion:    []byte("uid=alice,dc=example,dc=com"),
				DNAttributes: true,
			},
		},
	}
	controls := []Control{
		{OID: "1.2.3", Critical: true, Value: []byte{0, 1}, HasValue: true},
		{OID: "1.2.4", HasValue: true},
	}
	tests := []struct {
		name    string
		request Request
	}{
		{
			name: "simple bind",
			request: BindRequest{
				Version: 3,
				Name:    "uid=alice,dc=example,dc=com",
				Authentication: Authentication{
					Simple: []byte("secret"),
				},
			},
		},
		{
			name: "SASL bind",
			request: BindRequest{
				Version: 3,
				Authentication: Authentication{
					IsSASL:             true,
					SASLMechanism:      "PLAIN",
					SASLCredentials:    []byte("\x00alice\x00secret"),
					HasSASLCredentials: true,
				},
			},
		},
		{
			name: "search",
			request: SearchRequest{
				BaseDN:       "dc=example,dc=com",
				Scope:        directory.ScopeWholeSubtree,
				DerefAliases: DerefAlways,
				SizeLimit:    100,
				TimeLimit:    5,
				TypesOnly:    true,
				Filter:       filter,
				Attributes:   []string{"cn", "+"},
			},
		},
		{
			name: "children search",
			request: SearchRequest{
				BaseDN:     "dc=example,dc=com",
				Scope:      directory.ScopeChildren,
				Attributes: []string{},
				Filter: directory.Filter{
					Kind:      directory.FilterPresent,
					Attribute: "objectClass",
				},
			},
		},
		{name: "unbind", request: UnbindRequest{}},
		{
			name: "add",
			request: AddRequest{Entry: directory.Entry{
				DN: "uid=alice,dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: [][]byte{[]byte("person")}},
					{Description: "jpegPhoto", Values: [][]byte{{0, 1, 2}}},
				},
			}},
		},
		{
			name: "modify",
			request: ModifyRequest{
				DN: "uid=alice,dc=example,dc=com",
				Changes: []Modification{
					{
						Operation: ModificationReplace,
						Attribute: directory.Attribute{
							Description: "description",
							Values:      [][]byte{[]byte("changed")},
						},
					},
					{
						Operation: ModificationDelete,
						Attribute: directory.Attribute{
							Description: "mail",
							Values:      [][]byte{},
						},
					},
				},
			},
		},
		{
			name:    "delete",
			request: DeleteRequest{DN: "uid=alice,dc=example,dc=com"},
		},
		{
			name: "modify DN",
			request: ModifyDNRequest{
				DN:             "uid=alice,dc=example,dc=com",
				NewRDN:         "uid=renamed",
				DeleteOldRDN:   true,
				NewSuperior:    "ou=people,dc=example,dc=com",
				HasNewSuperior: true,
			},
		},
		{
			name: "compare",
			request: CompareRequest{
				DN:        "uid=alice,dc=example,dc=com",
				Attribute: "jpegPhoto",
				Assertion: []byte{0, 1, 2},
			},
		},
		{name: "abandon", request: AbandonRequest{MessageID: 7}},
		{
			name: "extended",
			request: ExtendedRequest{
				Name:     "1.3.6.1.4.1.4203.1.11.1",
				Value:    []byte{0x30, 0x00},
				HasValue: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := Message{
				ID: 23, Request: test.request, Controls: controls, ControlsPresent: true,
			}
			encoded, err := EncodeRequestMessage(message)
			if err != nil {
				t.Fatalf("EncodeRequestMessage(): %v", err)
			}
			decoded, err := ReadMessage(bytes.NewReader(encoded), int64(len(encoded)))
			if err != nil {
				t.Fatalf("ReadMessage(): %v", err)
			}
			if !reflect.DeepEqual(decoded, message) {
				t.Fatalf("round trip = %#v, want %#v", decoded, message)
			}
		})
	}
}

func TestEncodeRequestMessageRejectsUnsupportedRequest(t *testing.T) {
	t.Parallel()

	_, err := EncodeRequestMessage(Message{
		ID:      1,
		Request: UnsupportedRequest{Tag: 31},
	})
	if err == nil {
		t.Fatal("EncodeRequestMessage() accepted unsupported request")
	}
}

func TestEncodeRequestMessagePreservesEmptyControlsWrapper(t *testing.T) {
	t.Parallel()
	message := Message{
		ID: 17,
		Request: SearchRequest{
			Scope: directory.ScopeBase,
			Filter: directory.Filter{
				Kind: directory.FilterPresent, Attribute: "objectClass",
			},
		},
		ControlsPresent: true,
	}
	encoded, err := EncodeRequestMessage(message)
	if err != nil {
		t.Fatalf("EncodeRequestMessage(): %v", err)
	}
	decoded, err := ReadMessage(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatalf("ReadMessage(): %v", err)
	}
	if !decoded.ControlsPresent || len(decoded.Controls) != 0 {
		t.Fatalf("empty controls wrapper round trip = %#v", decoded)
	}
}

func TestReadMessageRejectsSearchScopeAboveChildren(t *testing.T) {
	t.Parallel()

	encoded, err := EncodeRequestMessage(Message{
		ID: 1,
		Request: SearchRequest{
			Scope: directory.ScopeChildren + 1,
			Filter: directory.Filter{
				Kind:      directory.FilterPresent,
				Attribute: "objectClass",
			},
			Attributes: []string{},
		},
	})
	if err != nil {
		t.Fatalf("EncodeRequestMessage(): %v", err)
	}
	_, err = ReadMessage(bytes.NewReader(encoded), int64(len(encoded)))
	if !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("ReadMessage() error = %v, want ErrMalformedMessage", err)
	}
}
