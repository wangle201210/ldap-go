package server

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestSockProtocolEncodesAllBackendOperations(t *testing.T) {
	t.Parallel()

	common := SockRequest{
		MessageID: 41,
		Suffixes:  []string{"dc=example,dc=com", "dc=other,dc=com"},
		Connection: SockConnectionFields{
			IncludeBindDN:   true,
			BindDN:          "uid=admin,dc=example,dc=com",
			IncludePeerName: true,
			PeerName:        "IP=192.0.2.1:38901",
			IncludeSSF:      true,
			SSF:             256,
			IncludeConnID:   true,
			ConnID:          987654321,
		},
	}
	prefix := "msgid: 41\n" +
		"binddn: uid=admin,dc=example,dc=com\n" +
		"peername: IP=192.0.2.1:38901\n" +
		"ssf: 256\n" +
		"connid: 987654321\n" +
		"suffix: dc=example,dc=com\n" +
		"suffix: dc=other,dc=com\n"

	tests := []struct {
		name      string
		operation SockOperation
		want      string
	}{
		{
			name: "add",
			operation: SockAddRequest{Entry: directory.Entry{
				DN: "uid=alice,dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: [][]byte{[]byte("inetOrgPerson")}},
					{Description: "cn", Values: [][]byte{[]byte("Alice"), []byte("Alice A")}},
					{Description: "description", Values: [][]byte{{}}},
					{Description: "jpegPhoto", Values: [][]byte{{0x00, 0xff, 0x10}}},
				},
			}},
			want: "ADD\n" + prefix +
				"dn: uid=alice,dc=example,dc=com\n" +
				"objectClass: inetOrgPerson\n" +
				"cn: Alice\n" +
				"cn: Alice A\n" +
				"description:\n" +
				"jpegPhoto:: AP8Q\n\n",
		},
		{
			name: "bind",
			operation: SockBindRequest{
				DN:          "uid=alice,dc=example,dc=com",
				Method:      128,
				Credentials: []byte("p:ss word"),
			},
			want: "BIND\n" + prefix +
				"dn: uid=alice,dc=example,dc=com\n" +
				"method: 128\n" +
				"credlen: 9\n" +
				"cred: p:ss word\n\n",
		},
		{
			name: "compare",
			operation: SockCompareRequest{
				DN:        "uid=alice,dc=example,dc=com",
				Attribute: "jpegPhoto;binary",
				Assertion: []byte{0x00, 0xff},
			},
			want: "COMPARE\n" + prefix +
				"dn: uid=alice,dc=example,dc=com\n" +
				"jpegPhoto;binary:: AP8=\n\n",
		},
		{
			name:      "delete",
			operation: SockDeleteRequest{DN: "uid=alice,dc=example,dc=com"},
			want: "DELETE\n" + prefix +
				"dn: uid=alice,dc=example,dc=com\n\n",
		},
		{
			name: "extended",
			operation: SockExtendedRequest{
				OID:      "1.3.6.1.4.1.4203.1.11.1",
				Value:    []byte{0x30, 0x03, 0x80, 0x01, 0xff},
				HasValue: true,
			},
			want: "EXTENDED\n" + prefix +
				"oid: 1.3.6.1.4.1.4203.1.11.1\n" +
				"value: MAOAAf8=\n\n",
		},
		{
			name: "modify",
			operation: SockModifyRequest{
				DN: "uid=alice,dc=example,dc=com",
				Changes: []ldapwire.Modification{
					{
						Operation: ldapwire.ModificationAdd,
						Attribute: directory.Attribute{Description: "description", Values: [][]byte{[]byte("first")}},
					},
					{
						Operation: ldapwire.ModificationDelete,
						Attribute: directory.Attribute{Description: "seeAlso"},
					},
					{
						Operation: ldapwire.ModificationReplace,
						Attribute: directory.Attribute{Description: "jpegPhoto", Values: [][]byte{{0x00, 0xff}}},
					},
					{
						Operation: ldapwire.ModificationIncrement,
						Attribute: directory.Attribute{Description: "uidNumber", Values: [][]byte{[]byte("1")}},
					},
				},
			},
			want: "MODIFY\n" + prefix +
				"dn: uid=alice,dc=example,dc=com\n" +
				"add: description\n" +
				"description: first\n" +
				"-\n" +
				"delete: seeAlso\n" +
				"-\n" +
				"replace: jpegPhoto\n" +
				"jpegPhoto:: AP8=\n" +
				"-\n" +
				"increment: uidNumber\n" +
				"uidNumber: 1\n" +
				"-\n\n",
		},
		{
			name: "modrdn",
			operation: SockModifyDNRequest{
				DN:             "uid=alice,ou=people,dc=example,dc=com",
				NewRDN:         "uid=alice2",
				DeleteOldRDN:   true,
				NewSuperior:    "ou=archive,dc=example,dc=com",
				HasNewSuperior: true,
			},
			want: "MODRDN\n" + prefix +
				"dn: uid=alice,ou=people,dc=example,dc=com\n" +
				"newrdn: uid=alice2\n" +
				"deleteoldrdn: 1\n" +
				"newSuperior: ou=archive,dc=example,dc=com\n\n",
		},
		{
			name: "search",
			operation: SockSearchRequest{
				BaseDN:       "dc=example,dc=com",
				Scope:        directory.ScopeWholeSubtree,
				DerefAliases: ldapwire.DerefAlways,
				SizeLimit:    500,
				TimeLimit:    30,
				Filter: directory.Filter{
					Kind: directory.FilterAnd,
					Children: []directory.Filter{
						{Kind: directory.FilterPresent, Attribute: "objectClass"},
						{Kind: directory.FilterEquality, Attribute: "uid", Assertion: []byte("a*(b)\\\x00")},
					},
				},
				TypesOnly:  true,
				Attributes: []string{"cn", "jpegPhoto;binary", "+"},
			},
			want: "SEARCH\n" + prefix +
				"base: dc=example,dc=com\n" +
				"scope: 2\n" +
				"deref: 3\n" +
				"sizelimit: 500\n" +
				"timelimit: 30\n" +
				"filter: (&(objectClass=*)(uid=a\\2a\\28b\\29\\5c\\00))\n" +
				"attrsonly: 1\n" +
				"attrs: cn jpegPhoto;binary +\n\n",
		},
		{
			name:      "unbind",
			operation: SockUnbindRequest{},
			want:      "UNBIND\n" + prefix + "\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := common
			request.Operation = test.operation
			got, err := EncodeSockRequest(request, SockProtocolLimits{})
			if err != nil {
				t.Fatalf("EncodeSockRequest(): %v", err)
			}
			if string(got) != test.want {
				t.Fatalf("encoded request mismatch\ngot:\n%q\nwant:\n%q", got, test.want)
			}
		})
	}
}

func TestSockProtocolRequestOptionalFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation SockOperation
		want      string
	}{
		{
			name: "anonymous bind and empty credentials",
			operation: SockBindRequest{
				Method: 128,
			},
			want: "BIND\nmsgid: 1\ndn: \nmethod: 128\ncredlen: 0\ncred: \n\n",
		},
		{
			name: "extended absent value",
			operation: SockExtendedRequest{
				OID: "1.3.6.1.4.1.4203.1.11.3",
			},
			want: "EXTENDED\nmsgid: 1\noid: 1.3.6.1.4.1.4203.1.11.3\n\n",
		},
		{
			name: "extended present empty value",
			operation: SockExtendedRequest{
				OID:      "1.3.6.1.4.1.4203.1.11.3",
				HasValue: true,
			},
			want: "EXTENDED\nmsgid: 1\noid: 1.3.6.1.4.1.4203.1.11.3\nvalue: \n\n",
		},
		{
			name: "search all attributes",
			operation: SockSearchRequest{
				Scope:  directory.ScopeBase,
				Filter: directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"},
			},
			want: "SEARCH\nmsgid: 1\nbase: \nscope: 0\nderef: 0\nsizelimit: 0\ntimelimit: 0\n" +
				"filter: (objectClass=*)\nattrsonly: 0\nattrs: all\n\n",
		},
		{
			name: "OpenLDAP object class attribute selectors",
			operation: SockSearchRequest{
				Filter:     directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"},
				Attributes: []string{"@inetOrgPerson", "!extensibleObject", "+person"},
			},
			want: "SEARCH\nmsgid: 1\nbase: \nscope: 0\nderef: 0\nsizelimit: 0\ntimelimit: 0\n" +
				"filter: (objectClass=*)\nattrsonly: 0\nattrs: @inetOrgPerson !extensibleObject +person\n\n",
		},
		{
			name: "modrdn keeps old RDN",
			operation: SockModifyDNRequest{
				DN:     "uid=before,dc=example,dc=com",
				NewRDN: "uid=after",
			},
			want: "MODRDN\nmsgid: 1\ndn: uid=before,dc=example,dc=com\n" +
				"newrdn: uid=after\ndeleteoldrdn: 0\n\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := EncodeSockRequest(SockRequest{MessageID: 1, Operation: test.operation}, SockProtocolLimits{})
			if err != nil {
				t.Fatalf("EncodeSockRequest(): %v", err)
			}
			if string(got) != test.want {
				t.Fatalf("encoded request = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSockProtocolLDIFSafetyAndFolding(t *testing.T) {
	t.Parallel()

	longValue := bytes.Repeat([]byte("x"), 200)
	request := SockRequest{
		MessageID: 1,
		Operation: SockAddRequest{Entry: directory.Entry{
			DN: "cn=leading space,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "description", Values: [][]byte{[]byte(" leading"), []byte("trailing "), []byte(":colon"), []byte("<less"), []byte("normal")}},
				{Description: "userPassword", Values: [][]byte{[]byte("secret")}},
				{Description: "binary;binary", Values: [][]byte{[]byte("printable")}},
				{Description: "cn", Values: [][]byte{longValue}},
			},
		}},
	}
	encoded, err := EncodeSockRequest(request, SockProtocolLimits{})
	if err != nil {
		t.Fatalf("EncodeSockRequest(): %v", err)
	}
	text := string(encoded)
	wants := []string{
		"description:: " + base64.StdEncoding.EncodeToString([]byte(" leading")),
		"description:: " + base64.StdEncoding.EncodeToString([]byte("trailing ")),
		"description:: " + base64.StdEncoding.EncodeToString([]byte(":colon")),
		"description:: " + base64.StdEncoding.EncodeToString([]byte("<less")),
		"description: normal",
		"userPassword:: " + base64.StdEncoding.EncodeToString([]byte("secret")),
		"binary;binary:: " + base64.StdEncoding.EncodeToString([]byte("printable")),
	}
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Errorf("encoded request does not contain %q:\n%s", want, text)
		}
	}

	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	folded := false
	for _, line := range lines {
		if len(line) > sockLDIFLineWidth {
			t.Errorf("physical LDIF line has %d bytes, want <= %d: %q", len(line), sockLDIFLineWidth, line)
		}
		if strings.HasPrefix(line, " ") {
			folded = true
		}
	}
	if !folded {
		t.Fatal("long ADD value was not folded")
	}

	for name, operation := range map[string]SockOperation{
		"compare": SockCompareRequest{
			DN:        "uid=alice,dc=example,dc=com",
			Attribute: "description",
			Assertion: longValue,
		},
		"modify": SockModifyRequest{
			DN: "uid=alice,dc=example,dc=com",
			Changes: []ldapwire.Modification{{
				Operation: ldapwire.ModificationReplace,
				Attribute: directory.Attribute{
					Description: "description",
					Values:      [][]byte{longValue},
				},
			}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := EncodeSockRequest(
				SockRequest{MessageID: 1, Operation: operation},
				SockProtocolLimits{},
			)
			if err != nil {
				t.Fatalf("EncodeSockRequest(): %v", err)
			}
			continuation := false
			for _, line := range strings.Split(strings.TrimSuffix(string(encoded), "\n"), "\n") {
				if len(line) > sockLDIFLineWidth {
					t.Errorf(
						"physical LDIF line has %d bytes, want <= %d: %q",
						len(line),
						sockLDIFLineWidth,
						line,
					)
				}
				continuation = continuation || strings.HasPrefix(line, " ")
			}
			if !continuation {
				t.Fatal("long value was not folded")
			}
		})
	}
}

func TestSockProtocolEncodesEveryFilterChoice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		filter directory.Filter
		want   string
	}{
		{"and", directory.Filter{Kind: directory.FilterAnd, Children: []directory.Filter{{Kind: directory.FilterPresent, Attribute: "cn"}, {Kind: directory.FilterEquality, Attribute: "uid", Assertion: []byte("alice")}}}, "(&(cn=*)(uid=alice))"},
		{"or", directory.Filter{Kind: directory.FilterOr, Children: []directory.Filter{{Kind: directory.FilterPresent, Attribute: "cn"}, {Kind: directory.FilterPresent, Attribute: "sn"}}}, "(|(cn=*)(sn=*))"},
		{"not", directory.Filter{Kind: directory.FilterNot, Children: []directory.Filter{{Kind: directory.FilterPresent, Attribute: "mail"}}}, "(!(mail=*))"},
		{"equality", directory.Filter{Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte("a*b")}, `(cn=a\2ab)`},
		{"greater or equal", directory.Filter{Kind: directory.FilterGreaterOrEqual, Attribute: "uidNumber", Assertion: []byte("100")}, "(uidNumber>=100)"},
		{"less or equal", directory.Filter{Kind: directory.FilterLessOrEqual, Attribute: "uidNumber", Assertion: []byte("200")}, "(uidNumber<=200)"},
		{"approx", directory.Filter{Kind: directory.FilterApprox, Attribute: "cn", Assertion: []byte("Alice")}, "(cn~=Alice)"},
		{"substring", directory.Filter{Kind: directory.FilterSubstrings, Attribute: "cn", Substring: directory.Substring{Initial: []byte("Al"), Any: [][]byte{[]byte("i*ce")}, Final: []byte(" Smith")}}, `(cn=Al*i\2ace* Smith)`},
		{"extensible", directory.Filter{Kind: directory.FilterExtensible, Attribute: "cn", MatchingRule: "2.5.13.2", DNAttributes: true, Assertion: []byte("Alice")}, "(cn:dn:2.5.13.2:=Alice)"},
		{"extensible without attribute", directory.Filter{Kind: directory.FilterExtensible, MatchingRule: "2.5.13.2", Assertion: []byte("Alice")}, "(:2.5.13.2:=Alice)"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := encodeSockFilter(test.filter)
			if err != nil {
				t.Fatalf("encodeSockFilter(): %v", err)
			}
			if got != test.want {
				t.Fatalf("encodeSockFilter() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSockProtocolWriteRequest(t *testing.T) {
	t.Parallel()

	request := SockRequest{MessageID: 7, Operation: SockUnbindRequest{}}
	var output bytes.Buffer
	if err := WriteSockRequest(&output, request, SockProtocolLimits{}); err != nil {
		t.Fatalf("WriteSockRequest(): %v", err)
	}
	if output.String() != "UNBIND\nmsgid: 7\n\n" {
		t.Fatalf("written request = %q", output.String())
	}

	wantErr := errors.New("write failed")
	err := WriteSockRequest(sockErrorWriter{err: wantErr}, request, SockProtocolLimits{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("WriteSockRequest() error = %v, want wrapped %v", err, wantErr)
	}
}

func TestSockProtocolRequestValidation(t *testing.T) {
	t.Parallel()

	validSearch := SockSearchRequest{
		Scope:  directory.ScopeBase,
		Filter: directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"},
	}
	tests := []struct {
		name    string
		request SockRequest
		limits  SockProtocolLimits
		limit   bool
	}{
		{"zero message ID", SockRequest{Operation: SockUnbindRequest{}}, SockProtocolLimits{}, false},
		{"large message ID", SockRequest{MessageID: 1 << 31, Operation: SockUnbindRequest{}}, SockProtocolLimits{}, false},
		{"nil operation", SockRequest{MessageID: 1}, SockProtocolLimits{}, false},
		{"nil operation pointer", SockRequest{MessageID: 1, Operation: (*SockAddRequest)(nil)}, SockProtocolLimits{}, false},
		{"suffix injection", SockRequest{MessageID: 1, Suffixes: []string{"dc=example\nSEARCH"}, Operation: SockUnbindRequest{}}, SockProtocolLimits{}, false},
		{"binddn injection", SockRequest{MessageID: 1, Connection: SockConnectionFields{IncludeBindDN: true, BindDN: "x\r\ny"}, Operation: SockUnbindRequest{}}, SockProtocolLimits{}, false},
		{"negative SSF", SockRequest{MessageID: 1, Connection: SockConnectionFields{IncludeSSF: true, SSF: -1}, Operation: SockUnbindRequest{}}, SockProtocolLimits{}, false},
		{"bind binary NUL", SockRequest{MessageID: 1, Operation: SockBindRequest{Method: 128, Credentials: []byte{'a', 0, 'b'}}}, SockProtocolLimits{}, false},
		{"bind newline", SockRequest{MessageID: 1, Operation: SockBindRequest{Method: 128, Credentials: []byte("a\nb")}}, SockProtocolLimits{}, false},
		{"empty add DN", SockRequest{MessageID: 1, Operation: SockAddRequest{}}, SockProtocolLimits{}, false},
		{"bad add attribute", SockRequest{MessageID: 1, Operation: SockAddRequest{Entry: directory.Entry{DN: "dc=x", Attributes: []directory.Attribute{{Description: "bad name", Values: [][]byte{[]byte("x")}}}}}}, SockProtocolLimits{}, false},
		{"empty compare DN", SockRequest{MessageID: 1, Operation: SockCompareRequest{Attribute: "cn"}}, SockProtocolLimits{}, false},
		{"bad compare attribute", SockRequest{MessageID: 1, Operation: SockCompareRequest{DN: "dc=x", Attribute: "bad:name"}}, SockProtocolLimits{}, false},
		{"empty delete DN", SockRequest{MessageID: 1, Operation: SockDeleteRequest{}}, SockProtocolLimits{}, false},
		{"bad extended OID", SockRequest{MessageID: 1, Operation: SockExtendedRequest{OID: "not-an-oid"}}, SockProtocolLimits{}, false},
		{"hidden extended value", SockRequest{MessageID: 1, Operation: SockExtendedRequest{OID: "1.2.3", Value: []byte("x")}}, SockProtocolLimits{}, false},
		{"bad modify operation", SockRequest{MessageID: 1, Operation: SockModifyRequest{DN: "dc=x", Changes: []ldapwire.Modification{{Operation: 99, Attribute: directory.Attribute{Description: "cn"}}}}}, SockProtocolLimits{}, false},
		{"empty modrdn", SockRequest{MessageID: 1, Operation: SockModifyDNRequest{}}, SockProtocolLimits{}, false},
		{"hidden new superior", SockRequest{MessageID: 1, Operation: SockModifyDNRequest{DN: "dc=x", NewRDN: "dc=y", NewSuperior: "dc=z"}}, SockProtocolLimits{}, false},
		{"bad search scope", SockRequest{MessageID: 1, Operation: func() SockSearchRequest {
			value := validSearch
			value.Scope = directory.ScopeChildren + 1
			return value
		}()}, SockProtocolLimits{}, false},
		{"bad search deref", SockRequest{MessageID: 1, Operation: func() SockSearchRequest { value := validSearch; value.DerefAliases = 4; return value }()}, SockProtocolLimits{}, false},
		{"negative search limit", SockRequest{MessageID: 1, Operation: func() SockSearchRequest { value := validSearch; value.SizeLimit = -1; return value }()}, SockProtocolLimits{}, false},
		{"bad search attribute", SockRequest{MessageID: 1, Operation: func() SockSearchRequest { value := validSearch; value.Attributes = []string{"cn uid"}; return value }()}, SockProtocolLimits{}, false},
		{"bad search filter", SockRequest{MessageID: 1, Operation: SockSearchRequest{Filter: directory.Filter{Kind: directory.FilterNot}}}, SockProtocolLimits{}, false},
		{"request bytes", SockRequest{MessageID: 1, Operation: SockUnbindRequest{}}, SockProtocolLimits{MaxRequestBytes: 8}, true},
		{"request line", SockRequest{MessageID: 1, Operation: SockDeleteRequest{DN: "dc=example,dc=com"}}, SockProtocolLimits{MaxLineBytes: 8}, true},
		{"invalid limits", SockRequest{MessageID: 1, Operation: SockUnbindRequest{}}, SockProtocolLimits{MaxLineBytes: -1}, false},
		{"overflowing response limit", SockRequest{MessageID: 1, Operation: SockUnbindRequest{}}, SockProtocolLimits{MaxResponseBytes: int64(^uint64(0) >> 1)}, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := EncodeSockRequest(test.request, test.limits)
			if err == nil {
				t.Fatal("EncodeSockRequest() succeeded, want error")
			}
			want := ErrSockProtocol
			if test.limit {
				want = ErrSockProtocolLimit
			}
			if !errors.Is(err, want) {
				t.Fatalf("EncodeSockRequest() error = %v, want %v", err, want)
			}
		})
	}
}

func TestSockProtocolParsesSearchResponse(t *testing.T) {
	t.Parallel()

	input := "# generated by test\n" +
		"DEBUG: accepted search\n" +
		"dn: uid=alice,dc=example,dc=com\n" +
		"objectClass: inetOrgPerson\n" +
		"cn: Alice\n" +
		"description: a long value that is\n" +
		" folded across physical lines\n" +
		"jpegPhoto:: AP8Q\n" +
		"empty:\n\n" +
		"# between records\n" +
		"dn:: " + base64.StdEncoding.EncodeToString([]byte("uid=space user,dc=example,dc=com")) + "\n" +
		"cn:: " + base64.StdEncoding.EncodeToString([]byte(" leading")) + "\n\n" +
		"RESULT\n" +
		"code: 4\n" +
		"matched: dc=example,dc=com\n" +
		"info: size limit reached\n\n"

	response, err := ParseSockResponse(strings.NewReader(input), SockProtocolLimits{})
	if err != nil {
		t.Fatalf("ParseSockResponse(): %v", err)
	}
	want := SockResponse{
		Entries: []directory.Entry{
			{
				DN: "uid=alice,dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: [][]byte{[]byte("inetOrgPerson")}},
					{Description: "cn", Values: [][]byte{[]byte("Alice")}},
					{Description: "description", Values: [][]byte{[]byte("a long value that isfolded across physical lines")}},
					{Description: "jpegPhoto", Values: [][]byte{{0x00, 0xff, 0x10}}},
					{Description: "empty", Values: [][]byte{{}}},
				},
			},
			{
				DN: "uid=space user,dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "cn", Values: [][]byte{[]byte(" leading")}},
				},
			},
		},
		Result: ldapwire.Result{
			Code:              ldapwire.ResultSizeLimitExceeded,
			MatchedDN:         " dc=example,dc=com",
			DiagnosticMessage: " size limit reached",
		},
	}
	if !reflect.DeepEqual(response, want) {
		t.Fatalf("ParseSockResponse() mismatch\ngot:  %#v\nwant: %#v", response, want)
	}
}

func TestSockProtocolParsesMinimalAndCRLFResults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  ldapwire.Result
	}{
		{"minimal", "RESULT\n\n", ldapwire.Result{}},
		{"CRLF", "result\r\nCoDe: 6\r\nMaTcHeD: dc=x\r\nInFo: equal\r\n\r\n", ldapwire.Result{Code: ldapwire.ResultCompareTrue, MatchedDN: " dc=x", DiagnosticMessage: " equal"}},
		{"empty optional values", "RESULT\nmatched:\ninfo:\n\n", ldapwire.Result{}},
		{"OpenLDAP code whitespace", "RESULT\ncode:\t 80 \t\n\n", ldapwire.Result{Code: ldapwire.ResultOther}},
		{"UTF-8 and significant spaces", "RESULT\ninfo:  caf\xc3\xa9 \n\n", ldapwire.Result{DiagnosticMessage: "  caf\xc3\xa9 "}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseSockResponse(strings.NewReader(test.input), SockProtocolLimits{})
			if err != nil {
				t.Fatalf("ParseSockResponse(): %v", err)
			}
			if !reflect.DeepEqual(got.Result, test.want) || len(got.Entries) != 0 {
				t.Fatalf("ParseSockResponse() = %#v, want result %#v", got, test.want)
			}
		})
	}
}

func TestSockProtocolResponseRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	validEntry := "dn: dc=example,dc=com\nobjectClass: domain\n\n"
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"missing final newline", "RESULT"},
		{"missing blank terminator", "RESULT\n"},
		{"missing result", validEntry},
		{"entry after result", "RESULT\n\n" + validEntry},
		{"extra blank after result", "RESULT\n\n\n"},
		{"comment after result", "RESULT\n\n# trailing\n"},
		{"bad result header", "RESULTS\ncode: 0\n\n"},
		{"bad result line", "RESULT\ncode 0\n\n"},
		{"empty code", "RESULT\ncode:\n\n"},
		{"negative code", "RESULT\ncode: -1\n\n"},
		{"code cruft", "RESULT\ncode: 0 success\n\n"},
		{"duplicate code", "RESULT\ncode: 0\ncode: 1\n\n"},
		{"unknown result field", "RESULT\nreferral: ldap://example.test\n\n"},
		{"base64 result field", "RESULT\ninfo:: Zm9v\n\n"},
		{"folded result", "RESULT\ninfo: first\n second\n\n"},
		{"bare CR", "RESULT\ninfo: bad\rvalue\n\n"},
		{"NUL", "RESULT\ninfo: bad\x00value\n\n"},
		{"orphan continuation", " continuation\n\nRESULT\n\n"},
		{"entry missing dn", "cn: Alice\n\nRESULT\n\n"},
		{"entry malformed line", "dn: dc=x\ncn Alice\n\nRESULT\n\n"},
		{"entry duplicate dn", "dn: dc=x\ndn: dc=y\n\nRESULT\n\n"},
		{"entry bad attribute", "dn: dc=x\nbad name: value\n\nRESULT\n\n"},
		{"entry invalid base64", "dn: dc=x\ncn:: %%%\n\nRESULT\n\n"},
		{"entry URL value", "dn: dc=x\ncn:< file:///etc/passwd\n\nRESULT\n\n"},
		{"entry unsafe direct leading space", "dn: dc=x\ncn:  unsafe\n\nRESULT\n\n"},
		{"entry unsafe direct trailing space", "dn: dc=x\ncn: unsafe \n\nRESULT\n\n"},
		{"entry raw nonascii", "dn: dc=x\ncn: Alice\xc3\xa9\n\nRESULT\n\n"},
		{"entry DN decoded newline", "dn:: bGluZQpicmVhaw==\ncn: value\n\nRESULT\n\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseSockResponse(strings.NewReader(test.input), SockProtocolLimits{})
			if err == nil {
				t.Fatal("ParseSockResponse() succeeded, want error")
			}
			if !errors.Is(err, ErrSockProtocol) {
				t.Fatalf("ParseSockResponse() error = %v, want ErrSockProtocol", err)
			}
		})
	}
}

func TestSockProtocolResponseLimits(t *testing.T) {
	t.Parallel()

	entry := func(dn, attributes string) string {
		return "dn: " + dn + "\n" + attributes + "\n\n"
	}
	tests := []struct {
		name   string
		input  string
		limits SockProtocolLimits
	}{
		{"response bytes", "RESULT\ncode: 0\n\n", SockProtocolLimits{MaxResponseBytes: 10, MaxLineBytes: 5, MaxEntryBytes: 10}},
		{"line bytes", "RESULT\ninfo: too-long\n\n", SockProtocolLimits{MaxLineBytes: 8}},
		{"record bytes", entry("dc=x", "description: value") + "RESULT\n\n", SockProtocolLimits{MaxEntryBytes: 10}},
		{"entry count", entry("dc=one", "cn: one") + entry("dc=two", "cn: two") + "RESULT\n\n", SockProtocolLimits{MaxEntries: 1}},
		{"attribute count", entry("dc=x", "cn: x\nsn: y") + "RESULT\n\n", SockProtocolLimits{MaxAttributes: 1}},
		{"value count", entry("dc=x", "cn: x\ncn: y") + "RESULT\n\n", SockProtocolLimits{MaxValues: 1}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseSockResponse(strings.NewReader(test.input), test.limits)
			if err == nil {
				t.Fatal("ParseSockResponse() succeeded, want limit error")
			}
			if !errors.Is(err, ErrSockProtocolLimit) {
				t.Fatalf("ParseSockResponse() error = %v, want ErrSockProtocolLimit", err)
			}
		})
	}
}

func TestSockProtocolParserPropagatesReaderError(t *testing.T) {
	t.Parallel()

	want := errors.New("read failed")
	_, err := ParseSockResponse(sockErrorReader{err: want}, SockProtocolLimits{})
	if !errors.Is(err, want) {
		t.Fatalf("ParseSockResponse() error = %v, want wrapped %v", err, want)
	}
}

func TestSockProtocolPointerOperations(t *testing.T) {
	t.Parallel()

	operations := []SockOperation{
		&SockAddRequest{Entry: directory.Entry{DN: "dc=x"}},
		&SockBindRequest{Method: 128},
		&SockCompareRequest{DN: "dc=x", Attribute: "cn"},
		&SockDeleteRequest{DN: "dc=x"},
		&SockExtendedRequest{OID: "1.2.3"},
		&SockModifyRequest{DN: "dc=x"},
		&SockModifyDNRequest{DN: "dc=x", NewRDN: "dc=y"},
		&SockSearchRequest{Filter: directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"}},
		&SockUnbindRequest{},
	}
	for _, operation := range operations {
		if _, err := EncodeSockRequest(SockRequest{MessageID: 1, Operation: operation}, SockProtocolLimits{}); err != nil {
			t.Errorf("EncodeSockRequest(%T): %v", operation, err)
		}
	}
}

func FuzzParseSockResponse(f *testing.F) {
	f.Add([]byte("RESULT\ncode: 0\n\n"))
	f.Add([]byte("dn: dc=x\ncn: x\n\nRESULT\ncode: 0\n\n"))
	f.Add([]byte("RESULT\r\ncode: 80\r\ninfo: failed\r\n\r\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		limits := SockProtocolLimits{
			MaxResponseBytes: 8 << 10,
			MaxLineBytes:     1 << 10,
			MaxEntryBytes:    4 << 10,
			MaxEntries:       32,
			MaxAttributes:    64,
			MaxValues:        256,
		}
		response, err := ParseSockResponse(bytes.NewReader(input), limits)
		if err != nil {
			return
		}
		if len(response.Entries) > limits.MaxEntries {
			t.Fatalf("parser returned %d entries, maximum is %d", len(response.Entries), limits.MaxEntries)
		}
		for _, entry := range response.Entries {
			if len(entry.Attributes) > limits.MaxAttributes {
				t.Fatalf("parser returned %d attributes, maximum is %d", len(entry.Attributes), limits.MaxAttributes)
			}
		}
	})
}

type sockErrorWriter struct {
	err error
}

func (writer sockErrorWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

type sockErrorReader struct {
	err error
}

func (reader sockErrorReader) Read([]byte) (int, error) {
	return 0, reader.err
}

func ExampleEncodeSockRequest() {
	encoded, err := EncodeSockRequest(SockRequest{
		MessageID: 12,
		Suffixes:  []string{"dc=example,dc=com"},
		Operation: SockDeleteRequest{DN: "uid=alice,dc=example,dc=com"},
	}, SockProtocolLimits{})
	if err != nil {
		panic(err)
	}
	fmt.Print(string(encoded))
	// Output:
	// DELETE
	// msgid: 12
	// suffix: dc=example,dc=com
	// dn: uid=alice,dc=example,dc=com
	//
}

var _ io.Writer = sockErrorWriter{}
