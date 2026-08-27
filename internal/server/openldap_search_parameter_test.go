package server

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPSearchParameterErrorsKeepConnectionUsable(t *testing.T) {
	t.Parallel()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	defer stop()
	observation := observeSearchParameterErrors(t, address)
	assertSearchParameterObservation(t, observation)
}

func TestOpenLDAPReferenceSearchParameterErrors(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServer(t, tools, nil)
	defer stopReference()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	localAddress, stopLocal := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	defer stopLocal()

	reference := observeSearchParameterErrors(
		t,
		strings.TrimPrefix(referenceURI, "ldap://"),
	)
	local := observeSearchParameterErrors(t, localAddress)
	if !reflect.DeepEqual(reference, local) {
		t.Fatalf(
			"Search parameter errors:\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			local,
		)
	}
	assertSearchParameterObservation(t, local)
}

type searchParameterObservation struct {
	outcomes []searchParameterOutcome
}

type searchParameterOutcome struct {
	name       string
	code       int64
	diagnostic string
	whoAmI     int64
}

func observeSearchParameterErrors(
	t *testing.T,
	address string,
) searchParameterObservation {
	t.Helper()
	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	defer connection.Close()
	tests := []struct {
		name                   string
		scope, deref, size, tm int64
	}{
		{name: "invalid time", scope: 2, deref: 0, size: 0, tm: -1},
		{name: "invalid size", scope: 2, deref: 0, size: -1, tm: 0},
		{name: "scope above range", scope: 4, deref: 0, size: 0, tm: 0},
		{name: "negative scope", scope: -1, deref: 0, size: 0, tm: 0},
		{name: "deref above range", scope: 2, deref: 4, size: 0, tm: 0},
		{name: "negative deref", scope: 2, deref: -1, size: 0, tm: 0},
		{name: "validation order", scope: 4, deref: 4, size: -1, tm: -1},
	}
	observation := searchParameterObservation{
		outcomes: make([]searchParameterOutcome, 0, len(tests)),
	}
	messageID := int64(2)
	for _, test := range tests {
		response := sendRawLDAPOperation(
			t,
			connection,
			messageID,
			rawSearchWithParameters(t, test.scope, test.deref, test.size, test.tm),
		)
		assertRawLDAPEnvelope(
			t,
			response,
			messageID,
			ldapwire.ApplicationSearchResultDone,
			int64(ldap.LDAPResultProtocolError),
		)
		messageID++
		whoAmI := sendRawLDAPOperation(
			t,
			connection,
			messageID,
			rawExtendedRequest(whoAmIOID, nil, false),
		)
		assertRawLDAPEnvelope(
			t,
			whoAmI,
			messageID,
			ldapwire.ApplicationExtendedResponse,
			int64(ldap.LDAPResultSuccess),
		)
		observation.outcomes = append(observation.outcomes, searchParameterOutcome{
			name:       test.name,
			code:       rawLDAPResultCode(t, response.Children[1]),
			diagnostic: rawLDAPDiagnostic(response),
			whoAmI:     rawLDAPResultCode(t, whoAmI.Children[1]),
		})
		messageID++
	}
	return observation
}

func assertSearchParameterObservation(
	t *testing.T,
	observation searchParameterObservation,
) {
	t.Helper()
	wantDiagnostics := []string{
		"invalid time limit",
		"invalid size limit",
		"invalid scope",
		"invalid scope",
		"invalid deref",
		"invalid deref",
		"invalid time limit",
	}
	if len(observation.outcomes) != len(wantDiagnostics) {
		t.Fatalf("Search parameter outcomes = %#v", observation.outcomes)
	}
	for index, outcome := range observation.outcomes {
		if outcome.code != int64(ldap.LDAPResultProtocolError) ||
			outcome.diagnostic != wantDiagnostics[index] ||
			outcome.whoAmI != int64(ldap.LDAPResultSuccess) {
			t.Fatalf("Search parameter outcome %d = %#v", index, outcome)
		}
	}
}

func rawSearchWithParameters(
	t *testing.T,
	scope,
	deref,
	sizeLimit,
	timeLimit int64,
) *ber.Packet {
	t.Helper()
	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationSearchRequest,
		nil,
		"SearchRequest",
	)
	request.AppendChild(rawOctetString([]byte("dc=example,dc=com")))
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		scope,
		"scope",
	))
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		deref,
		"derefAliases",
	))
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		sizeLimit,
		"sizeLimit",
	))
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		timeLimit,
		"timeLimit",
	))
	request.AppendChild(ber.NewLDAPBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		false,
		"typesOnly",
	))
	filter, err := ldap.CompileFilter("(objectClass=*)")
	if err != nil {
		t.Fatalf("CompileFilter(): %v", err)
	}
	request.AppendChild(filter)
	attributes := ber.NewSequence("attributes")
	attributes.AppendChild(rawOctetString([]byte("*")))
	request.AppendChild(attributes)
	message := ber.NewSequence("LDAPMessage")
	message.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(1),
		"messageID",
	))
	message.AppendChild(request)
	encoded := message.Bytes()
	decoded, err := ldapwire.ReadMessage(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatalf("decode generated Search request: %v", err)
	}
	search, ok := decoded.Request.(ldapwire.SearchRequest)
	if !ok || int64(search.Scope) != scope || int64(search.DerefAliases) != deref ||
		int64(search.SizeLimit) != sizeLimit || int64(search.TimeLimit) != timeLimit {
		t.Fatalf("generated Search request = %#v", decoded.Request)
	}
	return request
}
