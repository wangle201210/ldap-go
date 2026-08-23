package server

import (
	"fmt"
	"net"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	sockFrontendExactOID = "1.3.6.1.4.1.99999.934.1"
	sockFrontendFoldOID  = "1.3.6.1.4.1.99999.934.2"
	sockFrontendBaseDN   = "sockFoldName=Tenant,dc=example,dc=com"
)

func TestDNIdentitySockFrontendRequestDNs(t *testing.T) {
	registry, runtime, database := newDNIdentitySockFrontendRuntime(t)
	equivalentBase := sockFrontendFoldOID +
		`=\20TENANT\20,DC=EXAMPLE,DC=COM`
	target := "sockExactAlias=Alice," + equivalentBase
	filter := directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"}

	tests := []struct {
		name    string
		request ldapwire.Request
		rawDN   string
	}{
		{
			name: "add",
			request: ldapwire.AddRequest{Entry: directory.Entry{
				DN: target,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("top")},
					{Description: "sockExactName", Values: stringValues("Alice")},
				},
			}},
			rawDN: target,
		},
		{
			name:    "modify",
			request: ldapwire.ModifyRequest{DN: target},
			rawDN:   target,
		},
		{
			name:    "delete",
			request: ldapwire.DeleteRequest{DN: target},
			rawDN:   target,
		},
		{
			name: "compare",
			request: ldapwire.CompareRequest{
				DN: target, Attribute: "cn", Assertion: []byte("Alice"),
			},
			rawDN: target,
		},
		{
			name: "search",
			request: ldapwire.SearchRequest{
				BaseDN: target, Scope: directory.ScopeBase, Filter: filter,
			},
			rawDN: target,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validated, failure := validateSockBackendFrontend(
				runtime,
				database,
				test.request,
				requestControls{},
			)
			if failure != nil {
				t.Fatalf("validation failed: %#v", failure)
			}
			if got := sockFrontendRequestDN(validated); got != test.rawDN {
				t.Fatalf("forwarded DN = %q, want original %q", got, test.rawDN)
			}
		})
	}

	rootSearch, failure := validateSockBackendFrontend(
		runtime,
		database,
		ldapwire.SearchRequest{Scope: directory.ScopeBase, Filter: filter},
		requestControls{},
	)
	if failure != nil || rootSearch.(ldapwire.SearchRequest).BaseDN != "" {
		t.Fatalf("root DSE Search validation = %#v, %#v", rootSearch, failure)
	}

	invalidTarget := "undefinedNamingAttribute=value," + sockFrontendBaseDN
	for _, request := range []ldapwire.Request{
		ldapwire.AddRequest{Entry: directory.Entry{
			DN: invalidTarget,
			Attributes: []directory.Attribute{{
				Description: "objectClass", Values: stringValues("top"),
			}},
		}},
		ldapwire.ModifyRequest{DN: invalidTarget},
		ldapwire.DeleteRequest{DN: invalidTarget},
		ldapwire.CompareRequest{DN: invalidTarget, Attribute: "cn", Assertion: []byte("x")},
		ldapwire.SearchRequest{BaseDN: invalidTarget, Scope: directory.ScopeBase, Filter: filter},
	} {
		_, failure := validateSockBackendFrontend(
			runtime,
			database,
			request,
			requestControls{},
		)
		if failure == nil || failure.Code != ldapwire.ResultInvalidDNSyntax {
			t.Fatalf("%T invalid target result = %#v, want invalidDNSyntax", request, failure)
		}
	}

	caseExactUpper := "sockExactName=Alice," + sockFrontendBaseDN
	caseExactLower := "sockExactName=alice," + sockFrontendBaseDN
	upper, err := registry.NormalizeDN(caseExactUpper)
	if err != nil {
		t.Fatalf("NormalizeDN(caseExact upper): %v", err)
	}
	lower, err := registry.NormalizeDN(caseExactLower)
	if err != nil {
		t.Fatalf("NormalizeDN(caseExact lower): %v", err)
	}
	if upper.Equal(lower) {
		t.Fatal("caseExact request targets collapsed to one identity")
	}
}

func TestDNIdentitySockFrontendModifyDN(t *testing.T) {
	_, runtime, database := newDNIdentitySockFrontendRuntime(t)
	oldDN := "sockExactAlias=Parent+sockFoldAlias=Team," + sockFrontendBaseDN

	tests := []struct {
		name string
		req  ldapwire.ModifyDNRequest
		code ldapwire.ResultCode
	}{
		{
			name: "equivalent multi AVA new RDN already exists",
			req: ldapwire.ModifyDNRequest{
				DN: oldDN,
				NewRDN: sockFrontendFoldOID +
					`=\20TEAM\20+` + sockFrontendExactOID + "=Parent",
				DeleteOldRDN: true,
			},
			code: ldapwire.ResultEntryAlreadyExists,
		},
		{
			name: "caseIgnore equivalent superior is a subtree cycle",
			req: ldapwire.ModifyDNRequest{
				DN:             oldDN,
				NewRDN:         "sockExactName=Child",
				DeleteOldRDN:   true,
				NewSuperior:    sockFrontendFoldOID + "=TEAM+" + sockFrontendExactOID + "=Parent," + sockFrontendBaseDN,
				HasNewSuperior: true,
			},
			code: ldapwire.ResultUnwillingToPerform,
		},
		{
			name: "schema equivalent ancestor cannot replace parent",
			req: ldapwire.ModifyDNRequest{
				DN:             "cn=Leaf," + oldDN,
				NewRDN:         sockFrontendExactOID + "=Parent+" + sockFrontendFoldOID + "=team",
				DeleteOldRDN:   true,
				NewSuperior:    sockFrontendBaseDN,
				HasNewSuperior: true,
			},
			code: ldapwire.ResultUnwillingToPerform,
		},
		{
			name: "invalid new RDN attribute",
			req: ldapwire.ModifyDNRequest{
				DN: oldDN, NewRDN: "undefinedNamingAttribute=value", DeleteOldRDN: true,
			},
			code: ldapwire.ResultInvalidDNSyntax,
		},
		{
			name: "invalid new superior attribute",
			req: ldapwire.ModifyDNRequest{
				DN: oldDN, NewRDN: "sockExactName=Moved", DeleteOldRDN: true,
				NewSuperior:    "undefinedNamingAttribute=value," + sockFrontendBaseDN,
				HasNewSuperior: true,
			},
			code: ldapwire.ResultInvalidDNSyntax,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validated, failure := validateSockBackendFrontend(
				runtime, database, test.req, requestControls{},
			)
			if failure == nil || failure.Code != test.code {
				t.Fatalf("ModifyDN validation = %#v, want code %d", failure, test.code)
			}
			forwarded := validated.(ldapwire.ModifyDNRequest)
			if forwarded.DN != test.req.DN ||
				forwarded.NewRDN != test.req.NewRDN ||
				forwarded.NewSuperior != test.req.NewSuperior {
				t.Fatalf("ModifyDN display fields changed: %#v", forwarded)
			}
		})
	}

	caseExactDistinct := ldapwire.ModifyDNRequest{
		DN:             oldDN,
		NewRDN:         "sockExactName=Moved",
		DeleteOldRDN:   true,
		NewSuperior:    "sockExactAlias=parent+sockFoldAlias=TEAM," + sockFrontendBaseDN,
		HasNewSuperior: true,
	}
	validated, failure := validateSockBackendFrontend(
		runtime, database, caseExactDistinct, requestControls{},
	)
	if failure != nil {
		t.Fatalf("caseExact-distinct superior was treated as a cycle: %#v", failure)
	}
	if got := validated.(ldapwire.ModifyDNRequest); got != caseExactDistinct {
		t.Fatalf("ModifyDN display fields changed: %#v", got)
	}
}

func TestDNIdentitySockFrontendRelaxAndDNAssertion(t *testing.T) {
	registry, runtime, database := newDNIdentitySockFrontendRuntime(t)
	entryDN := "sockExactName=Entry," + sockFrontendBaseDN
	exactUpper := "sockExactAlias=Owner+sockFoldAlias=Team," + sockFrontendBaseDN
	exactLower := "sockExactAlias=owner+sockFoldAlias=TEAM," + sockFrontendBaseDN

	_, failure := validateSockBackendFrontend(
		runtime,
		database,
		ldapwire.AddRequest{Entry: directory.Entry{
			DN: entryDN,
			Attributes: []directory.Attribute{{
				Description: "modifiersName",
				Values:      stringValues(exactUpper),
			}},
		}},
		requestControls{relax: true},
	)
	if failure != nil {
		t.Fatalf("Relax rejected schema-aware DN value: %#v", failure)
	}

	for _, value := range []string{exactLower, "undefinedNamingAttribute=value," + sockFrontendBaseDN} {
		_, failure = validateSockBackendFrontend(
			runtime,
			database,
			ldapwire.AddRequest{Entry: directory.Entry{
				DN: entryDN,
				Attributes: []directory.Attribute{{
					Description: "modifiersName",
					Values:      stringValues(value),
				}},
			}},
			requestControls{relax: true},
		)
		if value == exactLower && failure != nil {
			t.Fatalf("Relax collapsed caseExact DN identity: %#v", failure)
		}
		if value != exactLower &&
			(failure == nil || failure.Code != ldapwire.ResultInvalidAttributeSyntax) {
			t.Fatalf("Relax invalid DN value = %#v, want invalidAttributeSyntax", failure)
		}
	}

	foldEquivalent := sockFrontendFoldOID +
		`=\20TEAM\20+` + sockFrontendExactOID + "=Owner," + sockFrontendBaseDN
	request := ldapwire.CompareRequest{
		DN:        entryDN,
		Attribute: "seeAlso",
		Assertion: []byte(foldEquivalent),
	}
	validated, failure := validateSockBackendFrontend(
		runtime, database, request, requestControls{},
	)
	if failure != nil {
		t.Fatalf("DN Compare assertion validation: %#v", failure)
	}
	wantDN, err := registry.NormalizeDN(foldEquivalent)
	if err != nil {
		t.Fatalf("NormalizeDN(assertion): %v", err)
	}
	compare := validated.(ldapwire.CompareRequest)
	if string(compare.Assertion) != wantDN.NormalizedString() {
		t.Fatalf("normalized DN assertion = %q, want %q", compare.Assertion, wantDN.NormalizedString())
	}
	if compare.DN != request.DN {
		t.Fatalf("Compare target display DN = %q, want %q", compare.DN, request.DN)
	}
}

func TestDNIdentitySockFrontendTransportPreservesDisplayAndRejectsCycle(t *testing.T) {
	requireSockRuntimeUnix(t)
	registry := newDNIdentitySockFrontendRegistry(t)
	fixture := startSockRuntimeFixture(t, func(
		connection net.Conn,
		request sockRuntimeCapturedRequest,
	) error {
		if request.command == "UNBIND" {
			return nil
		}
		code := ldapwire.ResultSuccess
		if request.command == "COMPARE" {
			code = ldapwire.ResultCompareTrue
		}
		return writeAll(connection, []byte(fmt.Sprintf(
			"RESULT\ncode: %d\nmatched:\ninfo:\n\n",
			code,
		)))
	})
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSockRuntimeConfiguration(t, store, sockRuntimeDatabaseSeed{
		order:  1,
		suffix: sockFrontendBaseDN,
		path:   fixture.path,
		access: []string{"{0}to * by * manage"},
	})
	accessRule, err := acl.ParseRule("to * by * manage")
	if err != nil {
		t.Fatalf("ParseRule(): %v", err)
	}
	accessPolicy, err := acl.NewPolicy([]acl.Rule{accessRule}, nil)
	if err != nil {
		t.Fatalf("NewPolicy(): %v", err)
	}
	address, stop := startServer(t, store, Config{
		Schema:       registry,
		AccessPolicy: accessPolicy,
	})
	t.Cleanup(stop)
	client := dialSockRuntimeClient(t, address)
	t.Cleanup(func() { _ = client.Close() })

	rawBase := sockFrontendFoldOID + `=\20TENANT\20,DC=EXAMPLE,DC=COM`
	oldDN := "sockExactAlias=Parent+sockFoldAlias=Team," + rawBase
	if err := client.Bind(oldDN, "secret"); err != nil {
		t.Fatalf("Bind(schema-aware DN): %v", err)
	}
	bindRequest := fixture.take(t)
	assertSockRuntimeCommand(t, bindRequest, "BIND")
	assertSockRuntimeField(t, bindRequest, "dn", oldDN)

	search := ldap.NewSearchRequest(
		rawBase,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"objectClass"},
		nil,
	)
	if _, err := client.Search(search); err != nil {
		t.Fatalf("Search(schema-equivalent base): %v", err)
	}
	searchRequest := fixture.take(t)
	assertSockRuntimeCommand(t, searchRequest, "SEARCH")
	assertSockRuntimeField(t, searchRequest, "base", rawBase)

	entryDN := "sockExactAlias=Display+sockFoldAlias=Target," + rawBase
	add := ldap.NewAddRequest(entryDN, nil)
	add.Attribute("objectClass", []string{"top"})
	add.Attribute("sockExactAlias", []string{"Display"})
	add.Attribute("sockFoldAlias", []string{"Target"})
	if err := client.Add(add); err != nil {
		t.Fatalf("Add(schema-aware DN): %v", err)
	}
	addRequest := fixture.take(t)
	assertSockRuntimeCommand(t, addRequest, "ADD")
	assertSockRuntimeField(t, addRequest, "dn", entryDN)

	modify := ldap.NewModifyRequest(entryDN, nil)
	modify.Replace("description", []string{"display target"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify(schema-aware DN): %v", err)
	}
	modifyRequest := fixture.take(t)
	assertSockRuntimeCommand(t, modifyRequest, "MODIFY")
	assertSockRuntimeField(t, modifyRequest, "dn", entryDN)

	matched, err := client.Compare(entryDN, "cn", "Display Target")
	if err != nil || !matched {
		t.Fatalf("Compare(schema-aware DN) = %t, %v", matched, err)
	}
	compareRequest := fixture.take(t)
	assertSockRuntimeCommand(t, compareRequest, "COMPARE")
	assertSockRuntimeField(t, compareRequest, "dn", entryDN)

	if err := client.Del(ldap.NewDelRequest(entryDN, nil)); err != nil {
		t.Fatalf("Delete(schema-aware DN): %v", err)
	}
	deleteRequest := fixture.take(t)
	assertSockRuntimeCommand(t, deleteRequest, "DELETE")
	assertSockRuntimeField(t, deleteRequest, "dn", entryDN)

	caseExactSuperior := "sockExactAlias=parent+sockFoldAlias=TEAM," + rawBase
	newRDN := "sockExactAlias=Moved"
	if err := client.ModifyDN(ldap.NewModifyDNRequest(
		oldDN,
		newRDN,
		true,
		caseExactSuperior,
	)); err != nil {
		t.Fatalf("ModifyDN(caseExact-distinct superior): %v", err)
	}
	modifyDNRequest := fixture.take(t)
	assertSockRuntimeCommand(t, modifyDNRequest, "MODRDN")
	assertSockRuntimeField(t, modifyDNRequest, "dn", oldDN)
	assertSockRuntimeField(t, modifyDNRequest, "newrdn", newRDN)
	assertSockRuntimeField(t, modifyDNRequest, "newsuperior", caseExactSuperior)

	equivalentSuperior := sockFrontendFoldOID + "=TEAM+" +
		sockFrontendExactOID + "=Parent," + rawBase
	err = client.ModifyDN(ldap.NewModifyDNRequest(
		oldDN,
		"sockExactName=Child",
		true,
		equivalentSuperior,
	))
	assertSockRuntimeLDAPError(
		t,
		err,
		ldap.LDAPResultUnwillingToPerform,
		"cannot place an entry below itself",
	)
	assertNoDNIdentitySockFrontendRequest(t, fixture)
}

func newDNIdentitySockFrontendRuntime(
	t *testing.T,
) (*schema.Registry, *runtimeState, runtimeDatabase) {
	t.Helper()
	registry := newDNIdentitySockFrontendRegistry(t)
	suffix := mustDNIdentitySockFrontendDN(t, registry, sockFrontendBaseDN)
	database := runtimeDatabase{
		name:          "{1}sock",
		partition:     "dn-identity-sock",
		suffixes:      []directory.DN{suffix},
		dnNormalizer:  registry,
		configDNKey:   "olcdatabase={1}sock,cn=config",
		sockBackend:   &sockBackendRuntimeConfiguration{},
		maxDerefDepth: defaultAliasDerefDepth,
	}
	runtime := &runtimeState{schema: registry, databases: []runtimeDatabase{database}}
	return registry, runtime, database
}

func newDNIdentitySockFrontendRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( " + sockFrontendExactOID + " NAME ( 'sockExactName' 'sockExactAlias' ) " +
			"EQUALITY caseExactMatch ORDERING caseExactOrderingMatch " +
			"SUBSTR caseExactSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
		"( " + sockFrontendFoldOID + " NAME ( 'sockFoldName' 'sockFoldAlias' ) " +
			"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
			"SUBSTR caseIgnoreSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", definition, err)
		}
	}
	return registry
}

func mustDNIdentitySockFrontendDN(
	t *testing.T,
	registry *schema.Registry,
	value string,
) directory.DN {
	t.Helper()
	dn, err := registry.NormalizeDN(value)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", value, err)
	}
	return dn
}

func sockFrontendRequestDN(request ldapwire.Request) string {
	switch request := request.(type) {
	case ldapwire.AddRequest:
		return request.Entry.DN
	case ldapwire.ModifyRequest:
		return request.DN
	case ldapwire.DeleteRequest:
		return request.DN
	case ldapwire.CompareRequest:
		return request.DN
	case ldapwire.SearchRequest:
		return request.BaseDN
	default:
		return ""
	}
}

func assertNoDNIdentitySockFrontendRequest(
	t *testing.T,
	fixture *sockRuntimeFixture,
) {
	t.Helper()
	select {
	case request := <-fixture.requests:
		t.Fatalf("socket unexpectedly received %s request: %#v", request.command, request.fields)
	case err := <-fixture.failures:
		t.Fatalf("socket fixture failed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}
