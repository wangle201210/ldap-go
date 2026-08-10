package server

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
)

func TestSockBackendControlSupport(t *testing.T) {
	t.Parallel()

	for _, request := range []ldapwire.Request{
		ldapwire.AddRequest{},
		ldapwire.ModifyRequest{},
		ldapwire.DeleteRequest{},
		ldapwire.ModifyDNRequest{},
	} {
		if support := sockBackendControlSupport(request); support != supportsRelax {
			t.Errorf("%T support = %d, want Relax", request, support)
		}
	}
	for _, request := range []ldapwire.Request{
		ldapwire.SearchRequest{},
		ldapwire.CompareRequest{},
	} {
		if support := sockBackendControlSupport(request); support != supportsDontUseCopy {
			t.Errorf("%T support = %d, want DontUseCopy", request, support)
		}
	}
	if support := sockBackendControlSupport(ldapwire.ExtendedRequest{}); support != 0 {
		t.Errorf("ExtendedRequest support = %d, want none", support)
	}
}

func TestValidateSockBackendFrontendSchemaRules(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("schema.NewBuiltinRegistry(): %v", err)
	}
	runtime, database := sockFrontendTestRuntime(t, registry)

	tests := []struct {
		name string
		req  ldapwire.Request
		code ldapwire.ResultCode
	}{
		{
			name: "add without attributes",
			req: ldapwire.AddRequest{Entry: directory.Entry{
				DN: "uid=alice,ou=people,dc=sock,dc=example",
			}},
			code: ldapwire.ResultProtocolError,
		},
		{
			name: "add undefined attribute",
			req: ldapwire.AddRequest{Entry: directory.Entry{
				DN: "uid=alice,ou=people,dc=sock,dc=example",
				Attributes: []directory.Attribute{{
					Description: "notRegistered",
					Values:      stringValues("value"),
				}},
			}},
			code: ldapwire.ResultUndefinedAttributeType,
		},
		{
			name: "add invalid syntax",
			req: ldapwire.AddRequest{Entry: directory.Entry{
				DN: "uid=alice,ou=people,dc=sock,dc=example",
				Attributes: []directory.Attribute{{
					Description: "uidNumber",
					Values:      stringValues("not-an-integer"),
				}},
			}},
			code: ldapwire.ResultInvalidAttributeSyntax,
		},
		{
			name: "add duplicate normalized value",
			req: ldapwire.AddRequest{Entry: directory.Entry{
				DN: "uid=alice,ou=people,dc=sock,dc=example",
				Attributes: []directory.Attribute{{
					Description: "cn",
					Values:      stringValues("Alice Example", " alice   EXAMPLE "),
				}},
			}},
			code: ldapwire.ResultAttributeOrValueExists,
		},
		{
			name: "add multiple single values",
			req: ldapwire.AddRequest{Entry: directory.Entry{
				DN: "uid=alice,ou=people,dc=sock,dc=example",
				Attributes: []directory.Attribute{{
					Description: "uidNumber",
					Values:      stringValues("1", "2"),
				}},
			}},
			code: ldapwire.ResultConstraintViolation,
		},
		{
			name: "modify add without values",
			req: ldapwire.ModifyRequest{
				DN: "uid=alice,ou=people,dc=sock,dc=example",
				Changes: []ldapwire.Modification{{
					Operation: ldapwire.ModificationAdd,
					Attribute: directory.Attribute{Description: "description"},
				}},
			},
			code: ldapwire.ResultProtocolError,
		},
		{
			name: "modify increment with multiple values",
			req: ldapwire.ModifyRequest{
				DN: "uid=alice,ou=people,dc=sock,dc=example",
				Changes: []ldapwire.Modification{{
					Operation: ldapwire.ModificationIncrement,
					Attribute: directory.Attribute{
						Description: "uidNumber",
						Values:      stringValues("1", "2"),
					},
				}},
			},
			code: ldapwire.ResultProtocolError,
		},
		{
			name: "sock backend does not advertise increment",
			req: ldapwire.ModifyRequest{
				DN: "uid=alice,ou=people,dc=sock,dc=example",
				Changes: []ldapwire.Modification{{
					Operation: ldapwire.ModificationIncrement,
					Attribute: directory.Attribute{
						Description: "uidNumber",
						Values:      stringValues("1"),
					},
				}},
			},
			code: ldapwire.ResultUnwillingToPerform,
		},
		{
			name: "compare undefined attribute",
			req: ldapwire.CompareRequest{
				DN:        "uid=alice,ou=people,dc=sock,dc=example",
				Attribute: "notRegistered",
				Assertion: []byte("value"),
			},
			code: ldapwire.ResultUndefinedAttributeType,
		},
		{
			name: "compare invalid assertion",
			req: ldapwire.CompareRequest{
				DN:        "uid=alice,ou=people,dc=sock,dc=example",
				Attribute: "uidNumber",
				Assertion: []byte("not-an-integer"),
			},
			code: ldapwire.ResultInvalidAttributeSyntax,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, failure := validateSockBackendFrontend(
				runtime,
				database,
				test.req,
				requestControls{},
			)
			if failure == nil || failure.Code != test.code {
				t.Fatalf("validation result = %#v, want code %d", failure, test.code)
			}
		})
	}

	normalized, failure := validateSockBackendFrontend(
		runtime,
		database,
		ldapwire.CompareRequest{
			DN:        "uid=alice,ou=people,dc=sock,dc=example",
			Attribute: "cn",
			Assertion: []byte("  Alice   EXAMPLE "),
		},
		requestControls{},
	)
	if failure != nil {
		t.Fatalf("valid Compare validation = %#v", failure)
	}
	compare := normalized.(ldapwire.CompareRequest)
	if string(compare.Assertion) != "alice example" {
		t.Fatalf("normalized Compare assertion = %q", compare.Assertion)
	}

	normalized, failure = validateSockBackendFrontend(
		runtime,
		database,
		ldapwire.CompareRequest{
			DN:        "cn=subschema",
			Attribute: "dITStructureRules",
			Assertion: []byte("17"),
		},
		requestControls{},
	)
	if failure != nil {
		t.Fatalf("first-component Compare validation = %#v", failure)
	}
	compare = normalized.(ldapwire.CompareRequest)
	if string(compare.Assertion) != "17" {
		t.Fatalf("first-component Compare assertion = %q", compare.Assertion)
	}
}

func TestValidateSockBackendFrontendModifyDN(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("schema.NewBuiltinRegistry(): %v", err)
	}
	runtime, database := sockFrontendTestRuntime(t, registry)

	for _, test := range []struct {
		name string
		req  ldapwire.ModifyDNRequest
		code ldapwire.ResultCode
	}{
		{
			name: "invalid RDN",
			req: ldapwire.ModifyDNRequest{
				DN:          "uid=alice,ou=people,dc=sock,dc=example",
				NewRDN:      "uid",
				NewSuperior: "",
			},
			code: ldapwire.ResultInvalidDNSyntax,
		},
		{
			name: "invalid superior",
			req: ldapwire.ModifyDNRequest{
				DN:             "uid=alice,ou=people,dc=sock,dc=example",
				NewRDN:         "uid=alice",
				NewSuperior:    "not-a-dn",
				HasNewSuperior: true,
			},
			code: ldapwire.ResultInvalidDNSyntax,
		},
		{
			name: "cross database",
			req: ldapwire.ModifyDNRequest{
				DN:             "uid=alice,ou=people,dc=sock,dc=example",
				NewRDN:         "uid=alice",
				NewSuperior:    "ou=people,dc=example,dc=com",
				HasNewSuperior: true,
			},
			code: ldapwire.ResultAffectsMultipleDSAs,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, failure := validateSockBackendFrontend(
				runtime,
				database,
				test.req,
				requestControls{},
			)
			if failure == nil || failure.Code != test.code {
				t.Fatalf("ModifyDN validation = %#v, want code %d", failure, test.code)
			}
		})
	}
}

func TestValidateSockBackendFrontendDontUseCopy(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("schema.NewBuiltinRegistry(): %v", err)
	}
	runtime, database := sockFrontendTestRuntime(t, registry)
	database.shadow = true
	controls := requestControls{dontUseCopy: true}

	_, failure := validateSockBackendFrontend(
		runtime,
		database,
		ldapwire.CompareRequest{
			DN:        "uid=alice,ou=people,dc=sock,dc=example",
			Attribute: "uidNumber",
			Assertion: []byte("not-an-integer"),
		},
		controls,
	)
	if failure == nil || failure.Code != ldapwire.ResultInvalidAttributeSyntax {
		t.Fatalf("invalid Compare plus DontUseCopy = %#v", failure)
	}

	_, failure = validateSockBackendFrontend(
		runtime,
		database,
		ldapwire.CompareRequest{
			DN:        "uid=alice,ou=people,dc=sock,dc=example",
			Attribute: "uidNumber",
			Assertion: []byte("1"),
		},
		controls,
	)
	if failure == nil ||
		failure.Code != ldapwire.ResultUnwillingToPerform ||
		failure.DiagnosticMessage != "copy not used" {
		t.Fatalf("valid shadow Compare plus DontUseCopy = %#v", failure)
	}

	search := ldapwire.SearchRequest{
		BaseDN: "ou=people,dc=sock,dc=example",
		Scope:  directory.ScopeWholeSubtree,
	}
	_, failure = validateSockBackendFrontend(
		runtime,
		database,
		search,
		controls,
	)
	if failure == nil ||
		failure.Code != ldapwire.ResultUnwillingToPerform ||
		failure.DiagnosticMessage !=
			"copy not used; no referral information available" {
		t.Fatalf("shadow Search without update referral = %#v", failure)
	}

	database.updateRefs = []string{"ldap://provider.example"}
	_, failure = validateSockBackendFrontend(
		runtime,
		database,
		search,
		controls,
	)
	if failure == nil ||
		failure.Code != ldapwire.ResultReferral ||
		len(failure.Referrals) != 1 {
		t.Fatalf("shadow Search with update referral = %#v", failure)
	}
}

func sockFrontendTestRuntime(
	t *testing.T,
	registry *schema.Registry,
) (*runtimeState, runtimeDatabase) {
	t.Helper()
	sockSuffix, err := directory.ParseDN("ou=people,dc=sock,dc=example")
	if err != nil {
		t.Fatalf("ParseDN(sock suffix): %v", err)
	}
	localSuffix, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(local suffix): %v", err)
	}
	database := runtimeDatabase{
		name:        "sock",
		configDNKey: "olcdatabase={1}sock,cn=config",
		suffixes:    []directory.DN{sockSuffix},
	}
	runtime := &runtimeState{
		schema: registry,
		databases: []runtimeDatabase{
			database,
			{
				name:        "mdb",
				configDNKey: "olcdatabase={2}mdb,cn=config",
				suffixes:    []directory.DN{localSuffix},
			},
		},
	}
	return runtime, database
}
