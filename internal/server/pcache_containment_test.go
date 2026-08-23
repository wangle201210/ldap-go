package server

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
)

func TestPcacheSchemaAwareTemplateContainment(t *testing.T) {
	t.Parallel()
	registry := pcacheContainmentRegistry(t)

	tests := []struct {
		name     string
		template string
		request  string
		want     bool
	}{
		{"attribute alias and equality normalization", "(userid=Smith)", "(0.9.2342.19200300.100.1.1= smith )", true},
		{"object class descendant containment", "(objectClass=person)", "(2.5.4.0=inetOrgPerson)", true},
		{"object class reverse containment rejected", "(objectClass=inetOrgPerson)", "(2.5.4.0=person)", false},
		{"case exact remains exact", "(pcacheExact=Alice)", "(1.3.6.1.4.1.4203.999.31=alice)", false},
		{"blank equality template", "(sn=)", "(2.5.4.4=Smith)", true},
		{"blank equality accepts substring shape", "(sn=)", "(2.5.4.4=Sm*th)", true},
		{"unordered and", "(&(sn=)(cn=Alice))", "(&(2.5.4.3=alice)(2.5.4.4=Smith))", true},
		{"unordered or", "(|(sn=Smith)(cn=))", "(|(2.5.4.3=Alice)(2.5.4.4= smith ))", true},
		{"duplicate children require distinct matches", "(&(cn=)(cn=Alice))", "(&(2.5.4.3=Bob)(cn=alice))", true},
		{"different boolean operator", "(&(cn=)(sn=))", "(|(cn=Alice)(sn=Smith))", false},
		{"unknown attribute fails closed", "(cn=)", "(pcacheUnknown=value)", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			template := pcacheCompileFilter(t, test.template)
			request := pcacheCompileFilter(t, test.request)
			if got := pcacheFilterMatchesTemplate(registry, template, request); got != test.want {
				t.Fatalf("pcacheFilterMatchesTemplate(%s, %s) = %t, want %t", test.template, test.request, got, test.want)
			}
		})
	}
}

func TestPcacheSubstringContainmentDirection(t *testing.T) {
	t.Parallel()
	registry := pcacheContainmentRegistry(t)

	tests := []struct {
		name     string
		template string
		request  string
		want     bool
	}{
		{"substring answers equality", "(cn=Al*ice)", "(2.5.4.3=Alice)", true},
		{"missing fixed any rejects equality", "(cn=Al*middle*ice)", "(cn=Alice)", false},
		{"narrower incoming substring", "(cn=Al*ice)", "(cn=Alice*Smith*ice)", true},
		{"case and spaces normalize", "(cn=AL*SMITH)", "(cn=Alice*  smith)", true},
		{"wider incoming initial rejected", "(cn=Alice*)", "(cn=Al*)", false},
		{"wider incoming final rejected", "(cn=*Smith)", "(cn=*mith)", false},
		{"fixed any cannot bridge request gaps", "(cn=*bc*)", "(cn=*ab*cd*)", false},
		{"request substring cannot use equality cache", "(cn=Alice)", "(cn=Al*ice)", false},
		{"case exact substring remains exact", "(pcacheExact=Al*ice)", "(1.3.6.1.4.1.4203.999.31=al*ice)", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := pcacheFilterMatchesTemplate(
				registry,
				pcacheCompileFilter(t, test.template),
				pcacheCompileFilter(t, test.request),
			); got != test.want {
				t.Fatalf("containment %s -> %s = %t, want %t", test.template, test.request, got, test.want)
			}
		})
	}
}

func TestPcacheExtensibleTemplateSemantics(t *testing.T) {
	t.Parallel()
	registry := pcacheContainmentRegistry(t)

	tests := []struct {
		name     string
		template string
		request  string
		want     bool
	}{
		{"attribute and matching rule aliases", "(cn:caseIgnoreMatch:=)", "(2.5.4.3:2.5.13.2:= Alice )", true},
		{"fixed assertion normalization", "(cn:caseIgnoreMatch:=Alice Smith)", "(2.5.4.3:2.5.13.2:= alice  smith )", true},
		{"implicit and explicit equality rule", "(cn:=)", "(2.5.4.3:2.5.13.2:=Alice)", true},
		{"attribute-free rule alias", "(:caseIgnoreMatch:=)", "(:2.5.13.2:=Alice)", true},
		{"different matching rule", "(cn:caseIgnoreMatch:=)", "(cn:caseExactMatch:=Alice)", false},
		{"different dnAttributes", "(cn:caseIgnoreMatch:=)", "(cn:dn:2.5.13.2:=Alice)", false},
		{"attribute-free shape differs", "(:caseIgnoreMatch:=)", "(cn:caseIgnoreMatch:=Alice)", false},
		{"unknown matching rule fails closed", "(cn:unknownMatch:=)", "(cn:unknownMatch:=Alice)", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := pcacheFilterMatchesTemplate(
				registry,
				pcacheCompileFilter(t, test.template),
				pcacheCompileFilter(t, test.request),
			); got != test.want {
				t.Fatalf("extensible match %s -> %s = %t, want %t", test.template, test.request, got, test.want)
			}
		})
	}
}

func TestPcacheSchemaFilterKeyCanonicalization(t *testing.T) {
	t.Parallel()
	registry := pcacheContainmentRegistry(t)

	left := pcacheCompileFilter(t, "(&(sn= Smith  Jones )(|(cn=Alice)(userid=100)))")
	right := pcacheCompileFilter(t, "(&(|(0.9.2342.19200300.100.1.1=100)(2.5.4.3= alice ))(2.5.4.4=smith jones))")
	leftKey, leftOK := pcacheSchemaFilterKey(registry, left)
	rightKey, rightOK := pcacheSchemaFilterKey(registry, right)
	if !leftOK || !rightOK || leftKey != rightKey {
		t.Fatalf("canonical keys = %q (%t), %q (%t)", leftKey, leftOK, rightKey, rightOK)
	}

	exactUpper, upperOK := pcacheSchemaFilterKey(registry, pcacheCompileFilter(t, "(pcacheExact=Alice)"))
	exactLower, lowerOK := pcacheSchemaFilterKey(registry, pcacheCompileFilter(t, "(pcacheExact=alice)"))
	if !upperOK || !lowerOK || exactUpper == exactLower {
		t.Fatal("caseExact assertions collapsed to one pcache key")
	}

	extensibleName, nameOK := pcacheSchemaFilterKey(
		registry,
		pcacheCompileFilter(t, "(cn:caseIgnoreMatch:=Alice)"),
	)
	extensibleOID, oidOK := pcacheSchemaFilterKey(
		registry,
		pcacheCompileFilter(t, "(2.5.4.3:2.5.13.2:=Alice)"),
	)
	if !nameOK || !oidOK || extensibleName != extensibleOID {
		t.Fatalf(
			"matching-rule alias keys = %q (%t), %q (%t)",
			extensibleName,
			nameOK,
			extensibleOID,
			oidOK,
		)
	}
}

func TestPcacheTemplateSupportsExtensibleFilters(t *testing.T) {
	t.Parallel()
	filter := pcacheCompileFilter(t, "(cn:caseIgnoreMatch:=)")
	if !pcacheTemplateFilterSupported(filter) {
		t.Fatal("extensible pcache template was rejected")
	}
}

func pcacheContainmentRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if err := registry.ParseAndRegisterAttributeType(
		"( 1.3.6.1.4.1.4203.999.31 NAME ( 'pcacheExact' 'pcacheExactAlias' ) EQUALITY caseExactMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	); err != nil {
		t.Fatalf("register pcacheExact: %v", err)
	}
	return registry
}

func pcacheCompileFilter(t *testing.T, value string) directory.Filter {
	t.Helper()
	filter, err := ldapwire.CompileFilter(value)
	if err != nil {
		t.Fatalf("CompileFilter(%q): %v", value, err)
	}
	return filter
}
