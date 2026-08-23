package server

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	derefExactOID = "1.3.6.1.4.1.99999.930.1"
	derefFoldOID  = "1.3.6.1.4.1.99999.930.2"
	derefBaseDN   = "dc=example,dc=com"
)

func TestDNIdentityDerefControl(t *testing.T) {
	backends := []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{name: "memory", open: func(*testing.T) storage.Store { return storage.NewMemory() }},
		{name: "bolt", open: func(t *testing.T) storage.Store {
			t.Helper()
			store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	}

	for _, backend := range backends {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			store := backend.open(t)
			t.Cleanup(func() { _ = store.Close() })
			instance, state, equivalentSource, differentSource :=
				newDNIdentityDerefServer(t, store)

			t.Run("source identity", func(t *testing.T) {
				control, err := instance.derefResponseControl(
					context.Background(), state, differentSource, dnIdentityDerefRequest(),
				)
				if err != nil {
					t.Fatalf("derefResponseControl(caseExact sibling): %v", err)
				}
				if control != nil {
					t.Fatalf("caseExact-different source produced control %#v", control)
				}
			})

			t.Run("target identity backend and ACL", func(t *testing.T) {
				control, err := instance.derefResponseControl(
					context.Background(), state, equivalentSource, dnIdentityDerefRequest(),
				)
				if err != nil {
					t.Fatalf("derefResponseControl(schema equivalent source): %v", err)
				}
				if control == nil {
					t.Fatal("schema-equivalent source did not produce a deref control")
				}
				results := decodeDerefTestResponse(t, control.Value)
				assertDNIdentityDerefResults(t, results)
			})
		})
	}
}

func newDNIdentityDerefServer(
	t *testing.T,
	store storage.Store,
) (*Server, *connectionState, string, string) {
	t.Helper()
	registry := dnIdentityDerefRegistry(t)
	policy := dnIdentityDerefPolicy(t, registry)
	base := mustDNIdentityDerefDN(t, registry, derefBaseDN)
	childBase := mustDNIdentityDerefDN(
		t,
		registry,
		"derefExactName=Nested,"+derefBaseDN,
	)
	parentPartition := "dn-identity-deref-parent"
	childPartition := "dn-identity-deref-child"
	parent := runtimeDatabase{
		name:         "{1}mdb",
		partition:    parentPartition,
		suffixes:     []directory.DN{base},
		dnNormalizer: registry,
		deref:        true,
	}
	child := runtimeDatabase{
		name:         "{2}mdb",
		partition:    childPartition,
		suffixes:     []directory.DN{childBase},
		dnNormalizer: registry,
	}
	runtime := &runtimeState{
		schema:    registry,
		access:    policy,
		databases: []runtimeDatabase{parent, child},
	}

	sourceDN := "derefExactName=Source+derefFoldName=Team,ou=people," + derefBaseDN
	targetDN := "derefExactName=Alice+derefFoldName=Research,ou=people," + derefBaseDN
	nestedDN := "derefExactName=Shadow,derefExactName=Nested," + derefBaseDN
	references := []string{
		derefFoldOID + `=\20RESEARCH\20+derefExactAlias=Alice,OU=PEOPLE,DC=EXAMPLE,DC=COM`,
		"derefFoldAlias=research+derefExactAlias=alice,ou=people," + derefBaseDN,
		"derefExactAlias=Shadow,derefExactAlias=Nested,DC=EXAMPLE,DC=COM",
	}
	entries := []directory.Entry{
		{
			DN: sourceDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top")},
				{Description: "member", Values: stringValues(references...)},
			},
		},
		{
			DN: targetDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top")},
				{Description: "cn", Values: stringValues("Resolved Target")},
				{Description: "description", Values: stringValues("visible", "secret")},
			},
		},
		{
			DN: nestedDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top")},
				{Description: "cn", Values: stringValues("Wrong Parent Backend")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		parentWriter := storage.WriterInPartitionWithNormalizer(
			writer,
			parentPartition,
			registry,
		)
		for _, entry := range entries {
			if err := parentWriter.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed schema-aware deref entries: %v", err)
	}

	instance := &Server{config: Config{Store: store}}
	state := &connectionState{
		boundDN: "uid=reader," + derefBaseDN,
		runtime: runtime,
	}
	equivalentSource := derefFoldOID +
		`=\20TEAM\20+derefExactAlias=Source,OU=PEOPLE,DC=EXAMPLE,DC=COM`
	differentSource := "derefFoldAlias=team+derefExactAlias=source,ou=people," + derefBaseDN
	return instance, state, equivalentSource, differentSource
}

func dnIdentityDerefRequest() *derefControlRequest {
	return &derefControlRequest{specs: []ldapwire.DerefSpec{{
		DerefAttr:  "member",
		Attributes: []string{"cn", "description"},
	}}}
}

func assertDNIdentityDerefResults(t *testing.T, results []ldapwire.DerefResult) {
	t.Helper()
	if len(results) != 3 {
		t.Fatalf("deref results = %#v, want three visible source values", results)
	}
	if len(results[0].Attributes) != 2 {
		t.Fatalf("schema-equivalent target attributes = %#v", results[0].Attributes)
	}
	if results[0].Attributes[0].Type != "cn" ||
		len(results[0].Attributes[0].Values) != 1 ||
		string(results[0].Attributes[0].Values[0]) != "Resolved Target" {
		t.Fatalf("resolved target cn = %#v", results[0].Attributes[0])
	}
	if results[0].Attributes[1].Type != "description" ||
		len(results[0].Attributes[1].Values) != 1 ||
		string(results[0].Attributes[1].Values[0]) != "visible" {
		t.Fatalf("ACL-filtered target description = %#v", results[0].Attributes[1])
	}
	for index := 1; index < len(results); index++ {
		if len(results[index].Attributes) != 0 {
			t.Fatalf("unresolved target %d leaked attributes: %#v", index, results[index])
		}
	}
}

func dnIdentityDerefRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( " + derefExactOID + " NAME ( 'derefExactName' 'derefExactAlias' ) " +
			"EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( " + derefFoldOID + " NAME ( 'derefFoldName' 'derefFoldAlias' ) " +
			"EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", definition, err)
		}
	}
	return registry
}

func dnIdentityDerefPolicy(t *testing.T, registry *schema.Registry) *acl.Policy {
	t.Helper()
	rules := make([]acl.Rule, 0, 2)
	for _, raw := range []string{
		`{0}to attrs=description val.exact="secret" by * none`,
		`{1}to * by * read`,
	} {
		rule, err := acl.ParseRule(raw)
		if err != nil {
			t.Fatalf("ParseRule(%q): %v", raw, err)
		}
		rules = append(rules, rule)
	}
	policy, err := acl.NewPolicy(rules, nil)
	if err != nil {
		t.Fatalf("NewPolicy(): %v", err)
	}
	if err := policy.Validate(registry); err != nil {
		t.Fatalf("Policy.Validate(): %v", err)
	}
	return policy
}

func mustDNIdentityDerefDN(
	t *testing.T,
	registry *schema.Registry,
	raw string,
) directory.DN {
	t.Helper()
	dn, err := registry.NormalizeDN(raw)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", raw, err)
	}
	return dn
}
