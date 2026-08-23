package server

import (
	"context"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDNIdentityPasswordPolicy(t *testing.T) {
	registry := dnIdentityPasswordPolicyRegistry(t)
	runtime := &runtimeState{schema: registry}

	t.Run("identity comparison follows naming matching rules", func(t *testing.T) {
		if passwordPolicySameDN(
			runtime,
			"ppolicyExactName=Alice,dc=example,dc=com",
			"ppolicyExactName=alice,dc=example,dc=com",
		) {
			t.Fatal("caseExact-different password policy identities compared equal")
		}
		if !passwordPolicySameDN(
			runtime,
			"ppolicyFoldName=Alice,dc=example,dc=com",
			"ppolicyFoldName=alice,dc=example,dc=com",
		) {
			t.Fatal("caseIgnore-equivalent password policy identities compared different")
		}
	})

	t.Run("restriction state is not retained across caseExact identities", func(t *testing.T) {
		state := &connectionState{
			boundDN:                    "ppolicyExactName=alice,dc=example,dc=com",
			passwordPolicyRestrictedDN: "ppolicyExactName=Alice,dc=example,dc=com",
			runtime:                    runtime,
		}
		refreshPasswordPolicyRestriction(state)
		if state.passwordPolicyRestrictedDN != "" {
			t.Fatal("caseExact-different identity retained another user's restriction")
		}

		state.boundDN = "ppolicyFoldName=alice,dc=example,dc=com"
		state.passwordPolicyRestrictedDN = "ppolicyFoldName=Alice,dc=example,dc=com"
		refreshPasswordPolicyRestriction(state)
		if state.passwordPolicyRestrictedDN == "" {
			t.Fatal("caseIgnore-equivalent identity lost its restriction")
		}
	})

	t.Run("assigned policy lookup keeps caseExact DNs distinct", func(t *testing.T) {
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		upperPolicyDN := "ppolicyExactName=Policy,dc=example,dc=com"
		lowerPolicyDN := "ppolicyExactName=policy,dc=example,dc=com"
		upper, err := registry.NormalizeDN(upperPolicyDN)
		if err != nil {
			t.Fatalf("NormalizeDN(upper policy): %v", err)
		}
		lower, err := registry.NormalizeDN(lowerPolicyDN)
		if err != nil {
			t.Fatalf("NormalizeDN(lower policy): %v", err)
		}
		if err := store.Update(context.Background(), func(writer storage.Writer) error {
			scoped := storage.WriterInPartitionWithNormalizer(
				writer,
				"ppolicy-dn-identity",
				registry,
			)
			for _, entry := range []directory.Entry{
				{DN: upperPolicyDN, Attributes: []directory.Attribute{
					{Description: "pwdMinLength", Values: stringValues("12")},
				}},
				{DN: lowerPolicyDN, Attributes: []directory.Attribute{
					{Description: "pwdMinLength", Values: stringValues("24")},
				}},
			} {
				if err := scoped.Put(entry, false); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("seed password policies: %v", err)
		}

		database := runtimeDatabase{
			name:         "{1}mdb",
			partition:    "ppolicy-dn-identity",
			suffixes:     []directory.DN{mustDNIdentityPPolicyDN(t, registry, "dc=example,dc=com")},
			dnNormalizer: registry,
			ppolicy:      &passwordPolicyRuntimeConfiguration{},
		}
		runtime.databases = []runtimeDatabase{database}
		entry := directory.Entry{DN: "ppolicyExactName=User,dc=example,dc=com"}
		entry.ReplaceValues("pwdPolicySubentry", [][]byte{[]byte(lowerPolicyDN)})

		if err := store.View(context.Background(), func(reader storage.Reader) error {
			policy, ok := loadPasswordPolicy(runtime, reader, database, entry)
			if !ok || policy.minLength != 24 {
				t.Fatalf("assigned caseExact policy = %#v, %t", policy, ok)
			}
			if upper.Equal(lower) {
				t.Fatal("caseExact policy DNs collapsed")
			}
			return nil
		}); err != nil {
			t.Fatalf("load assigned password policy: %v", err)
		}
	})
}

func dnIdentityPasswordPolicyRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.919.1 NAME 'ppolicyExactName' EQUALITY caseExactMatch " +
			"ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX " +
			schema.SyntaxDirectoryString + " )",
		"( 1.3.6.1.4.1.99999.919.2 NAME 'ppolicyFoldName' EQUALITY caseIgnoreMatch " +
			"ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " +
			schema.SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("register attribute %q: %v", definition, err)
		}
	}
	return registry
}

func mustDNIdentityPPolicyDN(
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
