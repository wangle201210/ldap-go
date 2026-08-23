package migration

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const dnIdentityPartitionConfigLDIF = `dn: cn=config
objectClass: olcGlobal
cn: config

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: cn={9}dnidentitypartition,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}dnidentitypartition
olcAttributeTypes: ( 1.3.6.1.4.1.99999.918.1 NAME 'partitionExactName' EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.99999.918.2 NAME 'partitionFoldName' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.99999.918.3 NAME 'dnIdentityPartitionEntry' SUP top STRUCTURAL MUST cn MAY ( partitionExactName $ partitionFoldName ) )

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcRootDN: cn=config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {1}mdb
olcSuffix: partitionExactName=Tenant

dn: olcDatabase={2}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {2}mdb
olcSuffix: partitionExactName=tenant

dn: olcDatabase={3}mdb,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {3}mdb
olcSuffix: partitionFoldName=Remote Tenant

`

const dnIdentityPartitionContentLDIF = `dn: partitionExactName=Tenant
objectClass: top
objectClass: dnIdentityPartitionEntry
cn: Exact Upper Partition
partitionExactName: Tenant

dn: partitionExactName=tenant
objectClass: top
objectClass: dnIdentityPartitionEntry
cn: Exact Lower Partition
partitionExactName: tenant

dn: partitionFoldName=REMOTE  TENANT
objectClass: top
objectClass: dnIdentityPartitionEntry
cn: Folded Partition
partitionFoldName: REMOTE  TENANT

`

func TestImportLDIFSelectsDatabaseWithSchemaAwareDNIdentity(t *testing.T) {
	factories := []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{
			name: "memory",
			open: func(*testing.T) storage.Store {
				return storage.NewMemory()
			},
		},
		{
			name: "bolt",
			open: func(t *testing.T) storage.Store {
				store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
				if err != nil {
					t.Fatalf("OpenBolt(): %v", err)
				}
				return store
			},
		},
	}

	for _, factory := range factories {
		factory := factory
		t.Run(factory.name, func(t *testing.T) {
			store := factory.open(t)
			t.Cleanup(func() { _ = store.Close() })
			if _, err := ImportLDIF(
				context.Background(),
				store,
				strings.NewReader(dnIdentityPartitionConfigLDIF),
				ImportOptions{
					Database:             "0",
					Replace:              true,
					SkipSchemaValidation: true,
				},
			); err != nil {
				t.Fatalf("ImportLDIF(cn=config): %v", err)
			}
			if _, err := ImportLDIF(
				context.Background(),
				store,
				strings.NewReader(dnIdentityPartitionContentLDIF),
				ImportOptions{},
			); err != nil {
				t.Fatalf("ImportLDIF(auto partition): %v", err)
			}

			if err := store.View(context.Background(), func(reader storage.Reader) error {
				registry, err := importedSchemaRegistry(reader, nil)
				if err != nil {
					return err
				}
				assertDNIdentityPartitionEntry(
					t,
					reader,
					storage.OpenLDAPDatabasePartition("{1}mdb", nil),
					registry,
					"partitionExactName=Tenant",
					"Exact Upper Partition",
				)
				assertDNIdentityPartitionEntry(
					t,
					reader,
					storage.OpenLDAPDatabasePartition("{2}mdb", nil),
					registry,
					"partitionExactName=tenant",
					"Exact Lower Partition",
				)
				assertDNIdentityPartitionEntry(
					t,
					reader,
					storage.OpenLDAPDatabasePartition("{3}mdb", nil),
					registry,
					`partitionFoldName=\20remote\20tenant\20`,
					"Folded Partition",
				)
				return nil
			}); err != nil {
				t.Fatalf("inspect schema-aware partitions: %v", err)
			}
		})
	}
}

func assertDNIdentityPartitionEntry(
	t *testing.T,
	reader storage.Reader,
	partition string,
	normalizer directory.DNAttributeNormalizer,
	rawDN string,
	wantCN string,
) {
	t.Helper()
	dn, err := directory.ParseDNWithNormalizer(rawDN, normalizer)
	if err != nil {
		t.Fatalf("ParseDNWithNormalizer(%q): %v", rawDN, err)
	}
	entry, err := reader.GetIn(partition, dn)
	if err != nil {
		t.Fatalf("GetIn(%q, %q): %v", partition, rawDN, err)
	}
	values := entry.Values("cn")
	if len(values) != 1 || string(values[0]) != wantCN {
		t.Fatalf("GetIn(%q, %q) cn = %q, want [%q]", partition, rawDN, values, wantCN)
	}
}
