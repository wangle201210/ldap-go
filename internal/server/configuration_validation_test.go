package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestValidateConfigurationBuildsCompleteRuntimeReadOnly(t *testing.T) {
	t.Parallel()

	memory := storage.NewMemory()
	t.Cleanup(func() { _ = memory.Close() })
	seedValidationConfiguration(t, memory)
	store := &configurationValidationReadOnlyStore{Store: memory}

	summary, err := ValidateConfiguration(
		context.Background(),
		Config{Store: store},
	)
	if err != nil {
		t.Fatalf("ValidateConfiguration(): %v", err)
	}
	if store.updates != 0 {
		t.Fatalf("ValidateConfiguration() called Update %d times", store.updates)
	}
	if summary.Databases != 1 || summary.Overlays != 1 ||
		summary.SyncreplConsumers != 1 || summary.ACLRules != 1 ||
		summary.SASLAuthzRules != 1 {
		t.Fatalf("configuration summary = %#v", summary)
	}
	if summary.AttributeTypes == 0 || summary.ObjectClasses == 0 {
		t.Fatalf("schema summary = %#v", summary)
	}
}

func TestValidateConfigurationRejectsRuntimeConfigurationLayers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		want          string
		global        []directory.Attribute
		database      []directory.Attribute
		configuration []directory.Entry
	}{
		{
			name: "schema",
			want: "olcAttributeTypes",
			configuration: []directory.Entry{
				{
					DN: "cn={1}invalid,cn=schema,cn=config",
					Attributes: []directory.Attribute{
						{
							Description: "olcAttributeTypes",
							Values:      validationValues("invalid"),
						},
					},
				},
			},
		},
		{
			name: "ACL",
			want: "olcAccess",
			global: []directory.Attribute{
				{Description: "olcAccess", Values: validationValues("invalid")},
			},
		},
		{
			name: "database",
			want: "olcRootPW requires olcRootDN",
			database: []directory.Attribute{
				{Description: "olcRootPW", Values: validationValues("secret")},
			},
		},
		{
			name: "overlay",
			want: "olcSpCheckpoint",
			configuration: []directory.Entry{
				{
					DN: "olcOverlay={0}syncprov,olcDatabase={1}mdb,cn=config",
					Attributes: []directory.Attribute{
						{Description: "olcOverlay", Values: validationValues("{0}syncprov")},
						{Description: "olcSpCheckpoint", Values: validationValues("invalid")},
					},
				},
			},
		},
		{
			name: "SASL",
			want: "olcSaslSecProps",
			global: []directory.Attribute{
				{Description: "olcSaslSecProps", Values: validationValues("minssf=invalid")},
			},
		},
		{
			name: "syncrepl",
			want: "syncrepl is missing provider, searchbase",
			database: []directory.Attribute{
				{Description: "olcSyncrepl", Values: validationValues("rid=001")},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			global := directory.Entry{
				DN:         "cn=config",
				Attributes: append([]directory.Attribute(nil), test.global...),
			}
			database := directory.Entry{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: append([]directory.Attribute{
					{Description: "olcDatabase", Values: validationValues("{1}mdb")},
					{Description: "olcSuffix", Values: validationValues("dc=example,dc=com")},
				}, test.database...),
			}
			err := store.Update(context.Background(), func(writer storage.Writer) error {
				for _, entry := range append(
					[]directory.Entry{global, database},
					test.configuration...,
				) {
					if err := writer.PutIn(
						storage.OpenLDAPConfigPartition,
						entry,
						false,
					); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				t.Fatalf("seed configuration: %v", err)
			}

			_, err = ValidateConfiguration(
				context.Background(),
				Config{Store: store},
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateConfiguration() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateConfigurationValidatesArguments(t *testing.T) {
	t.Parallel()

	//lint:ignore SA1012 This test verifies the public nil-context rejection contract.
	if _, err := ValidateConfiguration(nil, Config{}); err == nil ||
		!strings.Contains(err.Error(), "context") {
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := ValidateConfiguration(context.Background(), Config{}); err == nil ||
		!strings.Contains(err.Error(), "store") {
		t.Fatalf("missing store error = %v", err)
	}
}

type configurationValidationReadOnlyStore struct {
	storage.Store
	updates int
}

func (store *configurationValidationReadOnlyStore) Update(
	context.Context,
	func(storage.Writer) error,
) error {
	store.updates++
	return errors.New("unexpected write transaction")
}

func seedValidationConfiguration(t *testing.T, store storage.Store) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{
					Description: "olcServerID",
					Values:      validationValues("1 ldap://node-one.example"),
				},
				{
					Description: "olcAccess",
					Values:      validationValues("{0}to * by * read"),
				},
				{
					Description: "olcAuthzRegexp",
					Values: validationValues(
						`{0}^uid=([^,]+),cn=plain,cn=auth$ ` +
							`uid=$1,ou=people,dc=example,dc=com`,
					),
				},
			},
		},
		{
			DN: "cn={1}validation,cn=schema,cn=config",
			Attributes: []directory.Attribute{
				{
					Description: "olcAttributeTypes",
					Values: validationValues(
						"( 1.3.6.1.4.1.55555.1.2 NAME 'validationCode' " +
							"EQUALITY caseIgnoreMatch SYNTAX " +
							"1.3.6.1.4.1.1466.115.121.1.15 )",
					),
				},
			},
		},
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: validationValues("{1}mdb")},
				{Description: "olcSuffix", Values: validationValues("dc=example,dc=com")},
				{
					Description: "olcSyncrepl",
					Values: validationValues(
						`rid=001 provider=ldap://provider.example ` +
							`searchbase="dc=example,dc=com" type=refreshOnly`,
					),
				},
			},
		},
		{
			DN: "olcOverlay={0}sssvlv,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: validationValues("{0}sssvlv")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed validation configuration: %v", err)
	}
}

func validationValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = []byte(values[index])
	}
	return result
}
