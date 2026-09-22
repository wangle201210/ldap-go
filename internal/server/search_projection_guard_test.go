package server

import (
	"context"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSearchProjectionFrontendNestGroup(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range []directory.Entry{
			{
				DN: "olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
					{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
				},
			},
			{
				DN: "olcOverlay={0}nestgroup,olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcNestGroupConfig")},
					{Description: "olcOverlay", Values: stringValues("{0}nestgroup")},
					{Description: "olcNestGroupBase", Values: stringValues(nestGroupGroupsDN)},
					{Description: "olcNestGroupFlags", Values: stringValues("member-values", "member-filter")},
				},
			},
		} {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()
	leaf, top := addNestGroupPlacementGraph(t, client, "frontend")
	assertNestGroupPlacementProjection(t, client, leaf, top)

	for _, test := range []struct {
		name     string
		controls []ldap.Control
		want     int
	}{
		{name: "filtered", want: 1},
		{name: "paged", controls: []ldap.Control{ldap.NewControlPaging(1)}, want: 1},
		{name: "managed", controls: []ldap.Control{ldap.NewControlManageDsaIT(true)}},
		{
			name:     "managed paged",
			controls: []ldap.Control{ldap.NewControlManageDsaIT(true), ldap.NewControlPaging(1)},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := client.Search(ldap.NewSearchRequest(
				top,
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				0,
				0,
				false,
				"(member="+ldap.EscapeFilter(nestGroupAliceDN)+")",
				[]string{"member"},
				test.controls,
			))
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Entries) != test.want {
				t.Fatalf("entries = %d, want %d", len(result.Entries), test.want)
			}
			if test.want != 0 {
				assertNestGroupTestValues(t, ldapStringValues(result.Entries[0].GetAttributeValues("member")), leaf, nestGroupAliceDN)
			}
		})
	}
}
