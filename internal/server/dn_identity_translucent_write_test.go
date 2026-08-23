package server

import (
	"context"
	"fmt"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDNIdentityTranslucentWriteRuntimeSemantics(t *testing.T) {
	for _, backend := range dnIdentityOverlayStoreFactories() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			t.Run("delete keeps caseExact siblings distinct", func(t *testing.T) {
				client, localStore := startDNIdentityTranslucentWriteRuntime(t, backend.open)
				addDNIdentityTranslucentLocalEntry(
					t,
					client,
					dnIdentityOverlayLowerDN,
					"Local Lower",
					"overlayexactname",
					"alice",
					"local-lower",
				)
				addDNIdentityTranslucentLocalEntry(
					t,
					client,
					"cn=Upper Child,"+dnIdentityOverlayUpperDN,
					"Upper Child",
					"cn",
					"Upper Child",
					"local-upper-child",
				)

				if err := client.Del(ldap.NewDelRequest(dnIdentityOverlayLowerDN, nil)); err != nil {
					t.Fatalf("Delete(caseExact leaf %q): %v", dnIdentityOverlayLowerDN, err)
				}
				assertDNIdentityTranslucentLocalDN(t, localStore, "local-lower", "")

				assertDNIdentityRuntimeResultCode(
					t,
					client.Del(ldap.NewDelRequest(dnIdentityOverlayUpperDN, nil)),
					ldap.LDAPResultNotAllowedOnNonLeaf,
				)
				assertDNIdentityTranslucentLocalDN(
					t,
					localStore,
					"local-upper",
					dnIdentityOverlayUpperDN,
				)
			})

			t.Run("ModifyDN moves only true caseExact descendants", func(t *testing.T) {
				client, localStore := startDNIdentityTranslucentWriteRuntime(t, backend.open)
				addDNIdentityTranslucentLocalEntry(
					t,
					client,
					dnIdentityOverlayLowerDN,
					"Local Lower",
					"overlayexactname",
					"alice",
					"local-lower",
				)
				addDNIdentityTranslucentLocalEntry(
					t,
					client,
					"cn=Upper Child,"+dnIdentityOverlayUpperDN,
					"Upper Child",
					"cn",
					"Upper Child",
					"local-upper-child",
				)
				const destinationDN = "cn=destination," + dnIdentityOverlayBaseDN
				addDNIdentityTranslucentLocalEntry(
					t,
					client,
					destinationDN,
					"destination",
					"cn",
					"destination",
					"local-destination",
				)

				modify := ldap.NewModifyRequest(dnIdentityOverlayUpperDN, nil)
				modify.Add("overlayexactname", []string{"Alice"})
				if err := client.Modify(modify); err != nil {
					t.Fatalf("Modify(add local RDN value %q): %v", dnIdentityOverlayUpperDN, err)
				}
				if err := client.ModifyDN(ldap.NewModifyDNRequest(
					dnIdentityOverlayUpperDN,
					"overlayexactname=Alice",
					true,
					destinationDN,
				)); err != nil {
					t.Fatalf("ModifyDN(caseExact subtree %q): %v", dnIdentityOverlayUpperDN, err)
				}

				movedUpperDN := "overlayexactname=Alice," + destinationDN
				assertDNIdentityTranslucentLocalDN(
					t,
					localStore,
					"local-upper",
					movedUpperDN,
				)
				assertDNIdentityTranslucentLocalDN(
					t,
					localStore,
					"local-upper-child",
					"cn=Upper Child,"+movedUpperDN,
				)
				assertDNIdentityTranslucentLocalDN(
					t,
					localStore,
					"local-lower",
					dnIdentityOverlayLowerDN,
				)
			})
		})
	}
}

func startDNIdentityTranslucentWriteRuntime(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) (*ldap.Conn, storage.Store) {
	t.Helper()
	remoteStore := openStore(t)
	remoteAddress := startDNIdentityOverlayFixture(
		t,
		remoteStore,
		dnIdentityOverlayConfigPrefix,
		dnIdentityOverlayContentLDIF,
	)

	localStore := openStore(t)
	localAddress := startDNIdentityOverlayFixture(
		t,
		localStore,
		dnIdentityOverlayConfigPrefix+fmt.Sprintf(
			dnIdentityOverlayTranslucentConfigLDIF,
			"ldap://"+remoteAddress,
		),
		dnIdentityOverlayLocalOverridesLDIF,
	)
	return dialDNIdentityOverlayRoot(
		t,
		localAddress,
		"cn=admin,dc=example,dc=com",
	), localStore
}

func addDNIdentityTranslucentLocalEntry(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	commonName string,
	namingAttribute string,
	namingValue string,
	description string,
) {
	t.Helper()
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"top", "dnIdentityOverlayEntry"})
	request.Attribute("cn", []string{commonName})
	if namingAttribute != "cn" || namingValue != commonName {
		request.Attribute(namingAttribute, []string{namingValue})
	}
	request.Attribute("description", []string{description})
	if err := client.Add(request); err != nil {
		t.Fatalf("Add(translucent local entry %q): %v", dn, err)
	}
}

func assertDNIdentityTranslucentLocalDN(
	t *testing.T,
	store storage.Store,
	description string,
	wantDN string,
) {
	t.Helper()
	var matches []directory.Entry
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		return reader.ForEach(func(entry directory.Entry) error {
			if entry.HasValue("description", []byte(description)) {
				matches = append(matches, entry)
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("scan translucent local entries: %v", err)
	}
	if wantDN == "" {
		if len(matches) != 0 {
			t.Fatalf("local description %q matched %#v, want no entry", description, matches)
		}
		return
	}
	if len(matches) != 1 {
		t.Fatalf("local description %q matched %d entries, want 1: %#v", description, len(matches), matches)
	}
	if matches[0].DN != wantDN {
		t.Fatalf("local description %q DN = %q, want %q", description, matches[0].DN, wantDN)
	}
}
