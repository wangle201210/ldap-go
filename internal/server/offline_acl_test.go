package server

import (
	"context"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestCheckOfflineACLUsesRuntimeIdentityAndConnectionPolicy(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOfflineToolStore(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		entry, err := writer.GetIn(storage.OpenLDAPConfigPartition, dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccess", stringValues(
			`{0}to attrs=cn by dn.exact="`+offlineAliceDN+`" read by peername="IP=192.0.2.20:38900" search by * none`,
			`{1}to attrs=userPassword by self auth by * none`,
			`{2}to * by users read by * none`,
		))
		return writer.PutIn(storage.OpenLDAPConfigPartition, entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	before := readOfflineToolEntry(t, store, offlineBobDN)

	report, err := CheckOfflineACL(
		context.Background(),
		store,
		OfflineACLRequest{
			TargetDN:         offlineBobDN,
			AuthenticationID: "alice",
			Checks: []OfflineACLCheckRequest{
				{Attribute: "2.5.4.3", Access: "read", Value: []byte("Bob Example"), HasValue: true},
				{Attribute: "cn", Access: "write"},
				{Attribute: "cn"},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if report.AuthenticationDN != offlineAliceDN || len(report.Checks) != 3 {
		t.Fatalf("ACL report = %#v", report)
	}
	if !report.Checks[0].Allowed || report.Checks[0].Attribute != "cn" ||
		report.Checks[1].Allowed || report.Checks[2].Mask != "read(=rscxd)" {
		t.Fatalf("ACL checks = %#v", report.Checks)
	}

	peer, err := CheckOfflineACL(
		context.Background(),
		store,
		OfflineACLRequest{
			TargetDN: offlineBobDN,
			PeerName: "IP=192.0.2.20:38900",
			Checks:   []OfflineACLCheckRequest{{Attribute: "cn", Access: "search"}},
		},
	)
	if err != nil || len(peer.Checks) != 1 || !peer.Checks[0].Allowed {
		t.Fatalf("peer ACL report = %#v, %v", peer, err)
	}

	root, err := CheckOfflineACL(
		context.Background(),
		store,
		OfflineACLRequest{
			TargetDN:         offlineBobDN,
			AuthenticationDN: "cn=admin,dc=example,dc=com",
			Checks:           []OfflineACLCheckRequest{{Attribute: "cn", Access: "manage"}},
		},
	)
	if err != nil || len(root.Checks) != 1 || !root.Checks[0].Allowed {
		t.Fatalf("root ACL report = %#v, %v", root, err)
	}

	defaults, err := CheckOfflineACL(
		context.Background(),
		store,
		OfflineACLRequest{TargetDN: offlineBobDN, AuthenticationID: "alice"},
	)
	if err != nil || len(defaults.Checks) < 4 {
		t.Fatalf("default ACL report = %#v, %v", defaults, err)
	}
	if after := readOfflineToolEntry(t, store, offlineBobDN); !before.Equal(after) {
		t.Fatal("offline ACL check modified the target entry")
	}

	_, err = CheckOfflineACL(
		context.Background(),
		store,
		OfflineACLRequest{TargetDN: "uid=missing,dc=example,dc=com"},
	)
	if err == nil || !strings.Contains(err.Error(), "was not found") {
		t.Fatalf("missing target error = %v", err)
	}
}
