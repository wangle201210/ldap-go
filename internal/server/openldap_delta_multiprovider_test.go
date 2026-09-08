package server

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestOpenLDAPDeltaMultiProviderModifyReplayDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	version, err := exec.Command(tools.slapd, "-VV").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "slapd 2.6.13") {
		t.Fatalf("expected external OpenLDAP 2.6.13, got %s (%v)", version, err)
	}
	uri, stop := startOpenLDAPAccesslogProvider(t, tools)
	defer stop()
	provider := dialLDAPRoot(t, strings.TrimPrefix(uri, "ldap://"))
	defer provider.Close()
	seedOpenLDAPAccesslogData(t, provider)
	instance, store := newDeltaMPRServer(t, "memory", 10)
	config, _ := deltaCascadeUnitConfig(t, instance, 1)
	config.mode = syncConsumerRefreshOnly
	config.bindDN = syncTestRootDN
	config.credentials = []byte(syncTestRootPassword)
	config.credentialsSet = true
	config.operationTimeout = 5 * time.Second
	// Establish a common snapshot and UUID before either provider writes.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := instance.runSyncConsumerStandardSearch(ctx, provider, config, syncConsumerRefreshOnly, nil); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	node := &multiProviderTestNode{id: 10, store: store, address: listener.Addr().String(), listener: listener}
	startMultiProviderTestNode(node, instance)
	defer stopMultiProviderTestNode(t, node)
	local := dialLDAPRoot(t, node.address)
	defer local.Close()
	older := ldap.NewModifyRequest(deltaMPRTarget, nil)
	older.Replace("description", []string{"older value"})
	older.Replace("mail", []string{"remote@example.com"})
	if err := provider.Modify(older); err != nil {
		t.Fatal(err)
	}
	newer := ldap.NewModifyRequest(deltaMPRTarget, nil)
	newer.Replace("description", []string{"newer value"})
	newer.Replace("telephoneNumber", []string{"555-0101"})
	if err := local.Modify(newer); err != nil {
		t.Fatal(err)
	}
	// Replay the real OpenLDAP accesslog after the newer local write.
	if err := instance.runSyncConsumerCycle(ctx, config, uri); err != nil {
		t.Fatal(err)
	}
	// OpenLDAP applies the same modifications chronologically as the oracle.
	if err := provider.Modify(newer); err != nil {
		t.Fatal(err)
	}
	request := ldap.NewSearchRequest(deltaMPRTarget, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"description", "mail", "telephoneNumber"}, nil)
	want, err := provider.Search(request)
	if err != nil {
		t.Fatal(err)
	}
	got, err := local.Search(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(want.Entries) != 1 || len(got.Entries) != 1 {
		t.Fatal("missing differential entry")
	}
	for _, attribute := range request.Attributes {
		if !equalStringSets(want.Entries[0].GetAttributeValues(attribute), got.Entries[0].GetAttributeValues(attribute)) {
			t.Fatalf("%s: Go=%q OpenLDAP=%q", attribute, got.Entries[0].GetAttributeValues(attribute), want.Entries[0].GetAttributeValues(attribute))
		}
	}
}
