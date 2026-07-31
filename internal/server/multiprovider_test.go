package server

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type multiProviderTestPeer struct {
	rid     int
	address string
}

type multiProviderTestNode struct {
	id       uint16
	store    storage.Store
	address  string
	listener net.Listener
	cancel   context.CancelFunc
	done     chan error
}

func TestMultiProviderThreeNodeConvergence(t *testing.T) {
	nodes := startMultiProviderTestNodes(t)
	defer stopMultiProviderTestNodes(t, nodes)

	clients := make([]*ldap.Conn, len(nodes))
	for index := range nodes {
		clients[index] = dialLDAPRoot(t, nodes[index].address)
		defer clients[index].Close()
	}

	if err := clients[0].Add(newPersonAddRequest("from-a")); err != nil {
		t.Fatalf("node A add: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		clients[2],
		"uid=from-a,ou=people,dc=example,dc=com",
		"uid",
		"from-a",
	)
	assertMultiProviderEntrySID(
		t,
		nodes[2].store,
		"uid=from-a,ou=people,dc=example,dc=com",
		1,
	)

	if err := clients[2].Add(newPersonAddRequest("from-c")); err != nil {
		t.Fatalf("node C add: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		clients[0],
		"uid=from-c,ou=people,dc=example,dc=com",
		"uid",
		"from-c",
	)
	assertMultiProviderEntrySID(
		t,
		nodes[0].store,
		"uid=from-c,ou=people,dc=example,dc=com",
		3,
	)
	if err := clients[0].Add(newPersonAddRequest("delete-conflict")); err != nil {
		t.Fatalf("node A add delete-conflict: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		clients[2],
		"uid=delete-conflict,ou=people,dc=example,dc=com",
		"uid",
		"delete-conflict",
	)

	clients[1].Close()
	stopMultiProviderTestNode(t, nodes[1])

	start := make(chan struct{})
	var writes sync.WaitGroup
	writeErrors := make(chan error, 2)
	for _, update := range []struct {
		client *ldap.Conn
		value  string
	}{
		{client: clients[0], value: "written-on-a"},
		{client: clients[2], value: "written-on-c"},
	} {
		writes.Add(1)
		go func(client *ldap.Conn, value string) {
			defer writes.Done()
			<-start
			request := ldap.NewModifyRequest(
				"uid=alice,ou=people,dc=example,dc=com",
				nil,
			)
			request.Replace("description", []string{value})
			writeErrors <- client.Modify(request)
		}(update.client, update.value)
	}
	close(start)
	writes.Wait()
	close(writeErrors)
	for err := range writeErrors {
		if err != nil {
			t.Fatalf("concurrent modify: %v", err)
		}
	}
	if err := clients[0].Add(newPersonAddRequest("offline-a")); err != nil {
		t.Fatalf("node A offline add: %v", err)
	}
	if err := clients[2].Add(newPersonAddRequest("offline-c")); err != nil {
		t.Fatalf("node C offline add: %v", err)
	}
	modifyBeforeDelete := ldap.NewModifyRequest(
		"uid=delete-conflict,ou=people,dc=example,dc=com",
		nil,
	)
	modifyBeforeDelete.Replace("description", []string{"offline modify"})
	if err := clients[0].Modify(modifyBeforeDelete); err != nil {
		t.Fatalf("node A offline conflict modify: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if err := clients[2].Del(ldap.NewDelRequest(
		"uid=delete-conflict,ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("node C offline winning delete: %v", err)
	}

	restartMultiProviderTestNode(t, nodes[1])
	clients[1] = dialLDAPRoot(t, nodes[1].address)
	defer clients[1].Close()
	waitForMultiProviderConvergence(
		t,
		clients,
		"uid=alice,ou=people,dc=example,dc=com",
		"description",
		[]string{"written-on-a", "written-on-c"},
	)
	waitForSyncConsumerAttribute(
		t,
		clients[2],
		"uid=offline-a,ou=people,dc=example,dc=com",
		"uid",
		"offline-a",
	)
	waitForSyncConsumerAttribute(
		t,
		clients[0],
		"uid=offline-c,ou=people,dc=example,dc=com",
		"uid",
		"offline-c",
	)
	for index, client := range clients {
		t.Run(fmt.Sprintf("delete-conflict-node-%d", index+1), func(t *testing.T) {
			waitForMultiProviderMissing(
				t,
				client,
				"uid=delete-conflict,ou=people,dc=example,dc=com",
			)
		})
	}

	if err := clients[2].Del(ldap.NewDelRequest(
		"uid=from-c,ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("node C delete: %v", err)
	}
	for _, client := range clients[:2] {
		waitForMultiProviderMissing(
			t,
			client,
			"uid=from-c,ou=people,dc=example,dc=com",
		)
	}

	for _, node := range nodes {
		waitForMultiProviderContextSIDs(t, node.store, []uint16{0, 1, 3})
	}
}

func startMultiProviderTestNodes(t *testing.T) []*multiProviderTestNode {
	t.Helper()
	nodes := make([]*multiProviderTestNode, 3)
	for index := range nodes {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen node %d: %v", index+1, err)
		}
		nodes[index] = &multiProviderTestNode{
			id:       uint16(index + 1),
			store:    storage.NewMemory(),
			address:  listener.Addr().String(),
			listener: listener,
			done:     make(chan error, 1),
		}
	}

	peerSets := [][]int{
		{1},
		{0, 2},
		{1},
	}
	for index, node := range nodes {
		seedSyncProviderDirectory(t, node.store)
		peers := make([]multiProviderTestPeer, 0, len(peerSets[index]))
		for _, peerIndex := range peerSets[index] {
			peers = append(peers, multiProviderTestPeer{
				rid:     int(nodes[peerIndex].id),
				address: nodes[peerIndex].address,
			})
		}
		seedMultiProviderTestConfiguration(t, node, peers)
		instance, err := New(Config{
			Store:        node.store,
			ListenerURLs: []string{"ldap://" + node.address + "/"},
			RootDN:       syncTestRootDN,
			RootPassword: []byte(syncTestRootPassword),
		})
		if err != nil {
			t.Fatalf("create node %d: %v", node.id, err)
		}
		startMultiProviderTestNode(node, instance)
	}
	return nodes
}

func startMultiProviderTestNode(
	node *multiProviderTestNode,
	instance *Server,
) {
	ctx, cancel := context.WithCancel(context.Background())
	node.cancel = cancel
	node.done = make(chan error, 1)
	go func() {
		node.done <- instance.Serve(ctx, node.listener)
	}()
}

func restartMultiProviderTestNode(
	t *testing.T,
	node *multiProviderTestNode,
) {
	t.Helper()
	listener, err := net.Listen("tcp", node.address)
	if err != nil {
		t.Fatalf("restart listener for node %d: %v", node.id, err)
	}
	node.listener = listener
	instance, err := New(Config{
		Store:        node.store,
		ListenerURLs: []string{"ldap://" + node.address + "/"},
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	if err != nil {
		t.Fatalf("restart node %d: %v", node.id, err)
	}
	startMultiProviderTestNode(node, instance)
}

func seedMultiProviderTestConfiguration(
	t *testing.T,
	node *multiProviderTestNode,
	peers []multiProviderTestPeer,
) {
	t.Helper()
	err := node.store.Update(
		context.Background(),
		func(writer storage.Writer) error {
			if err := writer.Put(directory.Entry{
				DN: "cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcServerID",
					Values:      stringValues(fmt.Sprint(node.id)),
				}},
			}, false); err != nil {
				return err
			}
			databaseDN, err := directory.ParseDN(
				"olcDatabase={1}mdb,cn=config",
			)
			if err != nil {
				return err
			}
			database, err := writer.Get(databaseDN)
			if err != nil {
				return err
			}
			values := make([][]byte, 0, len(peers))
			for order, peer := range peers {
				values = append(values, []byte(fmt.Sprintf(
					"{%d}rid=%03d provider=ldap://%s "+
						"bindmethod=simple binddn=%q credentials=%q "+
						"searchbase=%q scope=sub filter=%q attrs=%q "+
						"schemachecking=off type=refreshAndPersist "+
						"retry=%q network-timeout=1 timeout=2",
					order,
					peer.rid,
					peer.address,
					syncTestRootDN,
					syncTestRootPassword,
					"dc=example,dc=com",
					"(objectClass=*)",
					"*,+",
					"1 +",
				)))
			}
			database.ReplaceValues("olcSyncrepl", values)
			database.ReplaceValues(
				"olcMultiProvider",
				stringValues("TRUE"),
			)
			if err := writer.Put(database, true); err != nil {
				return err
			}

			overlayDN, err := directory.ParseDN(
				"olcOverlay={0}syncprov,olcDatabase={1}mdb,cn=config",
			)
			if err != nil {
				return err
			}
			overlay, err := writer.Get(overlayDN)
			if err != nil {
				return err
			}
			overlay.ReplaceValues("olcSpSessionlog", stringValues("100"))
			return writer.Put(overlay, true)
		},
	)
	if err != nil {
		t.Fatalf("seed node %d configuration: %v", node.id, err)
	}
}

func stopMultiProviderTestNodes(
	t *testing.T,
	nodes []*multiProviderTestNode,
) {
	t.Helper()
	for _, node := range nodes {
		stopMultiProviderTestNode(t, node)
		_ = node.store.Close()
	}
}

func stopMultiProviderTestNode(
	t *testing.T,
	node *multiProviderTestNode,
) {
	t.Helper()
	if node.cancel == nil {
		return
	}
	node.cancel()
	select {
	case err := <-node.done:
		if err != nil {
			t.Errorf("serve node %d: %v", node.id, err)
		}
	case <-time.After(5 * time.Second):
		t.Errorf("node %d did not stop", node.id)
	}
	node.cancel = nil
	node.done = nil
}

func waitForMultiProviderConvergence(
	t *testing.T,
	clients []*ldap.Conn,
	dn,
	attribute string,
	allowed []string,
) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var observed []string
	for time.Now().Before(deadline) {
		observed = observed[:0]
		converged := true
		for _, client := range clients {
			result, err := client.Search(ldap.NewSearchRequest(
				dn,
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				0,
				0,
				false,
				"(objectClass=*)",
				[]string{attribute},
				nil,
			))
			if err != nil || len(result.Entries) != 1 {
				converged = false
				break
			}
			observed = append(
				observed,
				result.Entries[0].GetAttributeValue(attribute),
			)
		}
		if converged && len(observed) == len(clients) {
			value := observed[0]
			converged = slices.Contains(allowed, value)
			for _, candidate := range observed[1:] {
				converged = converged && candidate == value
			}
			if converged {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s did not converge: %q", dn, observed)
}

func waitForMultiProviderMissing(
	t *testing.T,
	client *ldap.Conn,
	dn string,
) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, err := client.Search(ldap.NewSearchRequest(
			dn,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"1.1"},
			nil,
		))
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s was not deleted", dn)
}

func assertMultiProviderEntrySID(
	t *testing.T,
	store storage.Store,
	dn string,
	want uint16,
) {
	t.Helper()
	entry := readStoredEntry(t, store, dn)
	values := entry.Values("entryCSN")
	if len(values) != 1 {
		t.Fatalf("%s entryCSN = %q", dn, values)
	}
	csn, err := parseOpenLDAPCSN(string(values[0]))
	if err != nil {
		t.Fatalf("parse %s entryCSN: %v", dn, err)
	}
	if csn.serverID != want {
		t.Fatalf("%s entryCSN SID = %03x, want %03x", dn, csn.serverID, want)
	}
}

func waitForMultiProviderContextSIDs(
	t *testing.T,
	store storage.Store,
	want []uint16,
) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var found []uint16
	for time.Now().Before(deadline) {
		found = found[:0]
		err := store.View(
			context.Background(),
			func(reader storage.Reader) error {
				state, err := syncContextCSNs(
					reader,
					configuredDatabasePartition("{1}mdb"),
				)
				if err != nil {
					return err
				}
				for _, serverID := range want {
					if _, exists := state[serverID]; exists {
						found = append(found, serverID)
					}
				}
				return nil
			},
		)
		if err == nil && len(found) == len(want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("context SIDs = %v, want %v", found, want)
}
