package server

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestDeltaMultiProviderTCPTopologies(t *testing.T) {
	for _, backend := range []string{"memory", "bbolt"} {
		for _, topology := range []string{"ring", "mesh"} {
			t.Run(backend+"/"+topology, func(t *testing.T) {
				const count = 3
				instances := make([]*Server, count)
				nodes := make([]*multiProviderTestNode, count)
				clients := make([]*ldap.Conn, count)
				for index := range nodes {
					instance, store := newDeltaMPRServer(t, backend, uint16(index+1))
					instances[index] = instance
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					node := &multiProviderTestNode{id: uint16(index + 1), store: store, address: listener.Addr().String(), listener: listener}
					nodes[index] = node
					startMultiProviderTestNode(node, instance)
					t.Cleanup(func() { stopMultiProviderTestNode(t, node) })
					clients[index] = dialLDAPRoot(t, node.address)
					t.Cleanup(func() { _ = clients[index].Close() })
				}
				// All peers write while disconnected. Each preserves one distinct
				// attribute and contributes a value to the same multi-valued one.
				for index, client := range clients {
					request := ldap.NewModifyRequest(deltaMPRTarget, nil)
					request.Add("description", []string{fmt.Sprintf("node-%d", index+1)})
					request.Replace([]string{"mail", "telephoneNumber", "sn"}[index], []string{fmt.Sprintf("value-%d", index+1)})
					if err := client.Modify(request); err != nil {
						t.Fatal(err)
					}
				}
				pump := func() {
					t.Helper()
					for round := 0; round < count; round++ {
						for target, instance := range instances {
							for source := range nodes {
								if source == target || topology == "ring" && source != (target+1)%count {
									continue
								}
								config, _ := deltaCascadeUnitConfig(t, instance, source+1)
								config.mode = syncConsumerRefreshOnly
								config.bindDN = syncTestRootDN
								config.credentials = []byte(syncTestRootPassword)
								config.credentialsSet = true
								config.operationTimeout = 5 * time.Second
								ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
								err := instance.runSyncConsumerCycle(ctx, config, "ldap://"+nodes[source].address)
								cancel()
								if err != nil {
									t.Fatalf("round %d node %d <- %d: %v", round, target+1, source+1, err)
								}
							}
						}
					}
				}
				pump()
				for index, node := range nodes {
					entry := readStoredEntry(t, node.store, deltaMPRTarget)
					if got := byteValuesToStrings(entry.Values("description")); !equalStringSets(got, []string{"node-1", "node-2", "node-3"}) {
						t.Fatalf("node %d: description = %q", index+1, got)
					}
					for attrIndex, attribute := range []string{"mail", "telephoneNumber", "sn"} {
						if got := byteValuesToStrings(entry.Values(attribute)); !equalStringSets(got, []string{fmt.Sprintf("value-%d", attrIndex+1)}) {
							t.Fatalf("node %d: %s = %q", index+1, attribute, got)
						}
					}
					if log := deltaMPRLog(t, instances[index]); len(log) != count {
						t.Fatalf("node %d has %d logs, want %d", index+1, len(log), count)
					}
				}
				// Restart with persisted context and cookies, then replay the ring.
				_ = clients[1].Close()
				stopMultiProviderTestNode(t, nodes[1])
				listener, err := net.Listen("tcp", nodes[1].address)
				if err != nil {
					t.Fatal(err)
				}
				nodes[1].listener = listener
				instances[1], err = New(Config{Store: nodes[1].store, RootDN: syncTestRootDN, RootPassword: []byte(syncTestRootPassword)})
				if err != nil {
					t.Fatal(err)
				}
				startMultiProviderTestNode(nodes[1], instances[1])
				pump()
				for index, instance := range instances {
					if log := deltaMPRLog(t, instance); len(log) != count {
						t.Fatalf("node %d replay created duplicate logs: %d", index+1, len(log))
					}
				}
			})
		}
	}
}
