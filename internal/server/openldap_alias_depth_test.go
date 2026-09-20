package server

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceAliasDepthBoundary(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	for _, depth := range []int{0, 1, 3, 4} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			var data strings.Builder
			entries := make([]directory.Entry, 0, 4)
			for i := 0; i < 4; i++ {
				dn := fmt.Sprintf("cn=depth-%d,ou=people,dc=example,dc=com", i)
				target := fmt.Sprintf("cn=depth-%d,ou=people,dc=example,dc=com", i+1)
				if i == 3 {
					target = "uid=alice,ou=people,dc=example,dc=com"
				}
				fmt.Fprintf(&data, "\ndn: %s\nobjectClass: alias\nobjectClass: extensibleObject\ncn: depth-%d\naliasedObjectName: %s\n", dn, i, target)
				entries = append(entries, directory.Entry{DN: dn, Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("alias", "extensibleObject")},
					{Description: "cn", Values: stringValues(fmt.Sprintf("depth-%d", i))},
					{Description: "aliasedObjectName", Values: stringValues(target)},
				}})
			}
			native, stopNative := startOpenLDAPReferenceServerWithConfig(t, tools, nil, "", fmt.Sprintf("maxderefdepth %d", depth), data.String())
			t.Cleanup(stopNative)
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedOnlineConfiguration(t, store)
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				configDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
				if err != nil {
					return err
				}
				config, err := writer.Get(configDN)
				if err != nil {
					return err
				}
				config.ReplaceValues("olcMaxDerefDepth", stringValues(fmt.Sprint(depth)))
				if err := writer.Put(config, true); err != nil {
					return err
				}
				for _, entry := range entries {
					if err := writer.Put(entry, false); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			local, stopLocal := startServer(t, store, Config{RootDN: "cn=admin,dc=example,dc=com", RootPassword: []byte("secret")})
			t.Cleanup(stopLocal)
			for _, mode := range []int{ldap.NeverDerefAliases, ldap.DerefInSearching, ldap.DerefFindingBaseObj, ldap.DerefAlways} {
				for _, base := range []string{"cn=depth-0,ou=people,dc=example,dc=com", "cn=missing,cn=depth-0,ou=people,dc=example,dc=com"} {
					t.Run(fmt.Sprintf("%d/%s", mode, base), func(t *testing.T) {
						var responses [2][][]byte
						for i, address := range []string{strings.TrimPrefix(native, "ldap://"), local} {
							conn := dialAndBindRawLDAP(t, address, "cn=admin,dc=example,dc=com", "secret")
							defer conn.Close()
							writeRawLDAPRequest(t, conn, 2, rawSyncSearchRequestFor(t, base, ldap.ScopeBaseObject, mode, "(objectClass=*)"))
							for {
								packet, err := ber.ReadPacket(conn)
								if err != nil {
									t.Fatal(err)
								}
								op := packet.Children[1]
								if uint64(op.Tag) == ldapwire.ApplicationSearchResultEntry {
									// Attributes and operational timestamps are outside this boundary test.
									responses[i] = append(responses[i], op.Children[0].Data.Bytes())
									continue
								}
								responses[i] = append(responses[i], packet.Bytes())
								break
							}
						}
						if !reflect.DeepEqual(responses[0], responses[1]) {
							t.Errorf("native=%q local=%q", responses[0], responses[1])
						}
					})
				}
			}
		})
	}
}
