package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const openLDAPConsumerPassword = "consumer-secret"

type openLDAPSyncreplConsumer struct {
	tools      openLDAPReferenceTools
	configPath string
	address    string
	uri        string
}

func TestOpenLDAPAndLDAPGoMultiProviderReplication(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)

	goListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ldap-go multi-provider: %v", err)
	}
	goAddress := goListener.Addr().String()
	goURI := "ldap://" + goAddress

	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{"syncprov"},
		"serverID 2",
		fmt.Sprintf(
			`syncrepl rid=001
  provider=%s
  type=refreshAndPersist
  retry="1 10 5 +"
  searchbase="dc=example,dc=com"
  scope=sub
  attrs="*,+"
  schemachecking=off
  bindmethod=simple
  binddn="%s"
  credentials=%s
multiprovider TRUE`,
			goURI,
			syncTestRootDN,
			syncTestRootPassword,
		),
		"",
	)
	defer stopOpenLDAP()

	store := storage.NewMemory()
	defer store.Close()
	seedOpenLDAPMultiProviderConsumer(
		t,
		store,
		strings.TrimPrefix(openLDAPURI, "ldap://"),
	)
	instance, err := New(Config{
		Store:        store,
		ListenerURLs: []string{goURI + "/"},
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	if err != nil {
		t.Fatalf("create ldap-go multi-provider: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- instance.Serve(ctx, goListener)
	}()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve ldap-go multi-provider: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("ldap-go multi-provider did not stop")
		}
	}()

	goClient := dialLDAPRoot(t, goAddress)
	defer goClient.Close()
	waitForSyncConsumerAttribute(
		t,
		goClient,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice",
	)
	assertMultiProviderEntrySID(
		t,
		store,
		"uid=alice,ou=people,dc=example,dc=com",
		0,
	)

	openLDAPClient, err := ldap.DialURL(openLDAPURI)
	if err != nil {
		t.Fatalf("dial OpenLDAP multi-provider: %v", err)
	}
	defer openLDAPClient.Close()
	if err := openLDAPClient.Bind(syncTestRootDN, "secret"); err != nil {
		t.Fatalf("bind OpenLDAP multi-provider: %v", err)
	}
	if err := goClient.Add(newPersonAddRequest("from-go")); err != nil {
		t.Fatalf("ldap-go add: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		openLDAPClient,
		"uid=from-go,ou=people,dc=example,dc=com",
		"uid",
		"from-go",
	)

	if err := openLDAPClient.Add(newPersonAddRequest("from-openldap")); err != nil {
		t.Fatalf("OpenLDAP add: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		goClient,
		"uid=from-openldap,ou=people,dc=example,dc=com",
		"uid",
		"from-openldap",
	)
	assertMultiProviderEntrySID(
		t,
		store,
		"uid=from-openldap,ou=people,dc=example,dc=com",
		2,
	)
	waitForMultiProviderContextSIDs(t, store, []uint16{1, 2})
}

func seedOpenLDAPMultiProviderConsumer(
	t *testing.T,
	store storage.Store,
	providerAddress string,
) {
	t.Helper()
	err := store.Update(
		context.Background(),
		func(writer storage.Writer) error {
			if err := writer.Put(directory.Entry{
				DN: "cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcServerID",
					Values:      stringValues("1"),
				}},
			}, false); err != nil {
				return err
			}
			if err := writer.Put(directory.Entry{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{
						Description: "olcDatabase",
						Values:      stringValues("{1}mdb"),
					},
					{
						Description: "olcSuffix",
						Values:      stringValues("dc=example,dc=com"),
					},
					{
						Description: "olcSyncrepl",
						Values: stringValues(
							`{0}rid=002 provider=ldap://` +
								providerAddress +
								` bindmethod=simple binddn="` +
								syncTestRootDN +
								`" credentials="` +
								"secret" +
								`" searchbase="dc=example,dc=com"` +
								` scope=sub filter="(objectClass=*)"` +
								` attrs="*,+" schemachecking=off` +
								` type=refreshAndPersist retry="1 +"`,
						),
					},
					{
						Description: "olcMultiProvider",
						Values:      stringValues("TRUE"),
					},
				},
			}, false); err != nil {
				return err
			}
			if err := writer.Put(directory.Entry{
				DN: "olcOverlay={0}syncprov,olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{
						Description: "olcOverlay",
						Values:      stringValues("{0}syncprov"),
					},
					{
						Description: "olcSpSessionlog",
						Values:      stringValues("100"),
					},
				},
			}, false); err != nil {
				return err
			}
			return writer.SetNamingContexts([]string{"dc=example,dc=com"})
		},
	)
	if err != nil {
		t.Fatalf("seed ldap-go multi-provider consumer: %v", err)
	}
}

func TestOpenLDAPSyncreplConsumesLDAPGoProvider(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)
	configureSyncProviderPolicy(t, store, map[string]string{
		"olcSpSessionlog": "20",
	})

	providerAddress, stopProvider := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopProvider()

	consumer := newOpenLDAPSyncreplConsumer(
		t,
		tools,
		"ldap://"+providerAddress,
	)
	stopConsumer := consumer.start(t)
	consumerClient := dialOpenLDAPSyncreplConsumer(t, consumer.uri)
	waitForOpenLDAPSyncreplEntries(
		t,
		consumerClient,
		[]string{
			"dc=example,dc=com",
			"ou=archive,dc=example,dc=com",
			"ou=people,dc=example,dc=com",
			"uid=alice,ou=people,dc=example,dc=com",
		},
		map[string]string{
			"uid=alice,ou=people,dc=example,dc=com": "Alice Example",
		},
	)

	providerClient := dialLDAPRoot(t, providerAddress)
	defer providerClient.Close()
	modify := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Alice Streaming"})
	if err := providerClient.Modify(modify); err != nil {
		t.Fatalf("Modify(alice streaming): %v", err)
	}
	if err := providerClient.Add(newPersonAddRequest("bob")); err != nil {
		t.Fatalf("Add(bob streaming): %v", err)
	}
	if err := providerClient.Del(ldap.NewDelRequest(
		"ou=archive,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("Delete(archive streaming): %v", err)
	}
	waitForOpenLDAPSyncreplEntries(
		t,
		consumerClient,
		[]string{
			"dc=example,dc=com",
			"ou=people,dc=example,dc=com",
			"uid=alice,ou=people,dc=example,dc=com",
			"uid=bob,ou=people,dc=example,dc=com",
		},
		map[string]string{
			"uid=alice,ou=people,dc=example,dc=com": "Alice Streaming",
			"uid=bob,ou=people,dc=example,dc=com":   "Test User",
		},
	)

	consumerClient.Close()
	stopConsumer()

	offlineModify := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	offlineModify.Replace("cn", []string{"Alice Reconnected"})
	if err := providerClient.Modify(offlineModify); err != nil {
		t.Fatalf("Modify(alice offline): %v", err)
	}
	if err := providerClient.Del(ldap.NewDelRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("Delete(bob offline): %v", err)
	}
	if err := providerClient.Add(newPersonAddRequest("carol")); err != nil {
		t.Fatalf("Add(carol offline): %v", err)
	}

	stopConsumer = consumer.start(t)
	defer stopConsumer()
	consumerClient = dialOpenLDAPSyncreplConsumer(t, consumer.uri)
	defer consumerClient.Close()
	waitForOpenLDAPSyncreplEntries(
		t,
		consumerClient,
		[]string{
			"dc=example,dc=com",
			"ou=people,dc=example,dc=com",
			"uid=alice,ou=people,dc=example,dc=com",
			"uid=carol,ou=people,dc=example,dc=com",
		},
		map[string]string{
			"uid=alice,ou=people,dc=example,dc=com": "Alice Reconnected",
			"uid=carol,ou=people,dc=example,dc=com": "Test User",
		},
	)
}

func TestLDAPGoSyncreplConsumesOpenLDAPProvider(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	providerURI, stopProvider := startOpenLDAPReferenceServer(
		t,
		tools,
		[]string{"syncprov"},
	)
	defer stopProvider()
	providerAddress := strings.TrimPrefix(providerURI, "ldap://")

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedSyncConsumerDatabase(t, consumerStore, providerAddress, "secret")
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer func() {
		if stopConsumer != nil {
			stopConsumer()
		}
	}()

	consumer := dialLDAPRoot(t, consumerAddress)
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice",
	)
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=bob,ou=people,dc=example,dc=com",
		"cn",
		"Bob",
	)

	provider, err := ldap.DialURL(providerURI)
	if err != nil {
		t.Fatalf("DialURL(OpenLDAP provider): %v", err)
	}
	defer provider.Close()
	if err := provider.Bind(syncTestRootDN, "secret"); err != nil {
		t.Fatalf("Bind(OpenLDAP provider): %v", err)
	}
	streaming := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	streaming.Replace("cn", []string{"Alice Streaming"})
	if err := provider.Modify(streaming); err != nil {
		t.Fatalf("OpenLDAP provider modify: %v", err)
	}
	if err := provider.Add(newPersonAddRequest("dave")); err != nil {
		t.Fatalf("OpenLDAP provider add: %v", err)
	}
	if err := provider.Del(ldap.NewDelRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("OpenLDAP provider delete: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice Streaming",
	)
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=dave,ou=people,dc=example,dc=com",
		"uid",
		"dave",
	)
	waitForSyncConsumerMissing(
		t,
		consumer,
		"uid=bob,ou=people,dc=example,dc=com",
	)

	consumer.Close()
	stopConsumer()
	stopConsumer = nil

	offline := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	offline.Replace("cn", []string{"Alice Reconnected"})
	if err := provider.Modify(offline); err != nil {
		t.Fatalf("OpenLDAP provider offline modify: %v", err)
	}
	if err := provider.Del(ldap.NewDelRequest(
		"uid=carol,ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("OpenLDAP provider offline delete: %v", err)
	}
	if err := provider.Add(newPersonAddRequest("erin")); err != nil {
		t.Fatalf("OpenLDAP provider offline add: %v", err)
	}

	consumerAddress, stopConsumer = startServer(t, consumerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	consumer = dialLDAPRoot(t, consumerAddress)
	defer consumer.Close()
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice Reconnected",
	)
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=erin,ou=people,dc=example,dc=com",
		"uid",
		"erin",
	)
	waitForSyncConsumerMissing(
		t,
		consumer,
		"uid=carol,ou=people,dc=example,dc=com",
	)
}

func TestLDAPGoSyncreplConsumesOpenLDAPProviderWithSCRAMSHA256(
	t *testing.T,
) {
	tools := requireOpenLDAPReferenceTools(t)
	const replicatorDN = "uid=replicator,ou=people,dc=example,dc=com"
	const replicatorPassword = "replication-secret"
	providerURI, stopProvider := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{"syncprov"},
		`authz-regexp "^uid=replicator,.*cn=auth$" "`+
			replicatorDN+`"`,
		`access to dn.exact="`+replicatorDN+`"
  by anonymous auth
  by dn.exact="`+replicatorDN+`" read
  by * none
access to *
  by dn.exact="`+replicatorDN+`" read
  by * none`,
		`
dn: `+replicatorDN+`
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: replicator
cn: Replication Account
sn: Account
userPassword: `+replicatorPassword+`
`,
	)
	defer stopProvider()

	provider, err := ldap.DialURL(providerURI)
	if err != nil {
		t.Fatalf("DialURL(OpenLDAP SASL provider): %v", err)
	}
	defer provider.Close()
	rootDSE, err := provider.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedSASLMechanisms"},
		nil,
	))
	if err != nil {
		t.Fatalf("read OpenLDAP supported SASL mechanisms: %v", err)
	}
	if len(rootDSE.Entries) != 1 ||
		!slices.ContainsFunc(
			rootDSE.Entries[0].GetAttributeValues(
				"supportedSASLMechanisms",
			),
			func(value string) bool {
				return strings.EqualFold(value, "SCRAM-SHA-256")
			},
		) {
		t.Skip("OpenLDAP Cyrus SASL has no SCRAM-SHA-256 plugin")
	}

	providerAddress := strings.TrimPrefix(providerURI, "ldap://")
	probeConfig := syncConsumerConfig{
		bindMethod:         "sasl",
		saslMechanism:      "SCRAM-SHA-256",
		authenticationID:   "replicator",
		credentials:        []byte(replicatorPassword),
		securityProperties: defaultSyncConsumerSASLSecurityProperties(),
	}
	probeTransport, err := dialSyncConsumer(
		context.Background(),
		probeConfig,
		providerURI,
	)
	if err != nil {
		t.Fatalf("dial OpenLDAP SCRAM probe: %v", err)
	}
	defer probeTransport.close()
	if err := bindSyncConsumerSASL(probeTransport, probeConfig); err != nil {
		t.Fatalf("bind OpenLDAP SCRAM probe: %v", err)
	}
	if err := probeTransport.clearDeadline(); err != nil {
		t.Fatalf("clear OpenLDAP SCRAM probe deadline: %v", err)
	}
	probe := ldap.NewConn(probeTransport.currentConnection(), false)
	probe.Start()
	defer probe.Close()
	probeResult, err := probe.Search(ldap.NewSearchRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	))
	probeEntries := 0
	if probeResult != nil {
		probeEntries = len(probeResult.Entries)
	}
	if err != nil || probeEntries != 1 {
		t.Fatalf(
			"search through OpenLDAP SCRAM identity: entries=%d error=%v",
			probeEntries,
			err,
		)
	}

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedOpenLDAPSASLSyncConsumerDatabase(
		t,
		consumerStore,
		providerAddress,
		replicatorPassword,
	)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopConsumer()
	consumer := dialLDAPRoot(t, consumerAddress)
	defer consumer.Close()
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice",
	)

	if err := provider.Bind(syncTestRootDN, "secret"); err != nil {
		t.Fatalf("Bind(OpenLDAP SASL provider root): %v", err)
	}
	modify := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Alice SCRAM Streaming"})
	if err := provider.Modify(modify); err != nil {
		t.Fatalf("modify OpenLDAP SASL provider: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice SCRAM Streaming",
	)
}

func seedOpenLDAPSASLSyncConsumerDatabase(
	t *testing.T,
	store storage.Store,
	providerAddress,
	password string,
) {
	t.Helper()
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{1}mdb")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			{
				Description: "olcSyncrepl",
				Values: stringValues(
					`{0}rid=001 provider=ldap://` + providerAddress +
						` bindmethod=sasl saslmech=SCRAM-SHA-256` +
						` authcid=replicator credentials="` + password + `"` +
						` searchbase="dc=example,dc=com"` +
						` filter="(objectClass=*)" scope=sub attrs="*,+"` +
						` schemachecking=off type=refreshAndPersist` +
						` retry="1 +"`,
				),
			},
			{
				Description: "olcUpdateRef",
				Values:      stringValues("ldap://" + providerAddress),
			},
		},
	}
	if err := store.Update(context.Background(), func(
		writer storage.Writer,
	) error {
		if err := writer.Put(entry, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed SCRAM syncrepl consumer: %v", err)
	}
}

func newOpenLDAPSyncreplConsumer(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerURI string,
) *openLDAPSyncreplConsumer {
	t.Helper()
	root := t.TempDir()
	databaseDir := filepath.Join(root, "db")
	if err := os.Mkdir(databaseDir, 0o700); err != nil {
		t.Fatalf("create OpenLDAP consumer database directory: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve OpenLDAP consumer port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release OpenLDAP consumer port: %v", err)
	}

	configPath := filepath.Join(root, "slapd.conf")
	config := fmt.Sprintf(
		`include %s
include %s
include %s
pidfile %s
argsfile %s

database mdb
maxsize 1073741824
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw %s
directory %s
index objectClass eq
index entryUUID,entryCSN eq

syncrepl rid=001
  provider=%s
  type=refreshAndPersist
  retry="1 10 5 +"
  searchbase="dc=example,dc=com"
  scope=sub
  attrs="*,+"
  schemachecking=off
  bindmethod=simple
  binddn="cn=admin,dc=example,dc=com"
  credentials=%s
updateref %s
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		filepath.Join(root, "slapd.pid"),
		filepath.Join(root, "slapd.args"),
		openLDAPConsumerPassword,
		databaseDir,
		providerURI,
		syncTestRootPassword,
		providerURI,
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write OpenLDAP consumer config: %v", err)
	}
	return &openLDAPSyncreplConsumer{
		tools:      tools,
		configPath: configPath,
		address:    address,
		uri:        "ldap://" + address,
	}
}

func (consumer *openLDAPSyncreplConsumer) start(t *testing.T) func() {
	t.Helper()
	var logs bytes.Buffer
	command := exec.Command(
		consumer.tools.slapd,
		"-f",
		consumer.configPath,
		"-h",
		consumer.uri,
		"-d",
		"0",
	)
	command.Stdout = &logs
	command.Stderr = &logs
	if err := command.Start(); err != nil {
		t.Fatalf("start OpenLDAP syncrepl consumer: %v", err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	}
	t.Cleanup(stop)

	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, err := net.DialTimeout(
			"tcp",
			consumer.address,
			100*time.Millisecond,
		)
		if err == nil {
			_ = connection.Close()
			return stop
		}
		if time.Now().After(deadline) {
			stop()
			t.Fatalf(
				"OpenLDAP syncrepl consumer did not start: %v\n%s",
				err,
				logs.Bytes(),
			)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func dialOpenLDAPSyncreplConsumer(
	t *testing.T,
	uri string,
) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(OpenLDAP consumer): %v", err)
	}
	if err := client.Bind(syncTestRootDN, openLDAPConsumerPassword); err != nil {
		client.Close()
		t.Fatalf("Bind(OpenLDAP consumer): %v", err)
	}
	return client
}

func waitForOpenLDAPSyncreplEntries(
	t *testing.T,
	client *ldap.Conn,
	wantDNs []string,
	wantCNs map[string]string,
) {
	t.Helper()
	wantDNs = slices.Clone(wantDNs)
	sort.Strings(wantDNs)
	deadline := time.Now().Add(10 * time.Second)
	var lastDNs []string
	lastCNs := make(map[string]string)
	var lastErr error
	for {
		result, err := client.Search(ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"cn"},
			nil,
		))
		lastErr = err
		lastDNs = lastDNs[:0]
		clear(lastCNs)
		if err == nil {
			for _, entry := range result.Entries {
				lastDNs = append(lastDNs, entry.DN)
				lastCNs[entry.DN] = entry.GetAttributeValue("cn")
			}
			sort.Strings(lastDNs)
			if slices.Equal(lastDNs, wantDNs) &&
				openLDAPSyncreplCNsEqual(lastCNs, wantCNs) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf(
				"OpenLDAP syncrepl did not converge: DNs %q, CNs %q, error %v; want DNs %q, CNs %q",
				lastDNs,
				lastCNs,
				lastErr,
				wantDNs,
				wantCNs,
			)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func openLDAPSyncreplCNsEqual(
	got map[string]string,
	want map[string]string,
) bool {
	for dn, wantCN := range want {
		if got[dn] != wantCN {
			return false
		}
	}
	return true
}
