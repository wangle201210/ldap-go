package server

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceGlobalDefaultReferralOnlineConfiguration(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI := startOpenLDAPDynamicConfigReferralServer(t, tools)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	localAddress, stopLocal := startServer(t, store, Config{})
	defer stopLocal()

	reference := observeDefaultReferralOnlineConfiguration(t, referenceURI)
	local := observeDefaultReferralOnlineConfiguration(t, "ldap://"+localAddress)
	if !reflect.DeepEqual(reference, local) {
		t.Fatalf(
			"online olcReferral:\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			local,
		)
	}
}

func TestOpenLDAPReferenceGlobalDefaultReferralValidation(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	for _, value := range []string{
		"ldap://ldap.example",
		"LDAPS://ldaps.example/",
		"ldapi://%2Fvar%2Frun%2Fldapi",
		"pldap://proxy.example/??",
		"pldaps://proxy.example/????!bindname=cn%3Droot",
		"pldap://proxy.example/????",
		"ldap+tlcp://opaque.example/dc=not-validated",
		"ordinary referral text",
		"ldap://example.test/dc=example,dc=com",
		"ldap://example.test/?cn,sn",
		"ldap://example.test/??sub",
		"ldap://example.test/???%28objectClass%3D%2A%29",
		"ldap://example.test:not-a-port",
		"ldaps://[2001:db8::1",
		"ldapi://%ZZ",
		"<ldap://example.test",
	} {
		t.Run(strings.NewReplacer("/", "_", ":", "_").Replace(value), func(t *testing.T) {
			localErr := validateOpenLDAPGlobalReferral(value)
			referenceValid := openLDAPReferenceAcceptsGlobalReferral(t, tools, value)
			if (localErr == nil) != referenceValid {
				t.Fatalf(
					"global referral %q: OpenLDAP valid=%t, ldap-go error=%v",
					value,
					referenceValid,
					localErr,
				)
			}
		})
	}
}

func openLDAPReferenceAcceptsGlobalReferral(
	t *testing.T,
	tools openLDAPReferenceTools,
	value string,
) bool {
	t.Helper()
	root := t.TempDir()
	databaseDir := filepath.Join(root, "db")
	if err := os.Mkdir(databaseDir, 0o700); err != nil {
		t.Fatalf("create OpenLDAP validation database: %v", err)
	}
	configPath := filepath.Join(root, "slapd.conf")
	config := fmt.Sprintf(
		`include %s
referral "%s"
database mdb
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
directory %s
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		strings.ReplaceAll(value, `"`, `\"`),
		databaseDir,
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write OpenLDAP validation config: %v", err)
	}
	command := exec.Command(tools.slapd, "-Ttest", "-u", "-f", configPath)
	return command.Run() == nil
}

type defaultReferralOnlineObservation struct {
	add             uint16
	duplicate       uint16
	second          uint16
	multiple        uint16
	invalid         uint16
	afterInvalid    defaultReferralOutcome
	remove          uint16
	afterRemove     defaultReferralOutcome
	rootAfterRemove string
}

func observeDefaultReferralOnlineConfiguration(
	t *testing.T,
	uri string,
) defaultReferralOnlineObservation {
	t.Helper()
	configClient, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s config): %v", uri, err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(%s cn=config): %v", uri, err)
	}
	code := func(request *ldap.ModifyRequest) uint16 {
		return defaultReferralLDAPResultCode(configClient.Modify(request))
	}
	observation := defaultReferralOnlineObservation{}
	add := ldap.NewModifyRequest("cn=config", nil)
	add.Add("olcReferral", []string{defaultReferralURI})
	observation.add = code(add)
	duplicate := ldap.NewModifyRequest("cn=config", nil)
	duplicate.Add("olcReferral", []string{defaultReferralURI})
	observation.duplicate = code(duplicate)
	second := ldap.NewModifyRequest("cn=config", nil)
	second.Add("olcReferral", []string{"ldap://second.example"})
	observation.second = code(second)
	multiple := ldap.NewModifyRequest("cn=config", nil)
	multiple.Replace("olcReferral", []string{
		defaultReferralURI,
		"ldap://second.example",
	})
	observation.multiple = code(multiple)
	invalid := ldap.NewModifyRequest("cn=config", nil)
	invalid.Replace("olcReferral", []string{"ldap://bad.example/dc=forbidden"})
	observation.invalid = code(invalid)

	dataClient, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s data): %v", uri, err)
	}
	defer dataClient.Close()
	search := func() defaultReferralOutcome {
		_, searchErr := dataClient.Search(ldap.NewSearchRequest(
			defaultReferralTargetDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"dn"},
			nil,
		))
		return observeDefaultReferralOutcome(t, searchErr)
	}
	observation.afterInvalid = search()
	remove := ldap.NewModifyRequest("cn=config", nil)
	remove.Delete("olcReferral", nil)
	observation.remove = code(remove)
	observation.afterRemove = search()
	rootDSE, err := dataClient.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"ref"},
		nil,
	))
	if err != nil || len(rootDSE.Entries) != 1 {
		t.Fatalf("Search(%s Root DSE): %#v, %v", uri, rootDSE, err)
	}
	observation.rootAfterRemove = strings.Join(
		rootDSE.Entries[0].GetAttributeValues("ref"),
		"\n",
	)
	return observation
}

func defaultReferralLDAPResultCode(err error) uint16 {
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var ldapError *ldap.Error
	if errors.As(err, &ldapError) {
		return ldapError.ResultCode
	}
	return ldap.LDAPResultOther
}

func startOpenLDAPDynamicConfigReferralServer(
	t *testing.T,
	tools openLDAPReferenceTools,
) string {
	t.Helper()
	root := t.TempDir()
	databaseDir := filepath.Join(root, "db")
	configDir := filepath.Join(root, "slapd.d")
	if err := os.Mkdir(databaseDir, 0o700); err != nil {
		t.Fatalf("create OpenLDAP database: %v", err)
	}
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatalf("create OpenLDAP config directory: %v", err)
	}
	configPath := filepath.Join(root, "slapd.conf")
	dataPath := filepath.Join(root, "data.ldif")
	config := fmt.Sprintf(
		`include %s
include %s
include %s
pidfile %s
argsfile %s
database config
rootdn "cn=config"
rootpw config-secret
database mdb
maxsize 1073741824
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
directory %s
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		filepath.Join(root, "slapd.pid"),
		filepath.Join(root, "slapd.args"),
		databaseDir,
	)
	data := `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example
`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write OpenLDAP config: %v", err)
	}
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		t.Fatalf("write OpenLDAP data: %v", err)
	}
	slaptest := filepath.Join(filepath.Dir(tools.slapadd), "slaptest")
	command := exec.Command(tools.slapadd, "-q", "-f", configPath, "-l", dataPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("seed OpenLDAP slapd.conf fixture: %v\n%s", err, output)
	}
	command = exec.Command(slaptest, "-f", configPath, "-F", configDir)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("convert OpenLDAP cn=config: %v\n%s", err, output)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve OpenLDAP port: %v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	uri := "ldap://" + address
	var logs bytes.Buffer
	slapd := exec.Command(tools.slapd, "-F", configDir, "-h", uri, "-d", "0")
	slapd.Stdout = &logs
	slapd.Stderr = &logs
	if err := slapd.Start(); err != nil {
		t.Fatalf("start OpenLDAP cn=config server: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- slapd.Wait() }()
	t.Cleanup(func() {
		if slapd.Process != nil {
			_ = slapd.Process.Signal(os.Interrupt)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = slapd.Process.Kill()
				<-done
			}
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case waitErr := <-done:
			t.Fatalf("OpenLDAP cn=config server exited: %v\n%s", waitErr, logs.String())
		default:
		}
		connection, dialErr := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return uri
		}
		if time.Now().After(deadline) {
			t.Fatalf("OpenLDAP cn=config server did not listen: %v\n%s", dialErr, logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestOpenLDAPReferenceGlobalDefaultReferral(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	for _, test := range []struct {
		name              string
		referrals         []string
		defaultSearchBase string
		globalConf        string
	}{
		{name: "not configured"},
		{
			name: "ordered LDAP and non-LDAP referrals",
			referrals: []string{
				"ldap://first.example:1389",
				"ldaps://second.example:1636",
				"pldap://proxy.example:2389",
				"ldapi://%2Ftmp%2Fldap-go-ldapi",
				"ldapi://%ZZ",
				"ldap+tlcp://tlcp.example:1636",
				"https://directory.example/referral-info",
				"ldap://first.example:1389",
			},
			globalConf: "referral ldap://first.example:1389\n" +
				"referral ldaps://second.example:1636\n" +
				"referral pldap://proxy.example:2389\n" +
				"referral ldapi://%2Ftmp%2Fldap-go-ldapi\n" +
				"referral ldapi://%ZZ\n" +
				"referral ldap+tlcp://tlcp.example:1636\n" +
				"referral https://directory.example/referral-info\n" +
				"referral ldap://first.example:1389",
		},
		{
			name:              "default search base is rewritten before referral",
			referrals:         []string{"ldap://first.example:1389"},
			defaultSearchBase: "dc=redirected,dc=example",
			globalConf: "referral ldap://first.example:1389\n" +
				`defaultSearchBase "dc=redirected,dc=example"`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
				t,
				tools,
				nil,
				test.globalConf,
				"",
				"",
			)
			defer stopReference()

			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			if test.referrals != nil {
				putDefaultReferralConfigGlobalEntry(t, store, test.referrals)
			}
			if test.defaultSearchBase != "" {
				if err := store.Update(t.Context(), func(writer storage.Writer) error {
					configuration := storage.WriterInPartition(
						writer,
						storage.OpenLDAPConfigPartition,
					)
					entry, err := configuration.Get(configurationSuffix)
					if err != nil {
						return err
					}
					entry.ReplaceValues(
						"olcDefaultSearchBase",
						stringValues(test.defaultSearchBase),
					)
					return configuration.Put(entry, true)
				}); err != nil {
					t.Fatalf("set default search base: %v", err)
				}
			}
			localAddress, stopLocal := startServer(t, store, Config{
				RootDN:       "cn=admin,dc=example,dc=com",
				RootPassword: []byte("admin-secret"),
			})
			defer stopLocal()

			reference := observeGlobalDefaultReferral(
				t,
				referenceURI,
				"secret",
			)
			local := observeGlobalDefaultReferral(
				t,
				"ldap://"+localAddress,
				"admin-secret",
			)
			if !reflect.DeepEqual(reference, local) {
				t.Fatalf(
					"default referral:\nOpenLDAP: %#v\nldap-go:  %#v",
					reference,
					local,
				)
			}
		})
	}
}

type defaultReferralObservation struct {
	rootRefs         string
	baseSearch       defaultReferralOutcome
	oneSearch        defaultReferralOutcome
	subtreeSearch    defaultReferralOutcome
	childrenSearch   defaultReferralOutcome
	emptyOneSearch   defaultReferralOutcome
	emptySubSearch   defaultReferralOutcome
	emptyChildSearch defaultReferralOutcome
	managedSearch    defaultReferralOutcome
	compare          defaultReferralOutcome
	add              defaultReferralOutcome
	modify           defaultReferralOutcome
	delete           defaultReferralOutcome
	modifyDN         defaultReferralOutcome
}

type defaultReferralOutcome struct {
	code       uint16
	matchedDN  string
	diagnostic string
	referrals  string
}

func observeGlobalDefaultReferral(
	t *testing.T,
	uri,
	password string,
) defaultReferralObservation {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", password); err != nil {
		t.Fatalf("Bind(%s): %v", uri, err)
	}

	rootDSE, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"ref"},
		nil,
	))
	if err != nil || len(rootDSE.Entries) != 1 {
		t.Fatalf("Search(%s Root DSE): %#v, %v", uri, rootDSE, err)
	}
	rootRefs := rootDSE.Entries[0].GetAttributeValues("ref")
	sort.Strings(rootRefs)

	search := func(base string, scope int, controls []ldap.Control) defaultReferralOutcome {
		_, searchErr := client.Search(ldap.NewSearchRequest(
			base,
			scope,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"dn"},
			controls,
		))
		return observeDefaultReferralOutcome(t, searchErr)
	}
	observation := defaultReferralObservation{
		rootRefs:         strings.Join(rootRefs, "\n"),
		baseSearch:       search(defaultReferralTargetDN, ldap.ScopeBaseObject, nil),
		oneSearch:        search(defaultReferralTargetDN, ldap.ScopeSingleLevel, nil),
		subtreeSearch:    search(defaultReferralTargetDN, ldap.ScopeWholeSubtree, nil),
		childrenSearch:   search(defaultReferralTargetDN, ldap.ScopeChildren, nil),
		emptyOneSearch:   search("", ldap.ScopeSingleLevel, nil),
		emptySubSearch:   search("", ldap.ScopeWholeSubtree, nil),
		emptyChildSearch: search("", ldap.ScopeChildren, nil),
		managedSearch: search(
			defaultReferralTargetDN,
			ldap.ScopeBaseObject,
			[]ldap.Control{ldap.NewControlManageDsaIT(true)},
		),
	}
	_, compareErr := client.Compare(defaultReferralTargetDN, "cn", "outside")
	observation.compare = observeDefaultReferralOutcome(t, compareErr)
	add := ldap.NewAddRequest(defaultReferralTargetDN, nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"outside"})
	add.Attribute("cn", []string{"Outside"})
	add.Attribute("sn", []string{"Outside"})
	observation.add = observeDefaultReferralOutcome(t, client.Add(add))
	modify := ldap.NewModifyRequest(defaultReferralTargetDN, nil)
	modify.Replace("cn", []string{"Changed"})
	observation.modify = observeDefaultReferralOutcome(t, client.Modify(modify))
	observation.delete = observeDefaultReferralOutcome(
		t,
		client.Del(ldap.NewDelRequest(defaultReferralTargetDN, nil)),
	)
	observation.modifyDN = observeDefaultReferralOutcome(
		t,
		client.ModifyDN(ldap.NewModifyDNRequest(
			defaultReferralTargetDN,
			"uid=renamed",
			true,
			"",
		)),
	)
	return observation
}

func observeDefaultReferralOutcome(t *testing.T, err error) defaultReferralOutcome {
	t.Helper()
	if err == nil {
		return defaultReferralOutcome{code: ldap.LDAPResultSuccess}
	}
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		t.Fatalf("LDAP operation error = %v", err)
	}
	diagnostic := ""
	if ldapError.Err != nil {
		diagnostic = ldapError.Err.Error()
	}
	return defaultReferralOutcome{
		code:       ldapError.ResultCode,
		matchedDN:  ldapError.MatchedDN,
		diagnostic: diagnostic,
		referrals:  strings.Join(ldapResultReferrals(ldapError.Packet), "\n"),
	}
}
