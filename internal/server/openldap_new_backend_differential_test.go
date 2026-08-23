package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferencePasswdBackendDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	users, err := readPasswdUsers(defaultPasswdFile)
	if err != nil || len(users) == 0 {
		t.Fatalf("read reference passwd source: %v", err)
	}
	user := users[0]
	for _, candidate := range users {
		if candidate.name == "root" {
			user = candidate
			break
		}
	}

	const suffix = "ou=accounts"
	config := fmt.Sprintf(
		"include %s\ninclude %s\ndatabase passwd\nsuffix %q\n",
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		suffix,
	)
	openLDAPURI := startOpenLDAPReferenceConfigServer(t, tools, config)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswdReferenceConfiguration(t, store, suffix)
	ldapGoAddress, stop := startServer(t, store, Config{})
	defer stop()

	dn := "uid=" + ldap.EscapeDN(user.name) + "," + suffix
	attributes := []string{"objectClass", "uid", "cn", "sn", "description"}
	openLDAPEntry := searchReferenceEntry(t, openLDAPURI, dn, attributes)
	ldapGoEntry := searchReferenceEntry(t, "ldap://"+ldapGoAddress, dn, attributes)
	if got, want := comparableLDAPEntry(ldapGoEntry), comparableLDAPEntry(openLDAPEntry); got != want {
		t.Fatalf("passwd differential\nldap-go: %s\nOpenLDAP: %s", got, want)
	}
}

func TestOpenLDAPReferenceDNSSRVBackendDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	config := fmt.Sprintf(
		"include %s\ninclude %s\ndatabase dnssrv\nsuffix \"\"\n",
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
	)
	openLDAPURI := startOpenLDAPReferenceConfigServer(t, tools, config)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDNSSRVBackendConfiguration(t, store, "1m", "10s")
	resolver := &fakeDNSSRVResolver{err: &net.DNSError{
		Err: "no such host", Name: "example.com", IsNotFound: true,
	}}
	ldapGoAddress, stop := startServer(t, store, Config{DNSSRVResolver: resolver})
	defer stop()

	request := func(base string) *ldap.SearchRequest {
		return ldap.NewSearchRequest(
			base,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			nil,
			[]ldap.Control{ldap.NewControlManageDsaIT(true)},
		)
	}
	openLDAPCode := referenceSearchResultCode(t, openLDAPURI, request("dc=example,dc=invalid"))
	ldapGoCode := referenceSearchResultCode(t, "ldap://"+ldapGoAddress, request("dc=example,dc=com"))
	if openLDAPCode != ldapGoCode || openLDAPCode != ldap.LDAPResultNoSuchObject {
		t.Fatalf("dnssrv result codes: ldap-go=%d OpenLDAP=%d", ldapGoCode, openLDAPCode)
	}
}

func TestOpenLDAPReferenceAsyncMetaBackendDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	providerAddress, stopProvider := startAsyncMetaTestProvider(t, "reference-async")
	defer stopProvider()

	config := fmt.Sprintf(
		"include %s\ninclude %s\ninclude %s\n"+
			"database asyncmeta\nsuffix %q\nuri %q\n",
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		ldapBackendTestSuffix,
		"ldap://"+providerAddress+"/"+ldapBackendTestSuffix,
	)
	openLDAPURI := startOpenLDAPReferenceConfigServer(t, tools, config)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSingleAsyncMetaReferenceConfiguration(t, store, providerAddress)
	ldapGoAddress, stop := startServer(t, store, Config{})
	defer stop()

	requestDN := "uid=reference-async," + ldapBackendTestPeopleDN
	attributes := []string{"uid", "cn", "sn"}
	openLDAPEntry := searchReferenceEntry(t, openLDAPURI, requestDN, attributes)
	ldapGoEntry := searchReferenceEntry(t, "ldap://"+ldapGoAddress, requestDN, attributes)
	if got, want := comparableLDAPEntry(ldapGoEntry), comparableLDAPEntry(openLDAPEntry); got != want {
		t.Fatalf("asyncmeta differential\nldap-go: %s\nOpenLDAP: %s", got, want)
	}
}

func TestOpenLDAPReferenceCryptDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	slappasswd := os.Getenv("OPENLDAP_SLAPPASSWD")
	if slappasswd == "" {
		var err error
		slappasswd, err = exec.LookPath("slappasswd")
		if err != nil {
			t.Fatalf("find OpenLDAP slappasswd: %v", err)
		}
	}
	const password = "reference-crypt-secret"
	command := exec.Command(
		slappasswd,
		"-s", password,
		"-h", "{CRYPT}",
		"-c", "%.2s",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("OpenLDAP slappasswd {CRYPT}: %v: %s", err, output)
	}
	stored := strings.TrimSpace(string(output))
	if !strings.HasPrefix(stored, auth.OpenLDAPCryptHashScheme) ||
		!auth.VerifyPassword([]byte(stored), []byte(password)) {
		t.Fatalf("ldap-go rejected OpenLDAP {CRYPT} value %q", stored)
	}

	extraData := fmt.Sprintf(
		"\ndn: uid=crypt,ou=people,dc=example,dc=com\n"+
			"objectClass: inetOrgPerson\nuid: crypt\ncn: Crypt User\nsn: User\nuserPassword: %s\n",
		stored,
	)
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t, tools, nil, "", "", extraData,
	)
	defer stopOpenLDAP()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	entry := directory.Entry{
		DN: "uid=crypt,ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues("crypt")},
			{Description: "cn", Values: stringValues("Crypt User")},
			{Description: "sn", Values: stringValues("User")},
			{Description: "userPassword", Values: stringValues(stored)},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed ldap-go {CRYPT} entry: %v", err)
	}
	ldapGoAddress, stop := startServer(t, store, Config{})
	defer stop()

	dn := entry.DN
	for _, endpoint := range []string{openLDAPURI, "ldap://" + ldapGoAddress} {
		assertReferenceBind(t, endpoint, dn, password, true)
		assertReferenceBind(t, endpoint, dn, "wrong-"+password, false)
	}
}

func startOpenLDAPReferenceConfigServer(
	t *testing.T,
	tools openLDAPReferenceTools,
	config string,
) string {
	t.Helper()
	root := t.TempDir()
	configPath := filepath.Join(root, "slapd.conf")
	logPath := filepath.Join(root, "slapd.log")
	config = fmt.Sprintf(
		"pidfile %s\nargsfile %s\n%s",
		filepath.Join(root, "slapd.pid"),
		filepath.Join(root, "slapd.args"),
		config,
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write OpenLDAP reference config: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve OpenLDAP reference port: %v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open OpenLDAP reference log: %v", err)
	}
	command := exec.Command(tools.slapd, "-f", configPath, "-h", "ldap://"+address, "-d", "0")
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		t.Fatalf("start OpenLDAP reference: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Signal(os.Interrupt)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = command.Process.Kill()
				<-done
			}
		}
		_ = logFile.Close()
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case waitErr := <-done:
			_ = logFile.Close()
			log, _ := os.ReadFile(logPath)
			t.Fatalf("OpenLDAP reference exited: %v\nconfig:\n%s\nlog:\n%s", waitErr, config, log)
		default:
		}
		connection, dialErr := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return "ldap://" + address
		}
		if time.Now().After(deadline) {
			t.Fatalf("OpenLDAP reference did not listen: %v", dialErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func seedPasswdReferenceConfiguration(t *testing.T, store storage.Store, suffix string) {
	t.Helper()
	entry := directory.Entry{
		DN: "olcDatabase={1}passwd,cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcPasswdConfig")},
			{Description: "olcDatabase", Values: stringValues("{1}passwd")},
			{Description: "olcSuffix", Values: stringValues(suffix)},
			{Description: "olcPasswdFile", Values: stringValues(defaultPasswdFile)},
			{Description: "olcAccess", Values: stringValues("{0}to * by * read")},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.PutIn(configurationStoragePartition, entry, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{suffix})
	}); err != nil {
		t.Fatalf("seed passwd reference configuration: %v", err)
	}
}

func seedSingleAsyncMetaReferenceConfiguration(
	t *testing.T,
	store storage.Store,
	providerAddress string,
) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: asyncMetaTestDatabaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcAsyncMetaConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}asyncmeta")},
				{Description: "olcSuffix", Values: stringValues(ldapBackendTestSuffix)},
			},
		},
		asyncMetaTestTarget(0, providerAddress),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{ldapBackendTestSuffix})
	}); err != nil {
		t.Fatalf("seed asyncmeta reference configuration: %v", err)
	}
}

func searchReferenceEntry(
	t *testing.T,
	uri, dn string,
	attributes []string,
) *ldap.Entry {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial %s: %v", uri, err)
	}
	defer client.Close()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		attributes,
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("search %s at %s: entries=%d error=%v", dn, uri, len(result.Entries), err)
	}
	return result.Entries[0]
}

func comparableLDAPEntry(entry *ldap.Entry) string {
	attributes := make([]string, 0, len(entry.Attributes))
	for _, attribute := range entry.Attributes {
		values := append([]string(nil), attribute.Values...)
		sort.Strings(values)
		attributes = append(attributes, strings.ToLower(attribute.Name)+"="+strings.Join(values, "\x00"))
	}
	sort.Strings(attributes)
	return strings.ToLower(entry.DN) + "|" + strings.Join(attributes, "|")
}

func referenceSearchResultCode(t *testing.T, uri string, request *ldap.SearchRequest) uint16 {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial %s: %v", uri, err)
	}
	defer client.Close()
	_, err = client.Search(request)
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	ldapError, ok := err.(*ldap.Error)
	if !ok {
		t.Fatalf("search %s returned non-LDAP error: %v", uri, err)
	}
	return ldapError.ResultCode
}

func assertReferenceBind(t *testing.T, uri, dn, password string, want bool) {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial %s: %v", uri, err)
	}
	defer client.Close()
	err = client.Bind(dn, password)
	if want && err != nil {
		t.Fatalf("Bind(%s): %v", uri, err)
	}
	if !want && !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("Bind(%s) error = %v, want invalidCredentials", uri, err)
	}
}
