package server

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPMetaVersion = "2.6.13"
	openLDAPMetaTag     = "OPENLDAP_REL_ENG_2_6_13"
	openLDAPMetaCommit  = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

	openLDAPMetaBaseDN       = "dc=meta,dc=test"
	openLDAPMetaSpecificBase = "ou=team," + openLDAPMetaBaseDN
)

type openLDAPMetaSearchObservation struct {
	code        uint16
	dn          string
	description string
}

type openLDAPMetaCompareObservation struct {
	matched bool
	code    uint16
}

type openLDAPMetaReferenceOutcome struct {
	failoverProbeCode uint16
	broadRoute        openLDAPMetaSearchObservation
	specificRoute     openLDAPMetaSearchObservation
	broadCompare      openLDAPMetaCompareObservation
	specificCompare   openLDAPMetaCompareObservation
	duplicateAddCode  uint16

	broadAddCode           uint16
	broadModifyCode        uint16
	broadRenameCode        uint16
	broadProviderBeforeDel openLDAPMetaSearchObservation
	broadDeleteCode        uint16
	broadProviderAfterDel  openLDAPMetaSearchObservation

	specificAddCode           uint16
	specificProviderBeforeDel openLDAPMetaSearchObservation
	specificDeleteCode        uint16
	specificProviderAfterDel  openLDAPMetaSearchObservation
}

func TestOpenLDAPReferenceMetaBackend(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	var reference openLDAPMetaReferenceOutcome
	t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
		providerOne, stopProviderOne := startOpenLDAPMetaProvider(
			t,
			tools,
			"route-one",
			"provider-one",
		)
		defer stopProviderOne()
		providerTwo, stopProviderTwo := startOpenLDAPMetaProvider(
			t,
			tools,
			"route-two",
			"provider-two",
		)
		defer stopProviderTwo()

		deadURI := reserveClosedOpenLDAPMetaURI(t)
		metaURI, stopMeta := startOpenLDAPMetaProxy(
			t,
			tools,
			deadURI,
			providerOne,
			providerTwo,
		)
		defer stopMeta()

		reference = observeOpenLDAPMetaReference(
			t,
			metaURI,
			providerOne,
			providerTwo,
		)
		assertOpenLDAPMetaReferenceOutcome(t, reference)
	})
	if t.Failed() {
		return
	}

	t.Run("ldap-go differential", func(t *testing.T) {
		providerOne, stopProviderOne := startOpenLDAPMetaProvider(
			t,
			tools,
			"route-one",
			"provider-one",
		)
		defer stopProviderOne()
		providerTwo, stopProviderTwo := startOpenLDAPMetaProvider(
			t,
			tools,
			"route-two",
			"provider-two",
		)
		defer stopProviderTwo()

		deadURI := reserveClosedOpenLDAPMetaURI(t)
		ldapGoURI, stopLDAPGo := startLDAPGoMetaReferenceFixture(
			t,
			deadURI,
			providerOne,
			providerTwo,
		)
		defer stopLDAPGo()

		got := observeOpenLDAPMetaReference(
			t,
			ldapGoURI,
			providerOne,
			providerTwo,
		)
		assertOpenLDAPMetaFailoverProbeCode(t, "ldap-go", got.failoverProbeCode)
		if !reflect.DeepEqual(
			stableOpenLDAPMetaReferenceOutcome(got),
			stableOpenLDAPMetaReferenceOutcome(reference),
		) {
			t.Fatalf(
				"ldap-go back-meta is not implemented or differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
				reference,
				got,
			)
		}
	})
}

func requireOpenLDAPMetaReferenceTools(t *testing.T) openLDAPReferenceTools {
	t.Helper()
	tools := requireOpenLDAPReferenceTools(t)
	output, err := exec.Command(tools.slapd, "-VVV").CombinedOutput()
	features := make(map[string]bool)
	for _, line := range strings.Split(string(output), "\n") {
		features[strings.ToLower(strings.TrimSpace(line))] = true
	}
	for _, feature := range []string{"ldap", "meta"} {
		if !features[feature] {
			t.Skipf(
				"the selected OpenLDAP slapd was not built with the %s backend:\n%s",
				feature,
				output,
			)
		}
	}
	if err != nil {
		t.Fatalf("inspect pinned OpenLDAP backends: %v\n%s", err, output)
	}
	return tools
}

func assertPinnedOpenLDAPMetaReference(
	t *testing.T,
	tools openLDAPReferenceTools,
) {
	t.Helper()
	if got := os.Getenv("OPENLDAP_REFERENCE_VERIFIED"); got != "1" {
		t.Fatalf("OPENLDAP_REFERENCE_VERIFIED = %q, want 1", got)
	}
	if got := os.Getenv("OPENLDAP_ACTUAL_VERSION"); got != openLDAPMetaVersion {
		t.Fatalf(
			"OpenLDAP reference version = %q, want %q",
			got,
			openLDAPMetaVersion,
		)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPMetaCommit {
		t.Fatalf(
			"OpenLDAP reference commit = %q, want %q",
			got,
			openLDAPMetaCommit,
		)
	}

	versionOutput, err := exec.Command(tools.slapd, "-VV").CombinedOutput()
	if err != nil && len(versionOutput) == 0 {
		t.Fatalf("inspect OpenLDAP version: %v", err)
	}
	if !strings.Contains(
		string(versionOutput),
		"OpenLDAP: slapd "+openLDAPMetaVersion+" ",
	) {
		t.Fatalf(
			"back-meta differential requires OpenLDAP slapd %s, got:\n%s",
			openLDAPMetaVersion,
			versionOutput,
		)
	}

	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Fatal("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	assertOpenLDAPMetaGitRevision(t, sourceRoot, "HEAD", openLDAPMetaCommit)
	assertOpenLDAPMetaGitRevision(
		t,
		sourceRoot,
		openLDAPMetaTag+"^{commit}",
		openLDAPMetaCommit,
	)

	pinnedFiles := map[string]string{
		filepath.Join("servers", "slapd", "back-meta", "init.c"):   "6f1494f3181c702d7516b451d8694d79a3b2be72be79a8eaca5162df65d5e925",
		filepath.Join("servers", "slapd", "back-meta", "conn.c"):   "0e5cd3a216e5cd1181dded5d2ceb3723f8254ef01e58c2e34c666d440612e177",
		filepath.Join("servers", "slapd", "back-meta", "search.c"): "9c5d6d26b99b7084f0d52101ef670d642b3e4fe7daaa1e3852dfa1c69f4b28c7",
		filepath.Join("tests", "scripts", "test035-meta"):          "3b390ced80241db15a6dbe801542cbe936cad54482466890ef2c9f0ab569547f",
		filepath.Join("tests", "data", "slapd-meta.conf"):          "9fdd98d7ddcb2dcbba7c8c93b3d2be14f0d2517c8be5a0e6996fb75f5a825fd8",
	}
	for relativePath, wantHash := range pinnedFiles {
		path := filepath.Join(sourceRoot, relativePath)
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read pinned OpenLDAP source %s: %v", path, readErr)
		}
		if gotHash := fmt.Sprintf("%x", sha256.Sum256(contents)); gotHash != wantHash {
			t.Fatalf(
				"pinned OpenLDAP source %s SHA-256 = %s, want %s",
				relativePath,
				gotHash,
				wantHash,
			)
		}
	}
}

func assertOpenLDAPMetaGitRevision(
	t *testing.T,
	sourceRoot string,
	revision string,
	want string,
) {
	t.Helper()
	output, err := exec.Command(
		"git",
		"-C",
		sourceRoot,
		"rev-parse",
		revision,
	).Output()
	if err != nil {
		t.Fatalf("resolve OpenLDAP revision %s: %v", revision, err)
	}
	if got := strings.TrimSpace(string(output)); got != want {
		t.Fatalf("OpenLDAP revision %s = %q, want %q", revision, got, want)
	}
}

func startOpenLDAPMetaProvider(
	t *testing.T,
	tools openLDAPReferenceTools,
	uid string,
	description string,
) (string, func()) {
	t.Helper()
	extraData := fmt.Sprintf(`
dn: uid=%s,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
uid: %s
cn: %s
sn: Route
description: %s
`, uid, uid, uid, description)
	return startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		"access to * by * write",
		extraData,
	)
}

func reserveClosedOpenLDAPMetaURI(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve unavailable back-meta URI: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release unavailable back-meta URI: %v", err)
	}
	return "ldap://" + address
}

func startOpenLDAPMetaProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	deadURI string,
	providerOne string,
	providerTwo string,
) (string, func()) {
	t.Helper()
	configuration := fmt.Sprintf(`database meta
suffix "%s"
rootdn "cn=admin,%s"
rootpw secret
access to * by * write
network-timeout 1
bind-timeout 1000000
nretries 1
chase-referrals no

uri "%s/%s" "%s/"
suffixmassage "%s" "dc=example,dc=com"
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"

uri "%s/%s"
suffixmassage "%s" "ou=people,dc=example,dc=com"
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"`,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		deadURI,
		openLDAPMetaBaseDN,
		providerOne,
		openLDAPMetaBaseDN,
		providerTwo,
		openLDAPMetaSpecificBase,
		openLDAPMetaSpecificBase,
	)
	return startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		configuration,
		"",
	)
}

func observeOpenLDAPMetaReference(
	t *testing.T,
	proxyURI string,
	providerOneURI string,
	providerTwoURI string,
) openLDAPMetaReferenceOutcome {
	t.Helper()
	client, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Fatalf("dial back-meta fixture %s: %v", proxyURI, err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,"+openLDAPMetaBaseDN, "secret"); err != nil {
		t.Fatalf("bind back-meta fixture %s: %v", proxyURI, err)
	}

	result := openLDAPMetaReferenceOutcome{}
	// OpenLDAP moves an unavailable URI to the end of the target's URI list
	// after the first attempt. Assert the probe result and then the recovered
	// target behavior without depending on elapsed time.
	result.failoverProbeCode = searchOpenLDAPMetaEntry(
		t,
		client,
		"uid=route-one,ou=people,"+openLDAPMetaBaseDN,
	).code
	result.broadCompare = compareOpenLDAPMetaEntry(
		client,
		"uid=route-one,ou=people,"+openLDAPMetaBaseDN,
		"description",
		"provider-one",
	)
	result.broadRoute = searchOpenLDAPMetaEntry(
		t,
		client,
		"uid=route-one,ou=people,"+openLDAPMetaBaseDN,
	)
	result.specificRoute = searchOpenLDAPMetaEntry(
		t,
		client,
		"uid=route-two,"+openLDAPMetaSpecificBase,
	)
	result.specificCompare = compareOpenLDAPMetaEntry(
		client,
		"uid=route-two,"+openLDAPMetaSpecificBase,
		"description",
		"provider-two",
	)

	duplicate := ldap.NewAddRequest(
		"uid=route-one,ou=people,"+openLDAPMetaBaseDN,
		nil,
	)
	duplicate.Attribute("objectClass", []string{"inetOrgPerson"})
	duplicate.Attribute("uid", []string{"route-one"})
	duplicate.Attribute("cn", []string{"Duplicate"})
	duplicate.Attribute("sn", []string{"Duplicate"})
	result.duplicateAddCode = monitorLDAPResultCode(client.Add(duplicate))

	broadDN := "uid=meta-write,ou=people," + openLDAPMetaBaseDN
	broadAdd := ldap.NewAddRequest(broadDN, nil)
	broadAdd.Attribute("objectClass", []string{"inetOrgPerson"})
	broadAdd.Attribute("uid", []string{"meta-write"})
	broadAdd.Attribute("cn", []string{"Meta Write"})
	broadAdd.Attribute("sn", []string{"Write"})
	result.broadAddCode = monitorLDAPResultCode(client.Add(broadAdd))
	broadModify := ldap.NewModifyRequest(broadDN, nil)
	broadModify.Replace("description", []string{"broad-modified"})
	result.broadModifyCode = monitorLDAPResultCode(client.Modify(broadModify))
	result.broadRenameCode = monitorLDAPResultCode(client.ModifyDN(
		ldap.NewModifyDNRequest(broadDN, "uid=meta-renamed", true, ""),
	))
	result.broadProviderBeforeDel = searchOpenLDAPMetaURI(
		t,
		providerOneURI,
		"uid=meta-renamed,ou=people,dc=example,dc=com",
	)
	result.broadDeleteCode = monitorLDAPResultCode(client.Del(ldap.NewDelRequest(
		"uid=meta-renamed,ou=people,"+openLDAPMetaBaseDN,
		nil,
	)))
	result.broadProviderAfterDel = searchOpenLDAPMetaURI(
		t,
		providerOneURI,
		"uid=meta-renamed,ou=people,dc=example,dc=com",
	)

	specificDN := "uid=meta-specific," + openLDAPMetaSpecificBase
	specificAdd := ldap.NewAddRequest(specificDN, nil)
	specificAdd.Attribute("objectClass", []string{"inetOrgPerson"})
	specificAdd.Attribute("uid", []string{"meta-specific"})
	specificAdd.Attribute("cn", []string{"Meta Specific"})
	specificAdd.Attribute("sn", []string{"Specific"})
	specificAdd.Attribute("description", []string{"specific-target"})
	result.specificAddCode = monitorLDAPResultCode(client.Add(specificAdd))
	result.specificProviderBeforeDel = searchOpenLDAPMetaURI(
		t,
		providerTwoURI,
		"uid=meta-specific,ou=people,dc=example,dc=com",
	)
	result.specificDeleteCode = monitorLDAPResultCode(client.Del(
		ldap.NewDelRequest(specificDN, nil),
	))
	result.specificProviderAfterDel = searchOpenLDAPMetaURI(
		t,
		providerTwoURI,
		"uid=meta-specific,ou=people,dc=example,dc=com",
	)
	return result
}

func searchOpenLDAPMetaURI(
	t *testing.T,
	uri string,
	dn string,
) openLDAPMetaSearchObservation {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial back-meta provider %s: %v", uri, err)
	}
	defer client.Close()
	return searchOpenLDAPMetaEntry(t, client, dn)
}

func searchOpenLDAPMetaEntry(
	t *testing.T,
	client *ldap.Conn,
	dn string,
) openLDAPMetaSearchObservation {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"description"},
		nil,
	))
	observation := openLDAPMetaSearchObservation{
		code: monitorLDAPResultCode(err),
	}
	if result != nil && len(result.Entries) > 0 {
		observation.dn = strings.ToLower(result.Entries[0].DN)
		observation.description = result.Entries[0].GetAttributeValue(
			"description",
		)
	}
	return observation
}

func compareOpenLDAPMetaEntry(
	client *ldap.Conn,
	dn string,
	attribute string,
	value string,
) openLDAPMetaCompareObservation {
	matched, err := client.Compare(dn, attribute, value)
	return openLDAPMetaCompareObservation{
		matched: matched,
		code:    monitorLDAPResultCode(err),
	}
}

func assertOpenLDAPMetaReferenceOutcome(
	t *testing.T,
	got openLDAPMetaReferenceOutcome,
) {
	t.Helper()
	assertOpenLDAPMetaFailoverProbeCode(t, "OpenLDAP", got.failoverProbeCode)
	want := openLDAPMetaReferenceOutcome{
		broadRoute: openLDAPMetaSearchObservation{
			code:        ldap.LDAPResultSuccess,
			dn:          "uid=route-one,ou=people," + openLDAPMetaBaseDN,
			description: "provider-one",
		},
		specificRoute: openLDAPMetaSearchObservation{
			code:        ldap.LDAPResultSuccess,
			dn:          "uid=route-two," + openLDAPMetaSpecificBase,
			description: "provider-two",
		},
		broadCompare: openLDAPMetaCompareObservation{
			matched: true,
			code:    ldap.LDAPResultSuccess,
		},
		specificCompare: openLDAPMetaCompareObservation{
			matched: true,
			code:    ldap.LDAPResultSuccess,
		},
		duplicateAddCode: ldap.LDAPResultEntryAlreadyExists,
		broadAddCode:     ldap.LDAPResultSuccess,
		broadModifyCode:  ldap.LDAPResultSuccess,
		broadRenameCode:  ldap.LDAPResultSuccess,
		broadProviderBeforeDel: openLDAPMetaSearchObservation{
			code:        ldap.LDAPResultSuccess,
			dn:          "uid=meta-renamed,ou=people,dc=example,dc=com",
			description: "broad-modified",
		},
		broadDeleteCode: ldap.LDAPResultSuccess,
		broadProviderAfterDel: openLDAPMetaSearchObservation{
			code: ldap.LDAPResultNoSuchObject,
		},
		specificAddCode: ldap.LDAPResultSuccess,
		specificProviderBeforeDel: openLDAPMetaSearchObservation{
			code:        ldap.LDAPResultSuccess,
			dn:          "uid=meta-specific,ou=people,dc=example,dc=com",
			description: "specific-target",
		},
		specificDeleteCode: ldap.LDAPResultSuccess,
		specificProviderAfterDel: openLDAPMetaSearchObservation{
			code: ldap.LDAPResultNoSuchObject,
		},
	}
	if !reflect.DeepEqual(stableOpenLDAPMetaReferenceOutcome(got), want) {
		t.Fatalf(
			"OpenLDAP back-meta fixture drifted:\n got: %#v\nwant: %#v",
			got,
			want,
		)
	}
}

func assertOpenLDAPMetaFailoverProbeCode(t *testing.T, implementation string, code uint16) {
	t.Helper()
	switch code {
	case ldap.LDAPResultSuccess, ldap.LDAPResultUnavailable:
		return
	default:
		t.Fatalf(
			"%s initial unavailable-URI probe result = %#x, want success or unavailable",
			implementation,
			code,
		)
	}
}

func stableOpenLDAPMetaReferenceOutcome(
	outcome openLDAPMetaReferenceOutcome,
) openLDAPMetaReferenceOutcome {
	// OpenLDAP may expose the first failed URI attempt or complete its retry
	// before replying. All observations after this probe must still match.
	outcome.failoverProbeCode = 0
	return outcome
}

func startLDAPGoMetaReferenceFixture(
	t *testing.T,
	deadURI string,
	providerOne string,
	providerTwo string,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoMetaReferenceConfiguration(
		t,
		store,
		deadURI,
		providerOne,
		providerTwo,
	)
	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, stop
}

func seedLDAPGoMetaReferenceConfiguration(
	t *testing.T,
	store storage.Store,
	deadURI string,
	providerOne string,
	providerTwo string,
) {
	t.Helper()
	databaseDN := "olcDatabase={1}meta,cn=config"
	broadURIs := providerOne + "/" + openLDAPMetaBaseDN
	if deadURI != "" {
		broadURIs = deadURI + "/" + openLDAPMetaBaseDN + " " + providerOne + "/"
	}
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
			},
		},
		{
			DN: "olcDatabase={0}config,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{0}config")},
				{Description: "olcRootDN", Values: stringValues("cn=config")},
				{Description: "olcRootPW", Values: stringValues("config-secret")},
			},
		},
		{
			DN: databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcMetaConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}meta")},
				{Description: "olcSuffix", Values: stringValues(openLDAPMetaBaseDN)},
				{Description: "olcRootDN", Values: stringValues("cn=admin," + openLDAPMetaBaseDN)},
				{Description: "olcRootPW", Values: stringValues("secret")},
				{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
				{Description: "olcDbNretries", Values: stringValues("1")},
			},
		},
		{
			DN: "olcMetaSub={0}uri," + databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcMetaTargetConfig")},
				{Description: "olcMetaSub", Values: stringValues("{0}uri")},
				{Description: "olcDbURI", Values: stringValues(broadURIs)},
				{Description: "olcDbRewrite", Values: stringValues(
					"suffixmassage \"" + openLDAPMetaBaseDN + "\" \"dc=example,dc=com\"",
				)},
				{Description: "olcDbIDAssertBind", Values: stringValues(
					`bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none`,
				)},
				{Description: "olcDbIDAssertAuthzFrom", Values: stringValues("*")},
			},
		},
		{
			DN: "olcMetaSub={1}uri," + databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcMetaTargetConfig")},
				{Description: "olcMetaSub", Values: stringValues("{1}uri")},
				{Description: "olcDbURI", Values: stringValues(
					providerTwo + "/" + openLDAPMetaSpecificBase,
				)},
				{Description: "olcDbRewrite", Values: stringValues(
					"suffixmassage \"" + openLDAPMetaSpecificBase + "\" \"ou=people,dc=example,dc=com\"",
				)},
				{Description: "olcDbIDAssertBind", Values: stringValues(
					`bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none`,
				)},
				{Description: "olcDbIDAssertAuthzFrom", Values: stringValues("*")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{openLDAPMetaBaseDN, "cn=config"})
	}); err != nil {
		t.Fatalf("seed ldap-go back-meta configuration: %v", err)
	}
}
