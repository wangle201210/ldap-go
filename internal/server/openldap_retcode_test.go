package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceRetcodeOverlay(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{retcodeReferenceOverlayConfiguration()},
		"",
		retcodeReferenceACLConfiguration(),
		"",
	)
	defer stopOpenLDAP()
	openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
	defer openLDAP.Close()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stopLDAPGo()
	ldapGo := bindConstraintClient(
		t,
		ldapGoAddress,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer ldapGo.Close()
	configClient := bindConstraintClient(t, ldapGoAddress, "cn=config", "config-secret")
	defer configClient.Close()
	overlay := ldap.NewAddRequest(testRetcodeOverlayDN, nil)
	overlay.Attribute(
		"objectClass",
		[]string{"olcOverlayConfig", "olcRetcodeConfig"},
	)
	overlay.Attribute("olcOverlay", []string{"{0}retcode"})
	overlay.Attribute(
		"olcRetcodeParent",
		[]string{"ou=RetCodes,dc=example,dc=com"},
	)
	overlay.Attribute("olcRetcodeItem", retcodeLifecycleItems(3))
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(ldap-go retcode overlay): %v", err)
	}
	access := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	access.Replace("olcAccess", []string{
		`{0}to attrs=errCode by dn.exact="cn=admin,dc=example,dc=com" read by * none`,
		`{1}to * by * read`,
	})
	if err := configClient.Modify(access); err != nil {
		t.Fatalf("Modify(ldap-go retcode ACL): %v", err)
	}

	openLDAPOutcome := runRetcodeReferenceScenario(t, openLDAP, "secret")
	ldapGoOutcome := runRetcodeReferenceScenario(t, ldapGo, "admin-secret")
	assertOverlayReferenceOutcome(
		t,
		"retcode",
		openLDAPOutcome,
		ldapGoOutcome,
		[]uint16{
			ldap.LDAPResultTimeLimitExceeded,
			ldap.LDAPResultUnwillingToPerform,
			ldap.LDAPResultUnwillingToPerform,
			ldap.LDAPResultCompareTrue,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultNoSuchObject,
			ldap.LDAPResultNoSuchObject,
			ldap.LDAPResultNoSuchObject,
			ldap.LDAPResultReferral,
			ldap.LDAPResultNoSuchObject,
			ldap.LDAPResultNamingViolation,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultInvalidCredentials,
		},
	)
	openLDAPAnonymous, err := ldap.DialURL(openLDAPURI)
	if err != nil {
		t.Fatalf("DialURL(OpenLDAP anonymous): %v", err)
	}
	defer openLDAPAnonymous.Close()
	ldapGoAnonymous, err := ldap.DialURL("ldap://" + ldapGoAddress)
	if err != nil {
		t.Fatalf("DialURL(ldap-go anonymous): %v", err)
	}
	defer ldapGoAnonymous.Close()
	openLDAPACLState := retcodeReferenceACLState(
		t,
		openLDAPAnonymous,
		openLDAP,
	)
	ldapGoACLState := retcodeReferenceACLState(t, ldapGoAnonymous, ldapGo)
	const wantACLState = "all=Bind Denied:,Bind Success:,Compare True:,Extended:," +
		"Referral:,Rename:,Search Only:,Success:,Time Limit:,Unwilling:;" +
		"anonymous-filter=0;root-filter=Time Limit:3"
	if openLDAPACLState != wantACLState || ldapGoACLState != openLDAPACLState {
		t.Fatalf(
			"retcode ACL state: OpenLDAP=%q ldap-go=%q want=%q",
			openLDAPACLState,
			ldapGoACLState,
			wantACLState,
		)
	}
}

func TestOpenLDAPReferenceRetcodeInDirectory(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{`retcode
retcode-parent "ou=RetCodes,dc=example,dc=com"
retcode-indir on`},
		"",
		"",
		retcodeInDirectoryReferenceData(),
	)
	defer stopOpenLDAP()
	openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
	defer openLDAP.Close()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stopLDAPGo()
	ldapGo := bindConstraintClient(
		t,
		ldapGoAddress,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer ldapGo.Close()
	configClient := bindConstraintClient(t, ldapGoAddress, "cn=config", "config-secret")
	defer configClient.Close()
	overlay := ldap.NewAddRequest(testRetcodeOverlayDN, nil)
	overlay.Attribute(
		"objectClass",
		[]string{"olcOverlayConfig", "olcRetcodeConfig"},
	)
	overlay.Attribute("olcOverlay", []string{"{0}retcode"})
	overlay.Attribute(
		"olcRetcodeParent",
		[]string{"ou=RetCodes,dc=example,dc=com"},
	)
	overlay.Attribute("olcRetcodeInDir", []string{"TRUE"})
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(ldap-go in-directory retcode overlay): %v", err)
	}
	for _, add := range retcodeInDirectoryReferenceAdds() {
		if strings.EqualFold(
			add.DN,
			"cn=Normalized Error,ou=people,dc=example,dc=com",
		) {
			// OpenLDAP's fixture reaches storage through slapadd's default
			// value-check=no path. Seed the same noncanonical INTEGER without
			// weakening online LDAP Add validation.
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				entry := directory.Entry{DN: add.DN}
				for _, attribute := range add.Attributes {
					entry.Attributes = append(entry.Attributes, directory.Attribute{
						Description: attribute.Type,
						Values:      stringValues(attribute.Vals...),
					})
				}
				return writer.PutIn(configuredDatabasePartition("{1}mdb"), entry, false)
			}); err != nil {
				t.Fatalf("seed noncanonical ldap-go retcode entry %s: %v", add.DN, err)
			}
			continue
		}
		if err := ldapGo.Add(add); err != nil {
			t.Fatalf("seed ldap-go in-directory retcode entry %s: %v", add.DN, err)
		}
	}

	openLDAPOutcome := runRetcodeInDirectoryReferenceScenario(
		t,
		openLDAP,
		"secret",
	)
	ldapGoOutcome := runRetcodeInDirectoryReferenceScenario(
		t,
		ldapGo,
		"admin-secret",
	)
	assertOverlayReferenceOutcome(
		t,
		"retcode in-directory",
		openLDAPOutcome,
		ldapGoOutcome,
		[]uint16{
			ldap.LDAPResultUnwillingToPerform,
			43,
			ldap.LDAPResultReferral,
			ldap.LDAPResultUnwillingToPerform,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultUnwillingToPerform,
			ldap.LDAPResultCompareTrue,
			ldap.LDAPResultNamingViolation,
			ldap.LDAPResultUnwillingToPerform,
			ldap.LDAPResultUnwillingToPerform,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultInvalidCredentials,
		},
	)
	const extendedDN = "cn=Extended Error Directory,ou=people,dc=example,dc=com"
	_, openLDAPExtendedErr := openLDAP.PasswordModify(ldap.NewPasswordModifyRequest(
		extendedDN,
		"",
		"replacement",
	))
	_, ldapGoExtendedErr := ldapGo.PasswordModify(ldap.NewPasswordModifyRequest(
		extendedDN,
		"",
		"replacement",
	))
	if openLDAPCode := overlayLDAPResultCode(t, openLDAPExtendedErr); openLDAPCode != ldap.ErrorUnexpectedResponse {
		t.Fatalf("OpenLDAP in-directory extended result = %d, want client unexpected response", openLDAPCode)
	}
	if ldapGoCode := overlayLDAPResultCode(t, ldapGoExtendedErr); ldapGoCode != ldap.LDAPResultUnwillingToPerform {
		t.Fatalf("ldap-go in-directory extended result = %d, want unwillingToPerform", ldapGoCode)
	}
}

func TestOpenLDAPSlapcatRetcodeConfigImport(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	slaptest := findOpenLDAPSchemaTool(
		t,
		"slaptest",
		"/opt/homebrew/opt/openldap/sbin/slaptest",
		"/usr/sbin/slaptest",
	)
	slapcat := findOpenLDAPSchemaTool(
		t,
		"slapcat",
		"/opt/homebrew/opt/openldap/sbin/slapcat",
		"/usr/sbin/slapcat",
	)

	root := t.TempDir()
	configDir := filepath.Join(root, "slapd.d")
	databaseDir := filepath.Join(root, "db")
	for _, path := range []string{configDir, databaseDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("Mkdir(%s): %v", path, err)
		}
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
rootpw secret
directory %s
overlay retcode
retcode-parent "ou=RetCodes,dc=example,dc=com"
retcode-item "cn=Imported" 53 op=search text="imported retcode"
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		filepath.Join(root, "slapd.pid"),
		filepath.Join(root, "slapd.args"),
		databaseDir,
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write slapd.conf: %v", err)
	}
	dataPath := filepath.Join(root, "data.ldif")
	data := `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

`
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		t.Fatalf("write OpenLDAP seed data: %v", err)
	}
	command := exec.Command(tools.slapadd, "-q", "-f", configPath, "-l", dataPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("slapadd failed: %v\n%s", err, output)
	}
	command = exec.Command(slaptest, "-f", configPath, "-F", configDir)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("slaptest failed: %v\n%s", err, output)
	}

	var stderr bytes.Buffer
	command = exec.Command(
		slapcat,
		"-F",
		configDir,
		"-n",
		"0",
		"-a",
		"(olcOverlay=*)",
	)
	command.Stderr = &stderr
	exported, err := command.Output()
	if err != nil {
		t.Fatalf("slapcat -n 0 failed: %v\n%s", err, stderr.Bytes())
	}
	for _, expected := range [][]byte{
		[]byte("olcRetcodeConfig"),
		[]byte("olcRetcodeParent:"),
		[]byte("olcRetcodeItem:"),
	} {
		if !bytes.Contains(exported, expected) {
			t.Fatalf("slapcat output is missing %q:\n%s", expected, exported)
		}
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		bytes.NewReader(exported),
		migration.ImportOptions{},
	); err != nil {
		t.Fatalf("ImportLDIF(real slapcat retcode config): %v\n%s", err, exported)
	}
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer client.Close()
	assertRetcodeSearchResult(
		t,
		client,
		"cn=Imported,ou=RetCodes,dc=example,dc=com",
		ldap.LDAPResultUnwillingToPerform,
		"",
		"imported retcode",
	)
}

func runRetcodeReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
	rootPassword string,
) overlayReferenceOutcome {
	t.Helper()

	var outcome overlayReferenceOutcome
	code, state := retcodeReferenceSearch(
		t,
		client,
		"cn=Time Limit,ou=RetCodes,dc=example,dc=com",
		ldap.ScopeBaseObject,
	)
	outcome.codes = append(outcome.codes, code)
	outcome.states = append(outcome.states, state)

	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Del(ldap.NewDelRequest(
			"cn=Unwilling,ou=RetCodes,dc=example,dc=com",
			nil,
		))),
	)
	modify := ldap.NewModifyRequest(
		"cn=Unwilling,ou=RetCodes,dc=example,dc=com",
		nil,
	)
	modify.Replace("description", []string{"ignored"})
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Modify(modify)),
		overlayCompareResultCode(
			t,
			client,
			"cn=Compare True,ou=RetCodes,dc=example,dc=com",
			"cn",
			"anything",
		),
	)
	add := ldap.NewAddRequest(
		"cn=Success,ou=RetCodes,dc=example,dc=com",
		nil,
	)
	add.Attribute("objectClass", []string{"organizationalRole"})
	add.Attribute("cn", []string{"Success"})
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Add(add)),
		overlayLDAPResultCode(t, client.Del(ldap.NewDelRequest(
			"cn=Search Only,ou=RetCodes,dc=example,dc=com",
			nil,
		))),
	)
	code, state = retcodeReferenceSearch(
		t,
		client,
		"cn=Missing,ou=RetCodes,dc=example,dc=com",
		ldap.ScopeBaseObject,
	)
	outcome.codes = append(outcome.codes, code)
	outcome.states = append(outcome.states, state)
	code, state = retcodeReferenceSearch(
		t,
		client,
		"ou=RetCodes,dc=example,dc=com",
		ldap.ScopeBaseObject,
	)
	outcome.codes = append(outcome.codes, code)
	outcome.states = append(outcome.states, state)
	outcome.states = append(outcome.states, retcodeReferenceList(t, client))
	code, state = retcodeReferenceSearch(
		t,
		client,
		"cn=Referral,ou=RetCodes,dc=example,dc=com",
		ldap.ScopeBaseObject,
	)
	outcome.codes = append(outcome.codes, code)
	outcome.states = append(outcome.states, state)
	_, err := client.PasswordModify(ldap.NewPasswordModifyRequest(
		"cn=Extended,ou=RetCodes,dc=example,dc=com",
		"",
		"replacement",
	))
	outcome.codes = append(outcome.codes, overlayLDAPResultCode(t, err))
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.ModifyDN(ldap.NewModifyDNRequest(
			"cn=Rename,ou=RetCodes,dc=example,dc=com",
			"cn=Renamed",
			true,
			"",
		))),
		overlayLDAPResultCode(t, client.Bind(
			"cn=Bind Success,ou=RetCodes,dc=example,dc=com",
			"irrelevant",
		)),
	)
	identity, err := client.WhoAmI(nil)
	if err != nil {
		t.Fatalf("WhoAmI after successful retcode Bind: %v", err)
	}
	outcome.states = append(outcome.states, identity.AuthzID)
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Bind(
			"cn=Bind Denied,ou=RetCodes,dc=example,dc=com",
			"irrelevant",
		)),
	)
	if err := client.Bind("cn=admin,dc=example,dc=com", rootPassword); err != nil {
		t.Fatalf("rebind after retcode Bind: %v", err)
	}
	return outcome
}

func runRetcodeInDirectoryReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
	rootPassword string,
) overlayReferenceOutcome {
	t.Helper()

	const (
		searchDN     = "cn=Search Error,ou=people,dc=example,dc=com"
		normalizedDN = "cn=Normalized Error,ou=people,dc=example,dc=com"
		referralDN   = "cn=Referral Directory,ou=people,dc=example,dc=com"
		modifyDN     = "cn=Modify Error,ou=people,dc=example,dc=com"
		compareDN    = "cn=Compare True Directory,ou=people,dc=example,dc=com"
		renameDN     = "cn=Rename Error Directory,ou=people,dc=example,dc=com"
		deleteDN     = "cn=Delete Error,ou=people,dc=example,dc=com"
		bindDN       = "cn=Bind Error Directory,ou=people,dc=example,dc=com"
	)
	var outcome overlayReferenceOutcome
	code, state := retcodeReferenceSearch(t, client, searchDN, ldap.ScopeBaseObject)
	outcome.codes = append(outcome.codes, code)
	outcome.states = append(outcome.states, state)
	code, state = retcodeReferenceSearch(t, client, normalizedDN, ldap.ScopeBaseObject)
	outcome.codes = append(outcome.codes, code)
	outcome.states = append(outcome.states, state)
	code, state = retcodeReferenceSearch(t, client, referralDN, ldap.ScopeBaseObject)
	outcome.codes = append(outcome.codes, code)
	outcome.states = append(outcome.states, state)

	_, err := client.Search(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(cn=Search Error)",
		[]string{"cn"},
		nil,
	))
	outcome.codes = append(outcome.codes, overlayLDAPResultCode(t, err))

	managed, err := client.Search(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(cn=Search Error)",
		[]string{"cn", "errCode"},
		[]ldap.Control{ldap.NewControlManageDsaIT(true)},
	))
	outcome.codes = append(outcome.codes, overlayLDAPResultCode(t, err))
	managedState := ""
	if err == nil && len(managed.Entries) == 1 {
		managedState = managed.Entries[0].GetAttributeValue("cn") + ":" +
			managed.Entries[0].GetAttributeValue("errCode")
	}
	outcome.states = append(outcome.states, managedState)

	modify := ldap.NewModifyRequest(modifyDN, nil)
	modify.Replace("description", []string{"blocked"})
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Modify(modify)),
		overlayCompareResultCode(t, client, compareDN, "cn", "not-present"),
		overlayLDAPResultCode(t, client.ModifyDN(ldap.NewModifyDNRequest(
			renameDN,
			"cn=Renamed Directory",
			true,
			"",
		))),
		overlayLDAPResultCode(t, client.Del(ldap.NewDelRequest(deleteDN, nil))),
	)

	addError := retcodeDirectoryAdd(
		"cn=Incoming Add Error,ou=people,dc=example,dc=com",
		53,
		"add",
		nil,
	)
	addSuccessDN := "cn=Incoming Add Success,ou=people,dc=example,dc=com"
	addSuccess := retcodeDirectoryAdd(addSuccessDN, 0, "add", nil)
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Add(addError)),
		overlayLDAPResultCode(t, client.Add(addSuccess)),
	)
	code, state = retcodeReferenceSearch(t, client, addSuccessDN, ldap.ScopeBaseObject)
	outcome.codes = append(outcome.codes, code)
	outcome.states = append(outcome.states, state)
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Bind(bindDN, "irrelevant")),
	)
	if err := client.Bind("cn=admin,dc=example,dc=com", rootPassword); err != nil {
		t.Fatalf("rebind after in-directory retcode Bind: %v", err)
	}
	return outcome
}

func retcodeInDirectoryReferenceAdds() []*ldap.AddRequest {
	manage := []ldap.Control{ldap.NewControlManageDsaIT(true)}
	definitions := []struct {
		dn        string
		code      int
		operation string
		text      string
		matched   string
	}{
		{
			"cn=Search Error,ou=people,dc=example,dc=com",
			53,
			"search",
			"directory search rejected",
			"ou=people,dc=example,dc=com",
		},
		{"cn=Referral Directory,ou=people,dc=example,dc=com", 10, "search", "", ""},
		{"cn=Modify Error,ou=people,dc=example,dc=com", 53, "modify", "", ""},
		{"cn=Compare True Directory,ou=people,dc=example,dc=com", 6, "compare", "", ""},
		{"cn=Rename Error Directory,ou=people,dc=example,dc=com", 64, "modrdn", "", ""},
		{"cn=Delete Error,ou=people,dc=example,dc=com", 53, "delete", "", ""},
		{"cn=Bind Error Directory,ou=people,dc=example,dc=com", 49, "bind", "", ""},
		{"cn=Extended Error Directory,ou=people,dc=example,dc=com", 53, "extended", "", ""},
	}
	adds := make([]*ldap.AddRequest, 0, len(definitions))
	for _, definition := range definitions {
		add := retcodeDirectoryAdd(
			definition.dn,
			definition.code,
			definition.operation,
			manage,
		)
		if definition.text != "" {
			add.Attribute("errText", []string{definition.text})
		}
		if definition.matched != "" {
			add.Attribute("errMatchedDN", []string{definition.matched})
		}
		if definition.code == int(ldap.LDAPResultReferral) {
			for index := range add.Attributes {
				if strings.EqualFold(add.Attributes[index].Type, "objectClass") {
					add.Attributes[index].Vals = []string{
						"referral",
						"errAuxObject",
					}
					break
				}
			}
			add.Attribute("ref", []string{"ldap://remote.example"})
		}
		adds = append(adds, add)
	}
	normalized := retcodeDirectoryAdd(
		"cn=Normalized Error,ou=people,dc=example,dc=com",
		53,
		"search",
		manage,
	)
	for index := range normalized.Attributes {
		switch {
		case strings.EqualFold(normalized.Attributes[index].Type, "errCode"):
			normalized.Attributes[index].Vals = []string{"053"}
		case strings.EqualFold(normalized.Attributes[index].Type, "errOp"):
			normalized.Attributes[index].Vals = []string{"SeArCh"}
		}
	}
	adds = append(adds, normalized)
	return adds
}

func retcodeInDirectoryReferenceData() string {
	return `
dn: cn=Search Error,ou=people,dc=example,dc=com
objectClass: errObject
cn: Search Error
errCode: 53
errOp: search
errText: directory search rejected
errMatchedDN: ou=people,dc=example,dc=com

dn: cn=Normalized Error,ou=people,dc=example,dc=com
objectClass: errObject
cn: Normalized Error
errCode: 053
errOp: SeArCh

dn: cn=Referral Directory,ou=people,dc=example,dc=com
objectClass: referral
objectClass: errAuxObject
cn: Referral Directory
errCode: 10
errOp: search
ref: ldap://remote.example

dn: cn=Modify Error,ou=people,dc=example,dc=com
objectClass: errObject
cn: Modify Error
errCode: 53
errOp: modify

dn: cn=Compare True Directory,ou=people,dc=example,dc=com
objectClass: errObject
cn: Compare True Directory
errCode: 6
errOp: compare

dn: cn=Rename Error Directory,ou=people,dc=example,dc=com
objectClass: errObject
cn: Rename Error Directory
errCode: 64
errOp: modrdn

dn: cn=Delete Error,ou=people,dc=example,dc=com
objectClass: errObject
cn: Delete Error
errCode: 53
errOp: delete

dn: cn=Bind Error Directory,ou=people,dc=example,dc=com
objectClass: errObject
cn: Bind Error Directory
errCode: 49
errOp: bind

dn: cn=Extended Error Directory,ou=people,dc=example,dc=com
objectClass: errObject
cn: Extended Error Directory
errCode: 53
errOp: extended
`
}

func retcodeReferenceSearch(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	scope int,
) (uint16, string) {
	t.Helper()
	_, err := client.Search(ldap.NewSearchRequest(
		dn,
		scope,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"*"},
		nil,
	))
	if err == nil {
		return ldap.LDAPResultSuccess, "success"
	}
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		t.Fatalf("Search(%s) returned non-LDAP error: %v", dn, err)
	}
	diagnostic := ""
	if ldapErr.Packet != nil && len(ldapErr.Packet.Children) >= 2 &&
		len(ldapErr.Packet.Children[1].Children) >= 3 {
		diagnostic = ldapErr.Packet.Children[1].Children[2].Data.String()
	}
	referrals := ldapResultReferrals(ldapErr.Packet)
	return ldapErr.ResultCode, fmt.Sprintf(
		"matched=%s;diagnostic=%s;referrals=%s",
		ldapErr.MatchedDN,
		diagnostic,
		strings.Join(referrals, "|"),
	)
}

func retcodeReferenceList(t *testing.T, client *ldap.Conn) string {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"ou=RetCodes,dc=example,dc=com",
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=errObject)(errOp=search))",
		[]string{"cn", "errCode", "errOp"},
		nil,
	))
	if err != nil {
		t.Fatalf("retcode list Search(): %v", err)
	}
	entries := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		operations := entry.GetAttributeValues("errOp")
		sort.Strings(operations)
		entries = append(entries, fmt.Sprintf(
			"%s:%s:%s",
			entry.GetAttributeValue("cn"),
			entry.GetAttributeValue("errCode"),
			strings.Join(operations, ","),
		))
	}
	sort.Strings(entries)
	return strings.Join(entries, "|")
}

func retcodeReferenceACLState(
	t *testing.T,
	anonymous,
	root *ldap.Conn,
) string {
	t.Helper()
	search := func(client *ldap.Conn, filter string) []*ldap.Entry {
		t.Helper()
		result, err := client.Search(ldap.NewSearchRequest(
			"ou=RetCodes,dc=example,dc=com",
			ldap.ScopeSingleLevel,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			filter,
			[]string{"cn", "errCode"},
			nil,
		))
		if err != nil {
			t.Fatalf("retcode ACL Search(%s): %v", filter, err)
		}
		return result.Entries
	}
	format := func(entries []*ldap.Entry) string {
		values := make([]string, 0, len(entries))
		for _, entry := range entries {
			values = append(values, entry.GetAttributeValue("cn")+":"+
				entry.GetAttributeValue("errCode"))
		}
		sort.Strings(values)
		return strings.Join(values, ",")
	}
	all := format(search(anonymous, "(objectClass=errObject)"))
	anonymousFiltered := search(anonymous, "(errCode=3)")
	rootFiltered := format(search(root, "(errCode=3)"))
	return fmt.Sprintf(
		"all=%s;anonymous-filter=%d;root-filter=%s",
		all,
		len(anonymousFiltered),
		rootFiltered,
	)
}

func retcodeReferenceACLConfiguration() string {
	return `access to attrs=errCode
    by dn.exact="cn=admin,dc=example,dc=com" read
    by * none
access to *
    by * read`
}

func retcodeReferenceOverlayConfiguration() string {
	return `retcode
retcode-parent "ou=RetCodes,dc=example,dc=com"
retcode-item "cn=Time Limit" 3 op=search text="search delayed" matched="dc=example,dc=com"
retcode-item "cn=Unwilling" 53 op=delete,modify
retcode-item "cn=Compare True" 6 op=compare
retcode-item "cn=Success" 0 op=add
retcode-item "cn=Search Only" 4 op=search
retcode-item "cn=Referral" 10 op=search ref="ldap://remote.example"
retcode-item "cn=Bind Denied" 49 op=bind text="denied"
retcode-item "cn=Bind Success" 0 op=bind
retcode-item "cn=Rename" 64 op=rename
retcode-item "cn=Extended" 53 op=extended`
}
