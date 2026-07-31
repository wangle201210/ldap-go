package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type contentRuleDifferentialResult struct {
	Code       uint16
	Diagnostic string
}

func TestOpenLDAPReferenceDITContentRules(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	globalConfig := `
attributetype ( 1.3.6.1.4.1.99999.10 NAME 'applicationCode'
	EQUALITY caseIgnoreMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 1.3.6.1.4.1.99999.11 NAME 'applicationLabel'
	EQUALITY caseIgnoreMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
objectclass ( 1.3.6.1.4.1.99999.12 NAME 'applicationAux'
	SUP top AUXILIARY MUST applicationCode )
objectclass ( 1.3.6.1.4.1.99999.13 NAME 'unlistedAux'
	SUP top AUXILIARY )
ditcontentrule ( 2.16.840.1.113730.3.2.2
	NAME 'applicationPersonRule'
	AUX applicationAux
	MUST uid
	MAY applicationLabel
	NOT description )
`
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		globalConfig,
		"",
		"",
	)
	defer stopOpenLDAP()
	openLDAPResult := exerciseDITContentRuleServer(
		t,
		openLDAPURI,
		"cn=admin,dc=example,dc=com",
		"secret",
	)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(
			ldapAddRequestEntry(testContentRuleSchemaRequest(
				"{0}( "+testContentRuleOID+
					" NAME 'applicationPersonRule' "+
					"AUX applicationAux MUST uid "+
					"MAY applicationLabel NOT description )",
			)),
			false,
		)
	}); err != nil {
		t.Fatalf("seed ldap-go content-rule schema: %v", err)
	}
	address, stopLDAPGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stopLDAPGo()
	ldapGoResult := exerciseDITContentRuleServer(
		t,
		"ldap://"+address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)

	if !reflect.DeepEqual(ldapGoResult, openLDAPResult) {
		t.Fatalf(
			"DIT content-rule differential mismatch:\nOpenLDAP: %#v\nldap-go: %#v",
			openLDAPResult,
			ldapGoResult,
		)
	}
}

func TestOpenLDAPSlapcatDITContentRuleImport(t *testing.T) {
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
	customSchemaPath := filepath.Join(root, "content-rule.schema")
	customSchema := `
attributetype ( 1.3.6.1.4.1.99999.10 NAME 'applicationCode'
	EQUALITY caseIgnoreMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 1.3.6.1.4.1.99999.11 NAME 'applicationLabel'
	EQUALITY caseIgnoreMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
objectclass ( 1.3.6.1.4.1.99999.12 NAME 'applicationAux'
	SUP top AUXILIARY MUST applicationCode )
ditcontentrule ( 2.16.840.1.113730.3.2.2
	NAME 'slapcatPersonRule'
	AUX applicationAux
	MUST uid
	MAY applicationLabel
	NOT description )
`
	if err := os.WriteFile(
		customSchemaPath,
		[]byte(customSchema),
		0o600,
	); err != nil {
		t.Fatalf("write custom OpenLDAP schema: %v", err)
	}
	configPath := filepath.Join(root, "slapd.conf")
	config := fmt.Sprintf(
		`include %s
include %s
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
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		customSchemaPath,
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
	command := exec.Command(
		tools.slapadd,
		"-q",
		"-f",
		configPath,
		"-l",
		dataPath,
	)
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
		"(olcDitContentRules=*)",
	)
	command.Stderr = &stderr
	exported, err := command.Output()
	if err != nil {
		t.Fatalf("slapcat -n 0 failed: %v\n%s", err, stderr.Bytes())
	}
	if !bytes.Contains(exported, []byte("olcDitContentRules:")) {
		t.Fatalf("slapcat output has no olcDitContentRules:\n%s", exported)
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
		t.Fatalf("ImportLDIF(real slapcat schema): %v\n%s", err, exported)
	}
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	configClient := bindContentRuleClient(
		t,
		address,
		"cn=config",
		"config-secret",
	)
	defer configClient.Close()
	assertPublishedContentRule(t, configClient, true, "slapcatPersonRule")

	dataClient := bindContentRuleClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer dataClient.Close()
	missingUID := ldap.NewAddRequest(
		"cn=slapcat-missing,ou=people,dc=example,dc=com",
		nil,
	)
	missingUID.Attribute("objectClass", []string{"inetOrgPerson"})
	missingUID.Attribute("cn", []string{"slapcat-missing"})
	missingUID.Attribute("sn", []string{"User"})
	assertLDAPResultCode(
		t,
		dataClient.Add(missingUID),
		ldap.LDAPResultObjectClassViolation,
	)
}

func findOpenLDAPSchemaTool(
	t *testing.T,
	name string,
	candidates ...string,
) string {
	t.Helper()
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	t.Skipf("OpenLDAP %s is not installed", name)
	return ""
}

func exerciseDITContentRuleServer(
	t *testing.T,
	uri,
	bindDN,
	password string,
) map[string]contentRuleDifferentialResult {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	if err := client.Bind(bindDN, password); err != nil {
		t.Fatalf("Bind(%s): %v", uri, err)
	}

	results := make(map[string]contentRuleDifferentialResult)
	record := func(name string, err error) {
		t.Helper()
		results[name] = contentRuleResult(t, err)
	}

	valid := newContentRulePersonAdd(
		"cn=differential-valid,ou=people,dc=example,dc=com",
		"differential-valid",
		"applicationAux",
	)
	valid.Attribute("applicationCode", []string{"portal"})
	valid.Attribute("applicationLabel", []string{"Portal"})
	record("valid add", client.Add(valid))

	missingRequired := ldap.NewAddRequest(
		"cn=differential-missing,ou=people,dc=example,dc=com",
		nil,
	)
	missingRequired.Attribute("objectClass", []string{"inetOrgPerson"})
	missingRequired.Attribute("cn", []string{"differential-missing"})
	missingRequired.Attribute("sn", []string{"User"})
	record("missing rule MUST", client.Add(missingRequired))

	precluded := newContentRulePersonAdd(
		"uid=differential-precluded,ou=people,dc=example,dc=com",
		"differential-precluded",
	)
	precluded.Attribute("description", []string{"blocked"})
	record("precluded attribute", client.Add(precluded))

	unlisted := newContentRulePersonAdd(
		"uid=differential-unlisted,ou=people,dc=example,dc=com",
		"differential-unlisted",
		"unlistedAux",
	)
	record("unlisted auxiliary", client.Add(unlisted))

	missingBeforeAuxiliary := ldap.NewAddRequest(
		"cn=differential-order-missing,ou=people,dc=example,dc=com",
		nil,
	)
	missingBeforeAuxiliary.Attribute(
		"objectClass",
		[]string{"inetOrgPerson", "unlistedAux"},
	)
	missingBeforeAuxiliary.Attribute("cn", []string{"differential-order-missing"})
	missingBeforeAuxiliary.Attribute("sn", []string{"User"})
	record("rule MUST before auxiliary", client.Add(missingBeforeAuxiliary))

	precludedBeforeAuxiliary := newContentRulePersonAdd(
		"uid=differential-order-not,ou=people,dc=example,dc=com",
		"differential-order-not",
		"unlistedAux",
	)
	precludedBeforeAuxiliary.Attribute("description", []string{"blocked"})
	record("rule NOT before auxiliary", client.Add(precludedBeforeAuxiliary))

	allowedByRule := newContentRulePersonAdd(
		"uid=differential-may,ou=people,dc=example,dc=com",
		"differential-may",
	)
	allowedByRule.Attribute("applicationLabel", []string{"Allowed"})
	record("rule MAY", client.Add(allowedByRule))

	notAllowed := newContentRulePersonAdd(
		"uid=differential-not-allowed,ou=people,dc=example,dc=com",
		"differential-not-allowed",
	)
	notAllowed.Attribute("applicationCode", []string{"orphan"})
	record("attribute outside rule", client.Add(notAllowed))

	modifyPrecluded := ldap.NewModifyRequest(valid.DN, nil)
	modifyPrecluded.Add("description", []string{"blocked"})
	record("modify precluded", client.Modify(modifyPrecluded))

	modifyRequired := ldap.NewModifyRequest(valid.DN, nil)
	modifyRequired.Delete("uid", nil)
	record("modify rule MUST", client.Modify(modifyRequired))

	subSchema, err := client.Search(ldap.NewSearchRequest(
		"cn=Subschema",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dITContentRules"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(cn=Subschema at %s): %v", uri, err)
	}
	published := false
	if len(subSchema.Entries) == 1 {
		for _, value := range subSchema.Entries[0].GetAttributeValues(
			"dITContentRules",
		) {
			if strings.Contains(value, "applicationPersonRule") {
				published = true
				break
			}
		}
	}
	if !published {
		t.Fatalf("server %s did not publish applicationPersonRule", uri)
	}
	return results
}

func contentRuleResult(
	t *testing.T,
	err error,
) contentRuleDifferentialResult {
	t.Helper()
	if err == nil {
		return contentRuleDifferentialResult{}
	}
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		t.Fatalf("LDAP operation returned non-LDAP error: %v", err)
	}
	return contentRuleDifferentialResult{
		Code:       uint16(ldapError.ResultCode),
		Diagnostic: fmt.Sprint(ldapError.Err),
	}
}
