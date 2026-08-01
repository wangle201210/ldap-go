package server

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceValueSortOverlay(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{valueSortReferenceOverlayConfiguration()},
		valueSortReferenceSchema(),
		"",
		"",
	)
	defer stopOpenLDAP()
	openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
	defer openLDAP.Close()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{
		Schema:       valueSortTestRegistry(t),
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
	overlay := ldap.NewAddRequest(testValueSortOverlayDN, nil)
	overlay.Attribute(
		"objectClass",
		[]string{"olcOverlayConfig", "olcValSortConfig"},
	)
	overlay.Attribute("olcOverlay", []string{"{0}valsort"})
	overlay.Attribute("olcValSortAttr", valueSortConfigurationValues(false))
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(ldap-go valsort overlay): %v", err)
	}

	openLDAPOutcome := runValueSortReferenceScenario(t, openLDAP)
	ldapGoOutcome := runValueSortReferenceScenario(t, ldapGo)
	assertOverlayReferenceOutcome(
		t,
		"valsort",
		openLDAPOutcome,
		ldapGoOutcome,
		[]uint16{
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultConstraintViolation,
			ldap.LDAPResultConstraintViolation,
			ldap.LDAPResultSuccess,
		},
	)
}

func TestOpenLDAPSlapcatValueSortConfigImport(t *testing.T) {
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
	customSchemaPath := filepath.Join(root, "valsort.schema")
	if err := os.WriteFile(
		customSchemaPath,
		[]byte(valueSortReferenceSchema()),
		0o600,
	); err != nil {
		t.Fatalf("write valsort schema: %v", err)
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
overlay valsort
valsort-attr plainLabel "ou=people,dc=example,dc=com" alpha-ascend
valsort-attr score "ou=people,dc=example,dc=com" numeric-descend
valsort-attr rankedLabel "ou=people,dc=example,dc=com" weighted alpha-ascend
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

dn: ou=people,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people

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
		[]byte("olcValSortConfig"),
		[]byte("olcValSortAttr:"),
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
		t.Fatalf("ImportLDIF(real slapcat valsort config): %v\n%s", err, exported)
	}
	address, stop := startServer(t, store, Config{
		Schema:       valueSortTestRegistry(t),
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
	if err := client.Add(valueSortPersonAdd("valsort-slapcat", true)); err != nil {
		t.Fatalf("Add(after valsort slapcat import): %v", err)
	}
	got := orderedValueSortSignature(
		t,
		client,
		"uid=valsort-slapcat,ou=people,dc=example,dc=com",
		nil,
	)
	want := "plainLabel=alpha|Beta|Zebra;score=10|2|-1;" +
		"rankedLabel=alpha|Zulu|Beta"
	if got != want {
		t.Fatalf("valsort after slapcat import = %q, want %q", got, want)
	}
}

func runValueSortReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
) overlayReferenceOutcome {
	t.Helper()

	const dn = "uid=valsort-reference,ou=people,dc=example,dc=com"
	var outcome overlayReferenceOutcome
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(
			t,
			client.Add(valueSortPersonAdd("valsort-reference", true)),
		),
	)
	outcome.states = append(
		outcome.states,
		orderedValueSortSignature(t, client, dn, nil),
		orderedValueSortSignature(
			t,
			client,
			dn,
			[]ldap.Control{valueSortControl(true)},
		),
		fmt.Sprintf("hidden-control-advertised=%t", valueSortControlAdvertised(t, client)),
	)
	singleDN := "uid=valsort-reference-single,ou=people,dc=example,dc=com"
	single := valueSortPersonAdd("valsort-reference-single", true)
	single.Attributes = replaceLDAPAddAttribute(
		single.Attributes,
		"rankedLabel",
		[]string{"{7}only"},
	)
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Add(single)),
	)
	outcome.states = append(
		outcome.states,
		orderedValueSortSignature(t, client, singleDN, nil),
	)

	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(
			t,
			client.Add(valueSortPersonAdd("valsort-reference-bad", false)),
		),
	)
	badModify := ldap.NewModifyRequest(dn, nil)
	badModify.Add("rankedLabel", []string{"missing-weight"})
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Modify(badModify)),
	)
	validModify := ldap.NewModifyRequest(dn, nil)
	validModify.Replace(
		"rankedLabel",
		[]string{"{3}gamma", "{1}delta", "{1}Beta"},
	)
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Modify(validModify)),
	)
	outcome.states = append(
		outcome.states,
		orderedValueSortSignature(t, client, dn, nil),
		orderedValueSortSignature(
			t,
			client,
			dn,
			[]ldap.Control{valueSortControl(true)},
		),
	)
	return outcome
}

func replaceLDAPAddAttribute(
	attributes []ldap.Attribute,
	description string,
	values []string,
) []ldap.Attribute {
	for index := range attributes {
		if strings.EqualFold(attributes[index].Type, description) {
			attributes[index].Vals = values
			return attributes
		}
	}
	return attributes
}

func orderedValueSortSignature(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	controls []ldap.Control,
) string {
	t.Helper()
	attributes := []string{"plainLabel", "score", "rankedLabel"}
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		attributes,
		controls,
	))
	if err != nil {
		t.Fatalf("Search(%s): %v", dn, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search(%s) returned %d entries", dn, len(result.Entries))
	}
	parts := make([]string, 0, len(attributes))
	for _, attribute := range attributes {
		parts = append(
			parts,
			attribute+"="+strings.Join(
				result.Entries[0].GetAttributeValues(attribute),
				"|",
			),
		)
	}
	return strings.Join(parts, ";")
}

func valueSortControlAdvertised(t *testing.T, client *ldap.Conn) bool {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedControl"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("Root DSE Search() = %#v, %v", result, err)
	}
	return containsString(
		result.Entries[0].GetAttributeValues("supportedControl"),
		valueSortControlOID,
	)
}

func valueSortReferenceOverlayConfiguration() string {
	return "valsort\n" +
		"valsort-attr plainLabel \"ou=people,dc=example,dc=com\" alpha-ascend\n" +
		"valsort-attr score \"ou=people,dc=example,dc=com\" numeric-descend\n" +
		"valsort-attr rankedLabel \"ou=people,dc=example,dc=com\" weighted alpha-ascend"
}

func valueSortReferenceSchema() string {
	return `
attributetype ( 1.3.6.1.4.1.99999.10.1 NAME 'rankedLabel'
	EQUALITY caseIgnoreMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 1.3.6.1.4.1.99999.10.2 NAME 'score'
	EQUALITY integerMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
attributetype ( 1.3.6.1.4.1.99999.10.3 NAME 'singleRank'
	EQUALITY caseIgnoreMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.99999.10.4 NAME 'plainLabel'
	EQUALITY caseIgnoreMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
objectclass ( 1.3.6.1.4.1.99999.10.10 NAME 'valueSortData'
	SUP top AUXILIARY
	MAY ( rankedLabel $ score $ singleRank $ plainLabel ) )
`
}
