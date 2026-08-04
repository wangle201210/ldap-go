package server

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPCollectVersion = "2.6.13"
	openLDAPCollectCommit  = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

	collectReferenceBroadTargetDN = "uid=collect-aaa,ou=people,dc=example,dc=com"
	collectReferenceNestedDN      = "uid=collect-zzz,ou=team,ou=people,dc=example,dc=com"
	collectReferenceProjectedDN   = "uid=collect-projected,ou=team,ou=people,dc=example,dc=com"
	collectReferenceReferralDN    = "ou=collect-ref,ou=team,ou=people,dc=example,dc=com"
)

type collectReferenceOutcome struct {
	descriptions       []string
	telephoneNumbers   []string
	localities         []string
	projectedFilterDNs []string
	compareCode        uint16
	cnOnlyProjected    bool
	typesOnlyPresent   bool
	typesOnlyValues    int
	paged              []string
	sortedDNs          []string
	sortedValues       [][]string
	managedReferral    []string
	unmanagedCode      uint16
}

type collectReferenceWriteOutcome struct {
	directCode       uint16
	directDiagnostic string
	multipleCode     uint16
	givenNameStored  bool
	descriptionSaved bool
	optionCode       uint16
	optionStored     bool
}

func TestOpenLDAPReferenceCollectOverlay(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	assertPinnedOpenLDAPCollectReference(t)

	t.Run("configuration grammar", func(t *testing.T) {
		assertOpenLDAPCollectConfigurationGrammar(t, tools)
	})

	t.Run("search controls and writes", func(t *testing.T) {
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{collectReferenceStaticOverlay(), "sssvlv"},
			collectReferenceGlobalConfig(tools),
			"",
			"",
		)
		defer stopOpenLDAP()
		openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAP.Close()
		addCollectReferenceFixtures(t, openLDAP)

		ldapGo, configClient, _, stopLDAPGo := startCollectReferenceLDAPGo(t, nil)
		defer stopLDAPGo()
		defer ldapGo.Close()
		defer configClient.Close()
		addCollectReferenceFixtures(t, ldapGo)

		openLDAPOutcome := runCollectReferenceScenario(t, openLDAP)
		ldapGoOutcome := runCollectReferenceScenario(t, ldapGo)
		if !reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
			t.Fatalf(
				"collect Search/control mismatch:\nOpenLDAP: %#v\nldap-go:  %#v",
				openLDAPOutcome,
				ldapGoOutcome,
			)
		}
		wantSort := []string{
			strings.ToLower(collectReferenceBroadTargetDN),
			strings.ToLower(collectReferenceNestedDN),
		}
		if !reflect.DeepEqual(openLDAPOutcome.sortedDNs, wantSort) {
			t.Fatalf(
				"collect response values affected sort = %q, want %q",
				openLDAPOutcome.sortedDNs,
				wantSort,
			)
		}
		if openLDAPOutcome.compareCode != ldap.LDAPResultNoSuchAttribute ||
			len(openLDAPOutcome.projectedFilterDNs) != 0 ||
			openLDAPOutcome.cnOnlyProjected ||
			!openLDAPOutcome.typesOnlyPresent ||
			openLDAPOutcome.typesOnlyValues != 0 ||
			openLDAPOutcome.unmanagedCode != ldap.LDAPResultReferral {
			t.Fatalf("collect response-only invariants = %#v", openLDAPOutcome)
		}

		openLDAPWrites := runOpenLDAPCollectWriteScenario(t, openLDAP)
		ldapGoWrites := runLDAPGoCollectWriteScenario(t, ldapGo)
		assertCollectWriteCompatibilityAndHardening(
			t,
			openLDAPWrites,
			ldapGoWrites,
		)
	})

	t.Run("ACL", func(t *testing.T) {
		aclRules := collectReferenceACLRules()
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{collectReferenceStaticOverlay()},
			collectReferenceGlobalConfig(tools),
			strings.Join(collectReferenceStaticACLRules(aclRules), "\n"),
			"",
		)
		defer stopOpenLDAP()
		openLDAPRoot := bindOverlayReferenceClient(t, openLDAPURI, "secret")
		defer openLDAPRoot.Close()
		addCollectReferenceFixtures(t, openLDAPRoot)
		addCollectReferenceReader(t, openLDAPRoot)
		openLDAPReader := bindOverlayReferenceClientWithDN(
			t,
			openLDAPURI,
			"uid=collect-reader,ou=people,dc=example,dc=com",
			"reader-secret",
		)
		defer openLDAPReader.Close()

		ldapGoRoot, configClient, ldapGoURI, stopLDAPGo := startCollectReferenceLDAPGo(
			t,
			aclRules,
		)
		defer stopLDAPGo()
		defer ldapGoRoot.Close()
		defer configClient.Close()
		addCollectReferenceFixtures(t, ldapGoRoot)
		addCollectReferenceReader(t, ldapGoRoot)
		ldapGoReader := bindOverlayReferenceClientWithDN(
			t,
			ldapGoURI,
			"uid=collect-reader,ou=people,dc=example,dc=com",
			"reader-secret",
		)
		defer ldapGoReader.Close()

		openLDAPValues, openLDAPHidden := runCollectReferenceACLScenario(
			t,
			openLDAPReader,
		)
		ldapGoValues, ldapGoHidden := runCollectReferenceACLScenario(t, ldapGoReader)
		if !reflect.DeepEqual(openLDAPValues, ldapGoValues) ||
			openLDAPHidden != ldapGoHidden {
			t.Fatalf(
				"collect ACL mismatch: OpenLDAP values=%q hidden=%d, ldap-go values=%q hidden=%d",
				openLDAPValues,
				openLDAPHidden,
				ldapGoValues,
				ldapGoHidden,
			)
		}
		if len(openLDAPValues) == 0 || openLDAPHidden != ldap.LDAPResultNoSuchObject {
			t.Fatalf(
				"collect ACL hard assertion values=%q hidden=%d",
				openLDAPValues,
				openLDAPHidden,
			)
		}
	})
}

func assertPinnedOpenLDAPCollectReference(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" {
		t.Fatal("collect differential test requires a verified OpenLDAP reference build")
	}
	if got := os.Getenv("OPENLDAP_ACTUAL_VERSION"); got != openLDAPCollectVersion {
		t.Fatalf("OpenLDAP reference version = %q, want %q", got, openLDAPCollectVersion)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPCollectCommit {
		t.Fatalf("OpenLDAP reference commit = %q, want %q", got, openLDAPCollectCommit)
	}
	source := os.Getenv("OPENLDAP_SOURCE")
	collectSource := filepath.Join(source, "servers", "slapd", "overlays", "collect.c")
	contents, err := os.ReadFile(collectSource)
	if err != nil {
		t.Fatalf("read pinned collect.c: %v", err)
	}
	for _, expected := range []string{
		"collectinfo",
		"backend_attribute",
		"attr_merge_normalize",
		"collect_modify",
	} {
		if !strings.Contains(string(contents), expected) {
			t.Fatalf("pinned collect.c lacks %q", expected)
		}
	}
}

func assertOpenLDAPCollectConfigurationGrammar(
	t *testing.T,
	tools openLDAPReferenceTools,
) {
	t.Helper()
	cases := []struct {
		name       string
		lines      []string
		wantOK     bool
		wantOutput string
	}{
		{
			name: "valid quoted and overlapping",
			lines: []string{
				`collectinfo "ou=people,dc=example,dc=com" description,telephoneNumber`,
				`collectinfo "ou=team,ou=people,dc=example,dc=com" description,description`,
			},
			wantOK: true,
		},
		{
			name: "normalized duplicate",
			lines: []string{
				`collectinfo "OU=People,DC=Example,DC=Com" description`,
				`collectinfo "ou=people,dc=example,dc=com" mail`,
			},
			wantOutput: "DN already configured",
		},
		{
			name: "unknown attribute",
			lines: []string{
				`collectinfo "ou=people,dc=example,dc=com" collectUndefined`,
			},
			wantOutput: "attribute description unknown",
		},
		{
			name: "whitespace after comma",
			lines: []string{
				`collectinfo "ou=people,dc=example,dc=com" description, telephoneNumber`,
			},
			wantOutput: "extra cruft",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			databaseDir := filepath.Join(root, "db")
			if err := os.Mkdir(databaseDir, 0o700); err != nil {
				t.Fatalf("Mkdir(database): %v", err)
			}
			config := fmt.Sprintf(
				"include %s\ninclude %s\ninclude %s\n"+
					"database mdb\nsuffix \"dc=example,dc=com\"\n"+
					"directory %s\noverlay collect\n%s\n",
				filepath.Join(tools.schemaDir, "core.schema"),
				filepath.Join(tools.schemaDir, "cosine.schema"),
				filepath.Join(tools.schemaDir, "inetorgperson.schema"),
				databaseDir,
				strings.Join(test.lines, "\n"),
			)
			path := filepath.Join(root, "slapd.conf")
			if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
				t.Fatalf("WriteFile(slapd.conf): %v", err)
			}
			command := exec.Command(tools.slapd, "-Ttest", "-u", "-f", path)
			output, err := command.CombinedOutput()
			if test.wantOK {
				if err != nil {
					t.Fatalf("valid collect configuration: %v: %s", err, output)
				}
				return
			}
			if err == nil || !strings.Contains(string(output), test.wantOutput) {
				t.Fatalf(
					"invalid collect configuration error=%v output=%q, want %q",
					err,
					output,
					test.wantOutput,
				)
			}
		})
	}
}

func collectReferenceGlobalConfig(tools openLDAPReferenceTools) string {
	return "attributetype ( 1.3.6.1.4.1.99999.1901 NAME 'collectSort' " +
		"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
		"SYNTAX " + schema.SyntaxDirectoryString + " )\n" +
		"database frontend\n" +
		"overlay collect\n" +
		`collectinfo "ou=people,dc=example,dc=com" l`
}

func collectReferenceStaticOverlay() string {
	return "collect\n" +
		`collectinfo "ou=people,dc=example,dc=com" description,telephoneNumber,l,collectSort` + "\n" +
		`collectinfo "ou=team,ou=people,dc=example,dc=com" description,description,telephoneNumber,l,collectSort` + "\n" +
		`collectinfo "ou=missing,dc=example,dc=com" mail`
}

func startCollectReferenceLDAPGo(
	t *testing.T,
	aclRules []string,
) (*ldap.Conn, *ldap.Conn, string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	configClient := bindConstraintClient(t, address, "cn=config", "config-secret")
	dataClient := bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)

	schemaRequest := ldap.NewAddRequest("cn={9}collect-reference,cn=schema,cn=config", nil)
	schemaRequest.Attribute("objectClass", []string{"olcSchemaConfig"})
	schemaRequest.Attribute("cn", []string{"{9}collect-reference"})
	schemaRequest.Attribute("olcAttributeTypes", []string{
		"{0}( 1.3.6.1.4.1.99999.1901 NAME 'collectSort' " +
			"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
			"SYNTAX " + schema.SyntaxDirectoryString + " )",
	})
	if err := configClient.Add(schemaRequest); err != nil {
		t.Fatalf("Add(ldap-go collect reference schema): %v", err)
	}
	if len(aclRules) > 0 {
		replaceCollectDataACL(t, configClient, aclRules...)
	}
	addCollectReferenceOverlays(t, configClient)
	sssVLV := ldap.NewAddRequest(
		"olcOverlay={1}sssvlv,olcDatabase={1}mdb,cn=config",
		nil,
	)
	sssVLV.Attribute("objectClass", []string{"olcOverlayConfig"})
	sssVLV.Attribute("olcOverlay", []string{"{1}sssvlv"})
	if err := configClient.Add(sssVLV); err != nil {
		t.Fatalf("Add(ldap-go reference sssvlv): %v", err)
	}
	return dataClient, configClient, "ldap://" + address, stop
}

func addCollectReferenceOverlays(t *testing.T, configClient *ldap.Conn) {
	t.Helper()
	database := ldap.NewAddRequest(collectDatabaseOverlayDN, nil)
	database.Attribute("objectClass", []string{"olcOverlayConfig", "olcCollectConfig"})
	database.Attribute("olcOverlay", []string{"{0}collect"})
	database.Attribute("olcCollectInfo", []string{
		`"ou=people,dc=example,dc=com" description,telephoneNumber,l,collectSort`,
		`"ou=team,ou=people,dc=example,dc=com" description,description,telephoneNumber,l,collectSort`,
		`"ou=missing,dc=example,dc=com" mail`,
	})
	if err := configClient.Add(database); err != nil {
		t.Fatalf("Add(ldap-go collect reference database overlay): %v", err)
	}
	frontend := ldap.NewAddRequest("olcDatabase={-1}frontend,cn=config", nil)
	frontend.Attribute("objectClass", []string{"olcDatabaseConfig"})
	frontend.Attribute("olcDatabase", []string{"{-1}frontend"})
	if err := configClient.Add(frontend); err != nil {
		t.Fatalf("Add(ldap-go collect reference frontend): %v", err)
	}
	global := ldap.NewAddRequest(collectFrontendOverlayDN, nil)
	global.Attribute("objectClass", []string{"olcOverlayConfig", "olcCollectConfig"})
	global.Attribute("olcOverlay", []string{"{0}collect"})
	global.Attribute(
		"olcCollectInfo",
		[]string{`"ou=people,dc=example,dc=com" l`},
	)
	if err := configClient.Add(global); err != nil {
		t.Fatalf("Add(ldap-go collect reference frontend overlay): %v", err)
	}
}

func addCollectReferenceFixtures(t *testing.T, client *ldap.Conn) {
	t.Helper()
	people := ldap.NewModifyRequest(collectPeopleDN, nil)
	people.Add("objectClass", []string{"extensibleObject"})
	people.Add("description", []string{"Broad-A", "shared"})
	people.Add("telephoneNumber", []string{"+1 555 0100"})
	people.Add("l", []string{"Global"})
	people.Add("collectSort", []string{"Zulu"})
	if err := client.Modify(people); err != nil {
		t.Fatalf("Modify(reference people template): %v", err)
	}
	team := ldap.NewAddRequest(collectTeamDN, nil)
	team.Attribute("objectClass", []string{"organizationalUnit", "extensibleObject"})
	team.Attribute("ou", []string{"team"})
	team.Attribute("description", []string{"Specific-A", "shared"})
	team.Attribute("telephoneNumber", []string{"+1 555 0200"})
	team.Attribute("l", []string{"Local"})
	team.Attribute("collectSort", []string{"Alpha"})
	if err := client.Add(team); err != nil {
		t.Fatalf("Add(reference team template): %v", err)
	}
	for _, fixture := range []struct {
		dn          string
		uid         string
		description []string
	}{
		{dn: collectReferenceBroadTargetDN, uid: "collect-aaa"},
		{
			dn:          collectReferenceNestedDN,
			uid:         "collect-zzz",
			description: []string{"Local-A", "SHARED"},
		},
		{dn: collectReferenceProjectedDN, uid: "collect-projected"},
	} {
		request := ldap.NewAddRequest(fixture.dn, nil)
		request.Attribute("objectClass", []string{"inetOrgPerson"})
		request.Attribute("uid", []string{fixture.uid})
		request.Attribute("cn", []string{fixture.uid})
		request.Attribute("sn", []string{fixture.uid})
		if len(fixture.description) > 0 {
			request.Attribute("description", fixture.description)
		}
		if err := client.Add(request); err != nil {
			t.Fatalf("Add(reference fixture %s): %v", fixture.dn, err)
		}
	}
	referral := ldap.NewAddRequest(collectReferenceReferralDN, nil)
	referral.Attribute("objectClass", []string{"referral", "extensibleObject"})
	referral.Attribute("ou", []string{"collect-ref"})
	referral.Attribute("ref", []string{"ldap://127.0.0.1:9/dc=invalid"})
	if err := client.Add(referral); err != nil {
		t.Fatalf("Add(reference collect referral): %v", err)
	}
}

func runCollectReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
) collectReferenceOutcome {
	t.Helper()
	nested := searchCollectEntry(
		t,
		client,
		collectReferenceNestedDN,
		[]string{"description", "telephoneNumber", "l"},
		false,
		nil,
	)
	outcome := collectReferenceOutcome{
		descriptions:     nested.GetAttributeValues("description"),
		telephoneNumbers: nested.GetAttributeValues("telephoneNumber"),
		localities:       nested.GetAttributeValues("l"),
	}

	filtered, err := client.Search(ldap.NewSearchRequest(
		collectReferenceProjectedDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(description=*)",
		[]string{"uid"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(reference projected filter): %v", err)
	}
	outcome.projectedFilterDNs = collectEntryDNs(filtered.Entries)
	outcome.compareCode = collectCompareResultCode(
		t,
		client,
		collectReferenceProjectedDN,
		"description",
		"specific-a",
	)
	cnOnly := searchCollectEntry(
		t,
		client,
		collectReferenceProjectedDN,
		[]string{"cn"},
		false,
		nil,
	)
	outcome.cnOnlyProjected = len(cnOnly.GetAttributeValues("description")) > 0
	typesOnly := searchCollectEntry(
		t,
		client,
		collectReferenceProjectedDN,
		[]string{"description"},
		true,
		nil,
	)
	for _, attribute := range typesOnly.Attributes {
		if strings.EqualFold(attribute.Name, "description") {
			outcome.typesOnlyPresent = true
			outcome.typesOnlyValues = len(attribute.ByteValues)
		}
	}

	paging := ldap.NewControlPaging(1)
	for {
		result, err := client.Search(ldap.NewSearchRequest(
			collectPeopleDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(uid=collect-*)",
			[]string{"uid", "description"},
			[]ldap.Control{paging},
		))
		if err != nil {
			t.Fatalf("Search(reference collect paging): %v", err)
		}
		for _, entry := range result.Entries {
			outcome.paged = append(
				outcome.paged,
				strings.ToLower(entry.DN)+"="+
					strings.Join(entry.GetAttributeValues("description"), ","),
			)
		}
		control, ok := ldap.FindControl(
			result.Controls,
			ldap.ControlTypePaging,
		).(*ldap.ControlPaging)
		if !ok {
			t.Fatalf("reference paging response = %#v", result.Controls)
		}
		if len(control.Cookie) == 0 {
			break
		}
		paging.SetCookie(control.Cookie)
	}
	sort.Strings(outcome.paged)

	sorted, err := client.Search(ldap.NewSearchRequest(
		collectPeopleDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(|(uid=collect-aaa)(uid=collect-zzz))",
		[]string{"uid", "collectSort"},
		[]ldap.Control{newSortControl(ldap.SortKey{AttributeType: "collectSort"})},
	))
	if err != nil {
		t.Fatalf("Search(reference collect sort): %v", err)
	}
	assertSortResult(t, sorted, ldap.ControlServerSideSortingCodeSuccess)
	outcome.sortedDNs = collectEntryDNs(sorted.Entries)
	for _, entry := range sorted.Entries {
		outcome.sortedValues = append(
			outcome.sortedValues,
			entry.GetAttributeValues("collectSort"),
		)
	}
	managed := searchCollectEntry(
		t,
		client,
		collectReferenceReferralDN,
		[]string{"description"},
		false,
		[]ldap.Control{ldap.NewControlManageDsaIT(true)},
	)
	outcome.managedReferral = managed.GetAttributeValues("description")
	_, err = client.Search(ldap.NewSearchRequest(
		collectReferenceReferralDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"description"},
		nil,
	))
	outcome.unmanagedCode = collectLDAPResultCode(t, err)
	return outcome
}

func runOpenLDAPCollectWriteScenario(
	t *testing.T,
	client *ldap.Conn,
) collectReferenceWriteOutcome {
	t.Helper()
	outcome := runCollectWriteRequests(t, client)
	if outcome.multipleCode != ldap.LDAPResultSuccess ||
		!outcome.givenNameStored || !outcome.descriptionSaved ||
		outcome.optionCode != ldap.LDAPResultSuccess || !outcome.optionStored {
		t.Fatalf("OpenLDAP 2.6.13 collect vulnerability baseline = %#v", outcome)
	}
	return outcome
}

func runLDAPGoCollectWriteScenario(
	t *testing.T,
	client *ldap.Conn,
) collectReferenceWriteOutcome {
	t.Helper()
	return runCollectWriteRequests(t, client)
}

func runCollectWriteRequests(
	t *testing.T,
	client *ldap.Conn,
) collectReferenceWriteOutcome {
	t.Helper()
	var outcome collectReferenceWriteOutcome
	direct := ldap.NewModifyRequest(collectReferenceProjectedDN, nil)
	direct.Add("description", []string{"direct-blocked"})
	outcome.directCode, outcome.directDiagnostic = collectLDAPError(t, client.Modify(direct))

	multiple := ldap.NewModifyRequest(collectReferenceProjectedDN, nil)
	multiple.Add("givenName", []string{"multi-first"})
	multiple.Add("description", []string{"multi-second"})
	outcome.multipleCode, _ = collectLDAPError(t, client.Modify(multiple))
	entry := searchCollectEntry(
		t,
		client,
		collectReferenceProjectedDN,
		[]string{"givenName", "description"},
		false,
		nil,
	)
	outcome.givenNameStored = entry.GetAttributeValue("givenName") == "multi-first"
	for _, value := range entry.GetAttributeValues("description") {
		if value == "multi-second" {
			outcome.descriptionSaved = true
		}
	}

	optioned := ldap.NewModifyRequest(collectReferenceProjectedDN, nil)
	optioned.Add("description;lang-en", []string{"option-bypass"})
	outcome.optionCode, _ = collectLDAPError(t, client.Modify(optioned))
	optionEntry := searchCollectEntry(
		t,
		client,
		collectReferenceProjectedDN,
		[]string{"description;lang-en"},
		false,
		nil,
	)
	outcome.optionStored = optionEntry.GetAttributeValue("description;lang-en") == "option-bypass"
	return outcome
}

func assertCollectWriteCompatibilityAndHardening(
	t *testing.T,
	openLDAP,
	ldapGo collectReferenceWriteOutcome,
) {
	t.Helper()
	for name, outcome := range map[string]collectReferenceWriteOutcome{
		"OpenLDAP": openLDAP,
		"ldap-go":  ldapGo,
	} {
		if outcome.directCode != ldap.LDAPResultUnwillingToPerform ||
			!strings.Contains(
				outcome.directDiagnostic,
				"cannot change virtual attribute 'description'",
			) {
			t.Fatalf("%s direct collect Modify = %#v", name, outcome)
		}
	}
	if ldapGo.multipleCode != ldap.LDAPResultUnwillingToPerform ||
		ldapGo.givenNameStored || ldapGo.descriptionSaved {
		t.Fatalf("ldap-go did not harden multi-modification bypass: %#v", ldapGo)
	}
	if ldapGo.optionCode != ldap.LDAPResultUnwillingToPerform || ldapGo.optionStored {
		t.Fatalf("ldap-go did not harden optioned-attribute bypass: %#v", ldapGo)
	}
}

func collectReferenceACLRules() []string {
	reader := `dn.exact="uid=collect-reader,ou=people,dc=example,dc=com"`
	return []string{
		`to dn.exact="` + collectTeamDN + `" attrs=description by ` + reader + ` none by * read`,
		`to dn.exact="` + collectReferenceNestedDN + `" attrs=telephoneNumber by ` + reader + ` none by * read`,
		`to dn.exact="` + collectReferenceNestedDN + `" attrs=description val.regex="^broad-a$" by ` + reader + ` none by * read`,
		`to dn.exact="` + collectReferenceBroadTargetDN + `" attrs=entry by ` + reader + ` none by * read`,
		`to * by * read`,
	}
}

func collectReferenceStaticACLRules(rules []string) []string {
	result := make([]string, len(rules))
	for index, rule := range rules {
		result[index] = "access " + rule
	}
	return result
}

func addCollectReferenceReader(t *testing.T, client *ldap.Conn) {
	t.Helper()
	request := ldap.NewAddRequest(
		"uid=collect-reader,ou=people,dc=example,dc=com",
		nil,
	)
	request.Attribute("objectClass", []string{"inetOrgPerson"})
	request.Attribute("uid", []string{"collect-reader"})
	request.Attribute("cn", []string{"Collect Reader"})
	request.Attribute("sn", []string{"Reader"})
	request.Attribute("userPassword", []string{"reader-secret"})
	if err := client.Add(request); err != nil {
		t.Fatalf("Add(collect reference reader): %v", err)
	}
}

func bindOverlayReferenceClientWithDN(
	t *testing.T,
	uri,
	dn,
	password string,
) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	if err := client.Bind(dn, password); err != nil {
		client.Close()
		t.Fatalf("Bind(%s): %v", dn, err)
	}
	return client
}

func runCollectReferenceACLScenario(
	t *testing.T,
	client *ldap.Conn,
) ([]string, uint16) {
	t.Helper()
	entry := searchCollectEntry(
		t,
		client,
		collectReferenceNestedDN,
		[]string{"description", "telephoneNumber"},
		false,
		nil,
	)
	if len(entry.GetAttributeValues("telephoneNumber")) != 0 {
		t.Fatalf("target attribute ACL exposed telephoneNumber: %#v", entry.Attributes)
	}
	_, err := client.Search(ldap.NewSearchRequest(
		collectReferenceBroadTargetDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"description"},
		nil,
	))
	return entry.GetAttributeValues("description"), collectLDAPResultCode(t, err)
}

func collectLDAPResultCode(t *testing.T, err error) uint16 {
	t.Helper()
	code, _ := collectLDAPError(t, err)
	return code
}

func collectLDAPError(t *testing.T, err error) (uint16, string) {
	t.Helper()
	if err == nil {
		return ldap.LDAPResultSuccess, ""
	}
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		t.Fatalf("LDAP operation returned non-LDAP error: %v", err)
	}
	return ldapErr.ResultCode, ldapErr.Error()
}
