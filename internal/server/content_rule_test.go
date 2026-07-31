package server

import (
	"context"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	testContentRuleSchemaDN = "cn={8}content-rule,cn=schema,cn=config"
	testContentRuleOID      = "2.16.840.1.113730.3.2.2"
)

func TestLDAPClientDITContentRuleLifecycle(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)

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
	dataClient := bindContentRuleClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer dataClient.Close()

	if err := configClient.Add(testContentRuleSchemaRequest(
		"{0}( " + testContentRuleOID + " NAME 'applicationPersonRule' " +
			"AUX applicationAux MUST uid MAY applicationLabel " +
			"NOT description )",
	)); err != nil {
		t.Fatalf("Add(content-rule schema): %v", err)
	}
	assertPublishedContentRule(t, configClient, true, "applicationPersonRule")

	valid := newContentRulePersonAdd(
		"cn=rule-valid,ou=people,dc=example,dc=com",
		"rule-valid",
		"applicationAux",
	)
	valid.Attribute("applicationCode", []string{"portal"})
	valid.Attribute("applicationLabel", []string{"Portal"})
	if err := dataClient.Add(valid); err != nil {
		t.Fatalf("Add(valid content-rule entry): %v", err)
	}

	missingRequired := ldap.NewAddRequest(
		"cn=missing-uid,ou=people,dc=example,dc=com",
		nil,
	)
	missingRequired.Attribute("objectClass", []string{"inetOrgPerson"})
	missingRequired.Attribute("cn", []string{"missing-uid"})
	missingRequired.Attribute("sn", []string{"User"})
	assertLDAPResultCode(
		t,
		dataClient.Add(missingRequired),
		ldap.LDAPResultObjectClassViolation,
	)

	precluded := newContentRulePersonAdd(
		"uid=precluded,ou=people,dc=example,dc=com",
		"precluded",
	)
	precluded.Attribute("description", []string{"not allowed"})
	assertLDAPResultCode(
		t,
		dataClient.Add(precluded),
		ldap.LDAPResultObjectClassViolation,
	)

	unlistedAuxiliary := newContentRulePersonAdd(
		"uid=unlisted-aux,ou=people,dc=example,dc=com",
		"unlisted-aux",
		"posixAccount",
	)
	assertLDAPResultCode(
		t,
		dataClient.Add(unlistedAuxiliary),
		ldap.LDAPResultObjectClassViolation,
	)

	addPrecluded := ldap.NewModifyRequest(valid.DN, nil)
	addPrecluded.Add("description", []string{"still not allowed"})
	assertLDAPResultCode(
		t,
		dataClient.Modify(addPrecluded),
		ldap.LDAPResultObjectClassViolation,
	)
	removeRequired := ldap.NewModifyRequest(valid.DN, nil)
	removeRequired.Delete("uid", nil)
	assertLDAPResultCode(
		t,
		dataClient.Modify(removeRequired),
		ldap.LDAPResultObjectClassViolation,
	)

	replaceRule := ldap.NewModifyRequest(testContentRuleSchemaDN, nil)
	replaceRule.Replace("olcDitContentRules", []string{
		"{0}( " + testContentRuleOID + " NAME 'applicationPersonRule' " +
			"AUX applicationAux MUST uid " +
			"MAY ( applicationLabel $ description ) )",
	})
	if err := configClient.Modify(replaceRule); err != nil {
		t.Fatalf("Modify(content rule): %v", err)
	}
	if err := dataClient.Modify(addPrecluded); err != nil {
		t.Fatalf("Modify(after online content-rule update): %v", err)
	}

	invalidRule := ldap.NewModifyRequest(testContentRuleSchemaDN, nil)
	invalidRule.Replace("olcDitContentRules", []string{
		"{0}( " + testContentRuleOID + " MAY entryUUID )",
	})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalidRule),
		ldap.LDAPResultConstraintViolation,
	)
	secondDescription := ldap.NewModifyRequest(valid.DN, nil)
	secondDescription.Replace("description", []string{"runtime rolled back"})
	if err := dataClient.Modify(secondDescription); err != nil {
		t.Fatalf("Modify(after invalid config rollback): %v", err)
	}

	if err := configClient.Del(
		ldap.NewDelRequest(testContentRuleSchemaDN, nil),
	); err != nil {
		t.Fatalf("Delete(content-rule schema): %v", err)
	}
	assertPublishedContentRule(t, configClient, false, "applicationPersonRule")
}

func TestDITContentRuleConfigurationSurvivesRestart(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	config := Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	}

	address, stop := startServer(t, store, config)
	configClient := bindContentRuleClient(
		t,
		address,
		"cn=config",
		"config-secret",
	)
	if err := configClient.Add(testContentRuleSchemaRequest(
		"{0}( " + testContentRuleOID + " NAME 'restartRule' " +
			"AUX applicationAux MUST uid )",
	)); err != nil {
		t.Fatalf("Add(content-rule schema): %v", err)
	}
	configClient.Close()
	stop()

	address, stop = startServer(t, store, config)
	defer stop()
	dataClient := bindContentRuleClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer dataClient.Close()

	missingUID := ldap.NewAddRequest(
		"cn=restart-missing,ou=people,dc=example,dc=com",
		nil,
	)
	missingUID.Attribute("objectClass", []string{"inetOrgPerson"})
	missingUID.Attribute("cn", []string{"restart-missing"})
	missingUID.Attribute("sn", []string{"User"})
	assertLDAPResultCode(
		t,
		dataClient.Add(missingUID),
		ldap.LDAPResultObjectClassViolation,
	)
}

func testContentRuleSchemaRequest(rule string) *ldap.AddRequest {
	request := ldap.NewAddRequest(testContentRuleSchemaDN, nil)
	request.Attribute("objectClass", []string{"olcSchemaConfig"})
	request.Attribute("cn", []string{"{8}content-rule"})
	request.Attribute("olcAttributeTypes", []string{
		"{0}( 1.3.6.1.4.1.99999.10 NAME 'applicationCode' " +
			"EQUALITY caseIgnoreMatch SYNTAX " +
			schema.SyntaxDirectoryString + " )",
		"{1}( 1.3.6.1.4.1.99999.11 NAME 'applicationLabel' " +
			"EQUALITY caseIgnoreMatch SYNTAX " +
			schema.SyntaxDirectoryString + " )",
	})
	request.Attribute("olcObjectClasses", []string{
		"{0}( 1.3.6.1.4.1.99999.12 NAME 'applicationAux' SUP top " +
			"AUXILIARY MUST applicationCode )",
		"{1}( 1.3.6.1.4.1.99999.13 NAME 'unlistedAux' SUP top " +
			"AUXILIARY )",
	})
	request.Attribute("olcDitContentRules", []string{rule})
	return request
}

func newContentRulePersonAdd(
	dn,
	uid string,
	additionalClasses ...string,
) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	classes := append([]string{"inetOrgPerson"}, additionalClasses...)
	request.Attribute("objectClass", classes)
	request.Attribute("uid", []string{uid})
	request.Attribute("cn", []string{uid})
	request.Attribute("sn", []string{"User"})
	return request
}

func bindContentRuleClient(
	t *testing.T,
	address,
	dn,
	password string,
) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", dn, err)
	}
	if err := client.Bind(dn, password); err != nil {
		client.Close()
		t.Fatalf("Bind(%s): %v", dn, err)
	}
	return client
}

func assertPublishedContentRule(
	t *testing.T,
	client *ldap.Conn,
	want bool,
	name string,
) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
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
		t.Fatalf("Search(cn=Subschema): %v", err)
	}
	found := false
	if len(result.Entries) == 1 {
		for _, value := range result.Entries[0].GetAttributeValues(
			"dITContentRules",
		) {
			if strings.Contains(value, "NAME '"+name+"'") {
				found = true
				break
			}
		}
	}
	if found != want {
		t.Fatalf(
			"published content rule %q found = %t, want %t: %#v",
			name,
			found,
			want,
			result.Entries,
		)
	}
}

func TestLoadDITContentRuleFromImportedConfiguration(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	request := testContentRuleSchemaRequest(
		"{0}( " + testContentRuleOID + " NAME 'importedRule' " +
			"AUX applicationAux MUST uid )",
	)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(ldapAddRequestEntry(request), false)
	}); err != nil {
		t.Fatalf("seed imported content-rule configuration: %v", err)
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
	assertPublishedContentRule(t, configClient, true, "importedRule")
}

func ldapAddRequestEntry(request *ldap.AddRequest) directory.Entry {
	entry := directory.Entry{DN: request.DN}
	for _, attribute := range request.Attributes {
		values := make([][]byte, len(attribute.Vals))
		for index := range attribute.Vals {
			values[index] = []byte(attribute.Vals[index])
		}
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: attribute.Type,
			Values:      values,
		})
	}
	return entry
}
