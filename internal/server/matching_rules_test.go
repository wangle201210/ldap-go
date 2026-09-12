package server

import (
	"slices"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestMatchingRuleNativeCorpus(t *testing.T) {
	uri := matchingRulesReferenceGoServer(t)
	observed := matchingRulesReferenceObserve(t, uri)
	matchingRulesReferenceAssertExpected(t, observed)
	matchingRulesReferenceAssertPublished(t, uri, observed)
}

func matchingRulesTestClient(t *testing.T) (*ldap.Conn, *ldap.Conn) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	dial := func() *ldap.Conn {
		client, err := ldap.DialURL("ldap://" + address)
		if err != nil {
			t.Fatal(err)
		}
		client.SetTimeout(3 * time.Second)
		t.Cleanup(func() { _ = client.Close() })
		return client
	}
	client, config := dial(), dial()
	if err := config.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	return client, config
}

func matchingRulesTestSearch(t *testing.T, client *ldap.Conn, attrs []string, typesOnly bool) *ldap.Entry {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest("cn=Subschema", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, typesOnly, "(objectClass=*)", attrs, nil))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("subschema query: %+v %v", result, err)
	}
	return result.Entries[0]
}

func TestMatchingRulePublicationSelectionAndAliases(t *testing.T) {
	client, _ := matchingRulesTestClient(t)
	for _, attrs := range [][]string{nil, {"*"}, {"1.1"}} {
		entry := matchingRulesTestSearch(t, client, attrs, false)
		if len(entry.GetAttributeValues("matchingRules")) != 0 || len(entry.GetAttributeValues("matchingRuleUse")) != 0 {
			t.Fatal("operational descriptions leaked into ordinary selection")
		}
	}
	for _, attrs := range [][]string{{"matchingRules", "matchingRuleUse"}, {"2.5.21.4", "2.5.21.8"}, {"+"}} {
		entry := matchingRulesTestSearch(t, client, attrs, false)
		rules := make(map[string]schema.MatchingRule)
		for _, raw := range entry.GetAttributeValues("matchingRules") {
			rule, err := schema.ParseMatchingRule(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, duplicate := rules[rule.OID]; duplicate {
				t.Fatalf("duplicate rule %s", rule.OID)
			}
			rules[rule.OID] = rule
		}
		if len(rules) < 20 || len(rules["2.5.13.2"].Names) != 1 || rules["2.5.13.2"].Names[0] != "caseIgnoreMatch" {
			t.Fatalf("missing implemented rule metadata: %v", rules)
		}
		for _, oid := range []string{"1.3.6.1.4.1.4203.666.4.12", "1.3.6.1.4.1.4203.666.4.4"} {
			if _, exposed := rules[oid]; exposed {
				t.Fatalf("hidden rule %s published", oid)
			}
		}
		uses := entry.GetAttributeValues("matchingRuleUse")
		if len(uses) == 0 {
			t.Fatal("missing rule-use metadata")
		}
		for _, raw := range uses {
			use, err := schema.ParseMatchingRuleUse(raw)
			if err != nil || len(use.Applies) == 0 {
				t.Fatalf("invalid rule-use: %s %v", raw, err)
			}
			if _, published := rules[use.OID]; !published {
				t.Fatalf("use for unpublished rule %s", use.OID)
			}
			if use.OID == "2.5.13.2" && !slices.Contains(use.Applies, "cn") {
				t.Fatal("caseIgnoreMatch missing cn")
			}
		}
	}
	types := matchingRulesTestSearch(t, client, []string{"matchingRules", "matchingRuleUse"}, true)
	if len(types.Attributes) != 2 {
		t.Fatalf("typesOnly attributes: %+v", types.Attributes)
	}
	for _, attribute := range types.Attributes {
		if len(attribute.Values) != 0 {
			t.Fatal("typesOnly returned descriptions")
		}
	}
	for _, attribute := range []string{"matchingRules", "matchingRuleUse", "2.5.21.4", "2.5.21.8"} {
		for _, assertion := range []string{"caseIgnoreMatch", "CASEIGNOREMATCH", "2.5.13.2"} {
			matched, err := client.Compare("cn=Subschema", attribute, assertion)
			if err != nil || !matched {
				t.Fatalf("Compare %s/%s: %v %v", attribute, assertion, matched, err)
			}
			result, err := client.Search(ldap.NewSearchRequest("cn=Subschema", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
				0, 0, false, "("+attribute+"="+assertion+")", []string{"1.1"}, nil))
			if err != nil || len(result.Entries) != 1 {
				t.Fatalf("rule filter failed: %v", err)
			}
		}
	}
}

func TestMatchingRuleUseOnlineSchemaRefresh(t *testing.T) {
	client, config := matchingRulesTestClient(t)
	const name = "mrOnlineValue"
	contains := func() bool {
		for _, raw := range matchingRulesTestSearch(t, client, []string{"matchingRuleUse"}, false).GetAttributeValues("matchingRuleUse") {
			use, err := schema.ParseMatchingRuleUse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if use.OID == "2.5.13.2" && slices.Contains(use.Applies, name) {
				return true
			}
		}
		return false
	}
	if contains() {
		t.Fatal("unregistered attribute advertised")
	}
	request := ldap.NewAddRequest("cn={9}matching-test,cn=schema,cn=config", nil)
	request.Attribute("objectClass", []string{"olcSchemaConfig"})
	request.Attribute("cn", []string{"{9}matching-test"})
	request.Attribute("olcAttributeTypes", []string{"( 1.3.6.1.4.1.99999.931.1 NAME 'mrOnlineValue' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"})
	if err := config.Add(request); err != nil {
		t.Fatal(err)
	}
	if !contains() {
		t.Fatal("APPLIES failed to refresh or incorrectly depended only on assigned equality")
	}
	modify := ldap.NewModifyRequest("cn={9}matching-test,cn=schema,cn=config", nil)
	modify.Add("olcAttributeTypes", []string{"( 1.3.6.1.4.1.99999.931.2 NAME 'mrBroken' SUP noSuchParent )"})
	if err := config.Modify(modify); err == nil {
		t.Fatal("invalid schema inheritance accepted")
	}
	if !contains() {
		t.Fatal("failed schema update changed cached publication")
	}
	for _, raw := range matchingRulesTestSearch(t, client, []string{"matchingRuleUse"}, false).GetAttributeValues("matchingRuleUse") {
		if strings.Contains(raw, "mrBroken") {
			t.Fatal("failed update leaked into publication")
		}
	}
}
