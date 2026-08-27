package server

import (
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
)

func TestLoadRetcodeRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	suffix, _ := directory.ParseDN("dc=example,dc=com")
	entry := directory.Entry{
		DN: "olcOverlay={0}retcode,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{
				Description: "olcRetcodeParent",
				Values:      stringValues("ou=RetCodes,dc=example,dc=com"),
			},
			{
				Description: "olcRetcodeInDir",
				Values:      stringValues("TRUE"),
			},
			{
				Description: "olcRetcodeSleep",
				Values:      stringValues("-4"),
			},
			{
				Description: "olcRetcodeItem",
				Values: stringValues(
					`{0}"cn=Unavailable" "0x34" "op=read,modify" ` +
						`"text=try later" "matched=dc=example,dc=com" ` +
						`"ref=ldap://one ldap://two" "sleeptime=2" ` +
						`"unsolicited=1.2.3:payload" ` +
						`"flags=post-disconnect"`,
				),
			},
		},
	}
	configuration, err := loadRetcodeRuntimeConfiguration(
		entry,
		runtimeDatabase{suffixes: []directory.DN{suffix}},
	)
	if err != nil {
		t.Fatalf("loadRetcodeRuntimeConfiguration(): %v", err)
	}
	if configuration.parent.Key() != "ou=retcodes,dc=example,dc=com" ||
		!configuration.inDirectory || configuration.sleepSeconds != -4 ||
		len(configuration.items) != 1 {
		t.Fatalf("configuration = %#v", configuration)
	}
	item := configuration.items[0]
	wantOperations := retcodeOperationRead | retcodeOperationModify
	if item.dn.Key() != "cn=unavailable,ou=retcodes,dc=example,dc=com" ||
		item.code != ldapwire.ResultUnavailable ||
		item.operations != wantOperations ||
		item.text != "try later" ||
		item.matchedDN != "dc=example,dc=com" ||
		item.sleepSeconds != 2 || item.unsolicitedOID != "1.2.3" ||
		string(item.unsolicitedData) != "payload" ||
		!item.hasUnsolicitedData || !item.postDisconnect || item.preDisconnect {
		t.Fatalf("item = %#v", item)
	}
	if got := stringsFromBytes(item.entry.Values("errOp")); strings.Join(got, ",") != "compare,modify,search" {
		t.Fatalf("synthetic errOp = %q", got)
	}
	if got := stringsFromBytes(item.entry.Values("ref")); strings.Join(got, ",") != "ldap://one,ldap://two" {
		t.Fatalf("synthetic ref = %q", got)
	}
}

func TestLoadRetcodeRuntimeConfigurationDefaultsParentToSuffix(t *testing.T) {
	t.Parallel()

	suffix, _ := directory.ParseDN("dc=example,dc=com")
	configuration, err := loadRetcodeRuntimeConfiguration(
		directory.Entry{
			DN: "olcOverlay=retcode,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcRetcodeItem",
				Values:      stringValues(`"cn=Busy" "063" "op=write"`),
			}},
		},
		runtimeDatabase{suffixes: []directory.DN{suffix}},
	)
	if err != nil {
		t.Fatalf("loadRetcodeRuntimeConfiguration(): %v", err)
	}
	if configuration.parent.Key() != suffix.Key() ||
		len(configuration.items) != 1 ||
		configuration.items[0].code != ldapwire.ResultBusy ||
		configuration.items[0].operations != retcodeOperationWrite {
		t.Fatalf("configuration = %#v", configuration)
	}
}

func TestLoadRetcodeRuntimeConfigurationRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	suffix, _ := directory.ParseDN("dc=example,dc=com")
	tests := map[string]directory.Entry{
		"parent count": {
			Attributes: []directory.Attribute{{
				Description: "olcRetcodeParent",
				Values:      stringValues("dc=one", "dc=two"),
			}},
		},
		"parent DN": {
			Attributes: []directory.Attribute{{
				Description: "olcRetcodeParent",
				Values:      stringValues("not-a-dn"),
			}},
		},
		"sleep": {
			Attributes: []directory.Attribute{{
				Description: "olcRetcodeSleep",
				Values:      stringValues("later"),
			}},
		},
		"ordering": {
			Attributes: []directory.Attribute{{
				Description: "olcRetcodeItem",
				Values:      stringValues(`{x}"cn=x" "0"`),
			}},
		},
		"arguments": {
			Attributes: []directory.Attribute{{
				Description: "olcRetcodeItem",
				Values:      stringValues(`"cn=x"`),
			}},
		},
		"RDN": {
			Attributes: []directory.Attribute{{
				Description: "olcRetcodeItem",
				Values:      stringValues(`"cn=x,dc=example" "0"`),
			}},
		},
		"code": {
			Attributes: []directory.Attribute{{
				Description: "olcRetcodeItem",
				Values:      stringValues(`"cn=x" "08"`),
			}},
		},
		"operation": {
			Attributes: []directory.Attribute{{
				Description: "olcRetcodeItem",
				Values:      stringValues(`"cn=x" "0" "op=explode"`),
			}},
		},
		"option": {
			Attributes: []directory.Attribute{{
				Description: "olcRetcodeItem",
				Values:      stringValues(`"cn=x" "0" "unknown=value"`),
			}},
		},
		"flag": {
			Attributes: []directory.Attribute{{
				Description: "olcRetcodeItem",
				Values:      stringValues(`"cn=x" "0" "flags=eventually"`),
			}},
		},
		"unsolicited base64": {
			Attributes: []directory.Attribute{{
				Description: "olcRetcodeItem",
				Values:      stringValues(`"cn=x" "0" "unsolicited=1.2.3::%%%"`),
			}},
		},
	}
	for name, entry := range tests {
		entry := entry
		entry.DN = "olcOverlay=retcode,olcDatabase={1}mdb,cn=config"
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := loadRetcodeRuntimeConfiguration(
				entry,
				runtimeDatabase{suffixes: []directory.DN{suffix}},
			); err == nil {
				t.Fatal("invalid retcode configuration was accepted")
			}
		})
	}
}

func TestRetcodeConfigurationRequiresParentOrSuffixForItems(t *testing.T) {
	t.Parallel()

	_, err := loadRetcodeRuntimeConfiguration(
		directory.Entry{
			DN: "olcOverlay=retcode,olcDatabase=frontend,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcRetcodeItem",
				Values:      stringValues(`"cn=x" "0"`),
			}},
		},
		runtimeDatabase{name: "frontend"},
	)
	if err == nil || !strings.Contains(err.Error(), "requires") {
		t.Fatalf("missing parent error = %v", err)
	}
}

func TestRetcodeItemFromDirectoryEntryPreservesOpenLDAPValueSemantics(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	runtime := &runtimeState{schema: registry}
	entry := directory.Entry{
		DN: "cn=Error,ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values:      stringValues("inetOrgPerson", "errAuxObject"),
			},
			{Description: "errCode", Values: stringValues("053")},
			{Description: "errOp", Values: stringValues("  SeArCh  ")},
			{Description: "errText", Values: stringValues("try later")},
			{
				Description: "errMatchedDN",
				Values:      stringValues("dc=example,dc=com"),
			},
			{Description: "ref", Values: stringValues("ldap://one")},
			{Description: "errSleepTime", Values: stringValues("+2")},
			{
				Description: "errUnsolicitedOID",
				Values:      stringValues("ExampleOID"),
			},
			{
				Description: "errUnsolicitedData",
				Values:      [][]byte{{0x00, 0xff}},
			},
			{Description: "errDisconnect", Values: stringValues("FALSE")},
		},
	}
	item, applies := retcodeItemFromDirectoryEntry(
		runtime,
		entry,
		retcodeOperationSearch,
	)
	if !applies || item.code != ldapwire.ResultCode(43) ||
		item.text != "try later" || item.matchedDN != "dc=example,dc=com" ||
		len(item.referrals) != 1 || item.referrals[0] != "ldap://one" ||
		item.sleepSeconds != 2 || item.unsolicitedOID != "exampleoid" ||
		string(item.unsolicitedData) != string([]byte{0x00, 0xff}) ||
		!item.hasUnsolicitedData || item.preDisconnect || !item.postDisconnect {
		t.Fatalf("retcode directory item = %#v, applies=%t", item, applies)
	}
	if _, applies := retcodeItemFromDirectoryEntry(
		runtime,
		entry,
		retcodeOperationModify,
	); applies {
		t.Fatal("search-only directory item applied to Modify")
	}
}

func TestBuildRetcodeResultReferralFallback(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("schema.NewBuiltinRegistry(): %v", err)
	}
	target, err := registry.NormalizeDN("cn=Referral,ou=RetCodes,dc=example,dc=com")
	if err != nil {
		t.Fatalf("NormalizeDN(): %v", err)
	}
	runtime := &runtimeState{
		schema:           registry,
		defaultReferrals: []string{"ldap://fallback.example"},
	}
	item := retcodeItem{
		dn:        target,
		code:      ldapwire.ResultReferral,
		matchedDN: "dc=example,dc=com",
		text:      "configured diagnostic",
		referrals: []string{"ldap:/invalid"},
	}

	search := buildRetcodeResult(
		runtime,
		ldapwire.SearchRequest{Scope: directory.ScopeSingleLevel},
		item,
	)
	if search.Code != ldapwire.ResultReferral ||
		search.MatchedDN != item.matchedDN ||
		search.DiagnosticMessage != item.text ||
		len(search.Referrals) != 1 ||
		search.Referrals[0] !=
			"ldap://fallback.example/cn=Referral,ou=RetCodes,dc=example,dc=com" {
		t.Fatalf("Search retcode fallback = %#v", search)
	}

	modify := buildRetcodeResult(
		runtime,
		ldapwire.ModifyRequest{DN: target.String()},
		retcodeItem{dn: target, code: ldapwire.ResultReferral},
	)
	if modify.Code != ldapwire.ResultReferral ||
		len(modify.Referrals) != 1 ||
		modify.Referrals[0] !=
			"ldap://fallback.example/cn=Referral,ou=RetCodes,dc=example,dc=com" {
		t.Fatalf("Modify retcode fallback = %#v", modify)
	}
}

func TestBuildRetcodeResultReferralPrecedenceAndMissingFallback(t *testing.T) {
	t.Parallel()

	target, err := directory.ParseDN("cn=Referral,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	runtime := &runtimeState{defaultReferrals: []string{"ldap://fallback.example"}}
	withItemReferral := buildRetcodeResult(
		runtime,
		ldapwire.SearchRequest{Scope: directory.ScopeWholeSubtree},
		retcodeItem{
			dn:        target,
			code:      ldapwire.ResultReferral,
			referrals: []string{"ldap://item.example"},
		},
	)
	if len(withItemReferral.Referrals) != 1 ||
		withItemReferral.Referrals[0] !=
			"ldap://item.example/cn=Referral,dc=example,dc=com" {
		t.Fatalf("item referral precedence = %#v", withItemReferral)
	}

	withoutReferral := buildRetcodeResult(
		&runtimeState{},
		ldapwire.CompareRequest{DN: target.String()},
		retcodeItem{
			dn:        target,
			code:      ldapwire.ResultReferral,
			matchedDN: "dc=example,dc=com",
			text:      "keep this diagnostic",
		},
	)
	if withoutReferral.Code != ldapwire.ResultOther ||
		withoutReferral.MatchedDN != "dc=example,dc=com" ||
		withoutReferral.DiagnosticMessage != "bad referral object" ||
		len(withoutReferral.Referrals) != 0 {
		t.Fatalf("retcode without referral = %#v", withoutReferral)
	}
}

func stringsFromBytes(values [][]byte) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = string(values[index])
	}
	return result
}
