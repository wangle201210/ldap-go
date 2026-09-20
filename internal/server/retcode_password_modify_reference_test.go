package server

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceRetcodePasswordModifyStages(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	for _, tc := range []struct {
		name, operation, old        string
		code                        int
		passwordAllowed, restricted bool
	}{
		{"extended-schema-error", "extended", "", 53, false, false},
		{"extended-write", "extended", "", 53, true, false},
		{"extended-old-correct", "extended", "old-secret", 53, true, false},
		{"extended-old-wrong", "extended", "wrong-secret", 53, true, false},
		{"modify-error", "modify", "", 53, true, false},
		{"modify-old-wrong", "modify", "wrong-secret", 53, true, false},
		{"modify-success", "modify", "", 0, true, false},
		{"search-error", "search", "", 53, true, false},
		{"all-error", "", "", 53, true, false},
		{"all-success", "", "", 0, true, false},
		{"restricted-attributes", "extended", "", 53, true, true},
		{"restricted-entry", "extended", "", 53, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const dn = "cn=Password Test,ou=people,dc=example,dc=com"
			const operatorDN = "uid=operator,ou=people,dc=example,dc=com"
			classes := []string{"errObject"}
			if tc.passwordAllowed {
				classes = append(classes, "extensibleObject")
			}
			entry := directory.Entry{DN: dn, Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues(classes...)},
				{Description: "cn", Values: stringValues("Password Test")},
				{Description: "errCode", Values: stringValues(fmt.Sprint(tc.code))},
				{Description: "errText", Values: stringValues("simulated failure")},
			}}
			if tc.passwordAllowed {
				entry.ReplaceValues("userPassword", stringValues("old-secret"))
				entry.ReplaceValues("description", stringValues("public", "private"))
			}
			if tc.operation != "" {
				entry.ReplaceValues("errOp", stringValues(tc.operation))
			}
			operator := directory.Entry{DN: operatorDN, Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("operator")},
				{Description: "cn", Values: stringValues("Operator")},
				{Description: "sn", Values: stringValues("Operator")},
				{Description: "userPassword", Values: stringValues("operator-secret")},
			}}
			var data strings.Builder
			for _, e := range []directory.Entry{entry, operator} {
				fmt.Fprintf(&data, "\ndn: %s\n", e.DN)
				for _, attr := range e.Attributes {
					for _, value := range attr.Values {
						fmt.Fprintf(&data, "%s: %s\n", attr.Description, value)
					}
				}
			}
			access := []string{"to * by * read"}
			if tc.restricted {
				access = []string{"to attrs=userPassword by anonymous auth by * none", "to attrs=description val.exact=private by * none", "to * by * read"}
				if tc.name == "restricted-entry" {
					access = append([]string{`to dn.exact="` + dn + `" attrs=entry by * none`}, access...)
				}
			}
			var nativeAccess strings.Builder
			for _, rule := range access {
				fmt.Fprintf(&nativeAccess, "access %s\n", rule)
			}
			native, stop := startOpenLDAPReferenceServerWithConfig(t, tools,
				[]string{"retcode\nretcode-parent ou=RetCodes,dc=example,dc=com\nretcode-indir on"}, "", nativeAccess.String(), data.String())
			defer stop()
			local := startRetcodePasswordModifyTestServer(t, access, entry, operator)
			var observations [2]retcodePasswordObservation
			for i, uri := range []string{native, "ldap://" + local} {
				bindDN, password := "cn=admin,dc=example,dc=com", "secret"
				if tc.restricted {
					bindDN, password = operatorDN, "operator-secret"
				}
				observations[i] = observeRetcodePasswordModify(t, uri, bindDN, password, dn, tc.old)
				t.Logf("endpoint=%d events=%v old=%t new=%t", i, observations[i].events, observations[i].oldOK, observations[i].newOK)
				if tc.restricted {
					for _, event := range observations[i].events {
						if strings.Contains(event, "userpassword=") || strings.Contains(event, "description=private") ||
							(tc.name == "restricted-entry" && strings.HasPrefix(event, "entry:")) {
							t.Errorf("endpoint %d disclosed an unreadable entry or value: %s", i, event)
						}
					}
				}
			}
			if tc.code != 0 && (tc.operation == "modify" || tc.operation == "") && tc.old != "wrong-secret" {
				// The native overlay reports a Modify error, then commits anyway.
				// Preserve the server's atomic failure contract for this defect.
				if !observations[0].newOK || observations[1].newOK || !observations[1].oldOK ||
					!reflect.DeepEqual(observations[1].events, []string{"tag=24 code=53 matched=\"\" text=\"simulated failure\""}) {
					t.Fatalf("atomic retcode failure: native=%+v local=%+v", observations[0], observations[1])
				}
			} else if !reflect.DeepEqual(observations[0], observations[1]) {
				t.Errorf("native=%+v local=%+v", observations[0], observations[1])
			}
		})
	}
}

func startRetcodePasswordModifyTestServer(t *testing.T, access []string, entries ...directory.Entry) string {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		configDN, _ := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		config, err := writer.Get(configDN)
		if err != nil {
			return err
		}
		config.ReplaceValues("olcAccess", stringValues(access...))
		if err := writer.Put(config, true); err != nil {
			return err
		}
		entries = append(entries, directory.Entry{DN: testRetcodeOverlayDN, Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcRetcodeConfig")},
			{Description: "olcOverlay", Values: stringValues("{0}retcode")},
			{Description: "olcRetcodeParent", Values: stringValues("ou=RetCodes,dc=example,dc=com")},
			{Description: "olcRetcodeInDir", Values: stringValues("TRUE")},
		}})
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	address, stop := startServer(t, store, Config{RootDN: "cn=admin,dc=example,dc=com", RootPassword: []byte("secret")})
	t.Cleanup(stop)
	return address
}

type retcodePasswordObservation struct {
	events       []string
	oldOK, newOK bool
}

func observeRetcodePasswordModify(t *testing.T, uri, bindDN, password, dn, old string) retcodePasswordObservation {
	t.Helper()
	conn := dialAndBindRawLDAP(t, strings.TrimPrefix(uri, "ldap://"), bindDN, password)
	defer conn.Close()
	value := ldapwire.EncodePasswordModifyRequestValue(ldapwire.PasswordModifyRequestValue{
		UserIdentity: []byte(dn), HasUserIdentity: true, OldPassword: []byte(old), HasOldPassword: old != "",
		NewPassword: []byte("replacement"), HasNewPassword: true,
	})
	writeRawLDAPRequest(t, conn, 2, rawExtendedRequest(passwordModifyOID, value, true))
	var observation retcodePasswordObservation
	for {
		packet, err := ber.ReadPacket(conn)
		if err != nil {
			t.Fatalf("events=%v: %v", observation.events, err)
		}
		id, err := ber.ParseInt64(packet.Children[0].Data.Bytes())
		if err != nil || id != 2 {
			t.Fatalf("invalid response ID: %q", packet.Bytes())
		}
		op := packet.Children[1]
		if uint64(op.Tag) == ldapwire.ApplicationSearchResultEntry {
			var attrs []string
			for _, attr := range op.Children[1].Children {
				name := attr.Children[0].Data.String()
				switch strings.ToLower(name) {
				case "objectclass", "cn", "errcode", "errop", "errtext", "userpassword", "description":
					for _, value := range attr.Children[1].Children {
						attrs = append(attrs, strings.ToLower(name)+"="+value.Data.String())
					}
				}
			}
			sort.Strings(attrs)
			observation.events = append(observation.events, "entry:"+op.Children[0].Data.String()+":"+strings.Join(attrs, ";"))
		} else {
			observation.events = append(observation.events, fmt.Sprintf("tag=%d code=%d matched=%q text=%q", op.Tag, rawLDAPResultCode(t, op), op.Children[1].Data.String(), op.Children[2].Data.String()))
		}
		if uint64(op.Tag) == ldapwire.ApplicationExtendedResponse {
			break
		}
	}
	writeRawLDAPRequest(t, conn, 3, rawExtendedRequest(whoAmIOID, nil, false))
	packet, err := ber.ReadPacket(conn)
	if err != nil {
		t.Fatal(err)
	}
	assertRetcodeWireResponse(t, packet, 3, ldapwire.ApplicationExtendedResponse, ldap.LDAPResultSuccess)
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	result, err := client.Search(ldap.NewSearchRequest("ou=people,dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(cn=Password Test)", []string{"userPassword"}, []ldap.Control{ldap.NewControlManageDsaIT(true)}))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("inspect password: result=%+v err=%v", result, err)
	}
	for _, value := range result.Entries[0].GetRawAttributeValues("userPassword") {
		observation.oldOK = observation.oldOK || auth.VerifyPassword(value, []byte("old-secret"))
		observation.newOK = observation.newOK || auth.VerifyPassword(value, []byte("replacement"))
	}
	return observation
}
