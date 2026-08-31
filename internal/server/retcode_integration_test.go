package server

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const testRetcodeOverlayDN = "olcOverlay={0}retcode,olcDatabase={1}mdb,cn=config"

func TestRetcodeOverlayOnlineLifecycle(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	config := Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	}
	address, stop := startServer(t, store, config)
	configClient := bindConstraintClient(t, address, "cn=config", "config-secret")
	dataClient := bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)

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
		t.Fatalf("Add(retcode overlay): %v", err)
	}

	assertRetcodeSearchResult(
		t,
		dataClient,
		"cn=Time Limit,ou=RetCodes,dc=example,dc=com",
		ldap.LDAPResultTimeLimitExceeded,
		"dc=example,dc=com",
		"search delayed",
	)
	assertLDAPResultCode(
		t,
		dataClient.Del(ldap.NewDelRequest(
			"cn=Unwilling,ou=RetCodes,dc=example,dc=com",
			nil,
		)),
		ldap.LDAPResultUnwillingToPerform,
	)
	modify := ldap.NewModifyRequest(
		"cn=Unwilling,ou=RetCodes,dc=example,dc=com",
		nil,
	)
	modify.Replace("description", []string{"ignored"})
	assertLDAPResultCode(
		t,
		dataClient.Modify(modify),
		ldap.LDAPResultUnwillingToPerform,
	)
	matched, err := dataClient.Compare(
		"cn=Compare True,ou=RetCodes,dc=example,dc=com",
		"cn",
		"anything",
	)
	if err != nil || !matched {
		t.Fatalf("retcode Compare() = %t, %v", matched, err)
	}
	assertRetcodeBind(t, address)
	assertRetcodeSuccessfulBind(t, address)
	assertLDAPResultCode(
		t,
		dataClient.ModifyDN(ldap.NewModifyDNRequest(
			"cn=Rename,ou=RetCodes,dc=example,dc=com",
			"cn=Renamed",
			true,
			"",
		)),
		ldap.LDAPResultNamingViolation,
	)

	syntheticAdd := ldap.NewAddRequest(
		"cn=Success,ou=RetCodes,dc=example,dc=com",
		nil,
	)
	syntheticAdd.Attribute("objectClass", []string{"organizationalRole"})
	syntheticAdd.Attribute("cn", []string{"Success"})
	if err := dataClient.Add(syntheticAdd); err != nil {
		t.Fatalf("retcode Add(success): %v", err)
	}
	assertRetcodeEntryNotStored(
		t,
		store,
		"cn=Success,ou=RetCodes,dc=example,dc=com",
	)

	assertLDAPResultCode(
		t,
		dataClient.Del(ldap.NewDelRequest(
			"cn=Search Only,ou=RetCodes,dc=example,dc=com",
			nil,
		)),
		ldap.LDAPResultNoSuchObject,
	)
	assertRetcodeSearchResult(
		t,
		dataClient,
		"cn=Missing,ou=RetCodes,dc=example,dc=com",
		ldap.LDAPResultNoSuchObject,
		"ou=RetCodes,dc=example,dc=com",
		"retcode not found",
	)
	assertRetcodeSearchResult(
		t,
		dataClient,
		"ou=RetCodes,dc=example,dc=com",
		ldap.LDAPResultNoSuchObject,
		"ou=RetCodes,dc=example,dc=com",
		"",
	)
	assertRetcodeSyntheticList(t, dataClient)
	assertRetcodeReferral(t, dataClient)
	_, err = dataClient.PasswordModify(ldap.NewPasswordModifyRequest(
		"cn=Extended,ou=RetCodes,dc=example,dc=com",
		"",
		"replacement",
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)

	invalid := ldap.NewModifyRequest(testRetcodeOverlayDN, nil)
	invalid.Replace(
		"olcRetcodeItem",
		[]string{`{0}"cn=Broken" "08"`},
	)
	assertLDAPResultCode(
		t,
		configClient.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	assertRetcodeSearchResult(
		t,
		dataClient,
		"cn=Time Limit,ou=RetCodes,dc=example,dc=com",
		ldap.LDAPResultTimeLimitExceeded,
		"dc=example,dc=com",
		"search delayed",
	)

	update := ldap.NewModifyRequest(testRetcodeOverlayDN, nil)
	update.Replace("olcRetcodeItem", retcodeLifecycleItems(11))
	if err := configClient.Modify(update); err != nil {
		t.Fatalf("Modify(retcode result): %v", err)
	}
	assertRetcodeSearchResult(
		t,
		dataClient,
		"cn=Time Limit,ou=RetCodes,dc=example,dc=com",
		ldap.LDAPResultAdminLimitExceeded,
		"dc=example,dc=com",
		"search delayed",
	)

	configClient.Close()
	dataClient.Close()
	stop()
	address, stop = startServer(t, store, config)
	defer stop()
	dataClient = bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer dataClient.Close()
	assertRetcodeSearchResult(
		t,
		dataClient,
		"cn=Time Limit,ou=RetCodes,dc=example,dc=com",
		ldap.LDAPResultAdminLimitExceeded,
		"dc=example,dc=com",
		"search delayed",
	)
}

func TestRetcodeSyntheticSearchHonorsACL(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	configClient := bindConstraintClient(t, address, "cn=config", "config-secret")
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
	overlay.Attribute("olcRetcodeItem", []string{
		`{0}"cn=Time Limit" "3" "op=search"`,
		`{1}"cn=Unwilling" "53" "op=modify"`,
	})
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(retcode ACL overlay): %v", err)
	}

	access := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	access.Replace("olcAccess", []string{
		`{0}to attrs=errCode by dn.exact="cn=admin,dc=example,dc=com" read by * none`,
		`{1}to * by * read`,
	})
	if err := configClient.Modify(access); err != nil {
		t.Fatalf("Modify(retcode ACL): %v", err)
	}

	anonymous, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(anonymous): %v", err)
	}
	defer anonymous.Close()
	list := func(client *ldap.Conn, filter string) *ldap.SearchResult {
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
			t.Fatalf("Search(%s): %v", filter, err)
		}
		return result
	}

	anonymousEntries := list(anonymous, "(objectClass=errObject)").Entries
	if len(anonymousEntries) != 2 {
		t.Fatalf("anonymous synthetic entries = %d, want 2", len(anonymousEntries))
	}
	for _, entry := range anonymousEntries {
		if entry.GetAttributeValue("cn") == "" ||
			entry.GetAttributeValue("errCode") != "" {
			t.Fatalf("anonymous synthetic entry = %#v", entry)
		}
	}
	if entries := list(anonymous, "(errCode=3)").Entries; len(entries) != 0 {
		t.Fatalf("anonymous errCode filter returned %d entries", len(entries))
	}

	root := bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer root.Close()
	rootEntries := list(root, "(errCode=3)").Entries
	if len(rootEntries) != 1 ||
		rootEntries[0].GetAttributeValue("errCode") != "3" {
		t.Fatalf("root errCode filter entries = %#v", rootEntries)
	}
}

func TestRetcodeOverlayWireResponses(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	configClient := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer configClient.Close()
	overlay := ldap.NewAddRequest(testRetcodeOverlayDN, nil)
	overlay.Attribute(
		"objectClass",
		[]string{"olcOverlayConfig", "olcRetcodeConfig"},
	)
	overlay.Attribute("olcOverlay", []string{"{0}retcode"})
	overlay.Attribute(
		"olcRetcodeParent",
		[]string{"ou=WireRetCodes,dc=example,dc=com"},
	)
	overlay.Attribute("olcRetcodeItem", []string{
		`{0}"cn=Unsolicited" "53" "op=search" ` +
			`"text=unsolicited result" "unsolicited=1.2.3.4::cGF5bG9hZA=="`,
		`{1}"cn=Unsolicited Native" "53" "op=search" "unsolicited=0"`,
		`{2}"cn=Pre Disconnect" "53" "op=search" "flags=pre-disconnect"`,
		`{3}"cn=Post Disconnect" "53" "op=search" "flags=post-disconnect"`,
	})
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(retcode wire overlay): %v", err)
	}

	t.Run("extended unsolicited response", func(t *testing.T) {
		connection := dialAndBindRawLDAP(
			t,
			address,
			"cn=admin,dc=example,dc=com",
			"admin-secret",
		)
		defer connection.Close()
		writeRawLDAPRequest(t, connection, 2, rawRetcodeSearchRequest(
			t,
			"cn=Unsolicited,ou=WireRetCodes,dc=example,dc=com",
		))
		response, err := ber.ReadPacket(connection)
		if err != nil {
			t.Fatalf("read unsolicited response: %v", err)
		}
		assertRetcodeWireResponse(
			t,
			response,
			0,
			ldapwire.ApplicationExtendedResponse,
			ldap.LDAPResultUnwillingToPerform,
		)
		operation := response.Children[1]
		if len(operation.Children) != 5 ||
			operation.Children[3].ClassType != ber.ClassContext ||
			operation.Children[3].Tag != 10 ||
			operation.Children[3].Data.String() != "1.2.3.4" ||
			operation.Children[4].ClassType != ber.ClassContext ||
			operation.Children[4].Tag != 11 ||
			operation.Children[4].Data.String() != "payload" {
			t.Fatalf("unexpected unsolicited ExtendedResponse: %#v", operation)
		}
	})

	t.Run("native unsolicited response", func(t *testing.T) {
		connection := dialAndBindRawLDAP(
			t,
			address,
			"cn=admin,dc=example,dc=com",
			"admin-secret",
		)
		defer connection.Close()
		writeRawLDAPRequest(t, connection, 2, rawRetcodeSearchRequest(
			t,
			"cn=Unsolicited Native,ou=WireRetCodes,dc=example,dc=com",
		))
		response, err := ber.ReadPacket(connection)
		if err != nil {
			t.Fatalf("read native unsolicited response: %v", err)
		}
		assertRetcodeWireResponse(
			t,
			response,
			0,
			ldapwire.ApplicationSearchResultDone,
			ldap.LDAPResultUnwillingToPerform,
		)
	})

	t.Run("pre disconnect", func(t *testing.T) {
		connection := dialAndBindRawLDAP(
			t,
			address,
			"cn=admin,dc=example,dc=com",
			"admin-secret",
		)
		defer connection.Close()
		writeRawLDAPRequest(t, connection, 2, rawRetcodeSearchRequest(
			t,
			"cn=Pre Disconnect,ou=WireRetCodes,dc=example,dc=com",
		))
		assertRetcodeConnectionClosed(t, connection)
	})

	t.Run("post disconnect", func(t *testing.T) {
		connection := dialAndBindRawLDAP(
			t,
			address,
			"cn=admin,dc=example,dc=com",
			"admin-secret",
		)
		defer connection.Close()
		writeRawLDAPRequest(t, connection, 2, rawRetcodeSearchRequest(
			t,
			"cn=Post Disconnect,ou=WireRetCodes,dc=example,dc=com",
		))
		response, err := ber.ReadPacket(connection)
		if err != nil {
			t.Fatalf("read post-disconnect response: %v", err)
		}
		assertRetcodeWireResponse(
			t,
			response,
			2,
			ldapwire.ApplicationSearchResultDone,
			ldap.LDAPResultUnwillingToPerform,
		)
		assertRetcodeConnectionClosed(t, connection)
	})
}

func TestRetcodeOverlayInDirectoryLifecycle(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	configClient := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer configClient.Close()
	dataClient := bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer dataClient.Close()

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
		t.Fatalf("Add(in-directory retcode overlay): %v", err)
	}

	manage := ldap.NewControlManageDsaIT(true)
	failedAddDN := "cn=Add Error,ou=people,dc=example,dc=com"
	failedAdd := retcodeDirectoryAdd(failedAddDN, 53, "add", nil)
	failedAdd.Attribute("errText", []string{"add rejected"})
	assertLDAPResultCode(
		t,
		dataClient.Add(failedAdd),
		ldap.LDAPResultUnwillingToPerform,
	)
	assertRetcodeEntryNotStored(t, store, failedAddDN)

	managedAdd := retcodeDirectoryAdd(failedAddDN, 53, "add", []ldap.Control{manage})
	managedAdd.Attribute("errText", []string{"add rejected"})
	if err := dataClient.Add(managedAdd); err != nil {
		t.Fatalf("managed Add(errObject): %v", err)
	}

	successDN := "cn=Add Success,ou=people,dc=example,dc=com"
	if err := dataClient.Add(retcodeDirectoryAdd(successDN, 0, "add", nil)); err != nil {
		t.Fatalf("Add(errCode=0): %v", err)
	}

	searchDN := "cn=Search Error,ou=people,dc=example,dc=com"
	searchEntry := retcodeDirectoryAdd(searchDN, 53, "search", []ldap.Control{manage})
	searchEntry.Attribute("errText", []string{"directory search rejected"})
	searchEntry.Attribute("errMatchedDN", []string{"ou=people,dc=example,dc=com"})
	if err := dataClient.Add(searchEntry); err != nil {
		t.Fatalf("managed Add(search errObject): %v", err)
	}
	assertRetcodeSearchResult(
		t,
		dataClient,
		searchDN,
		ldap.LDAPResultUnwillingToPerform,
		"ou=people,dc=example,dc=com",
		"directory search rejected",
	)
	_, err := dataClient.Search(ldap.NewSearchRequest(
		searchDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn", "errCode"},
		[]ldap.Control{manage},
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultUnwillingToPerform)
	_, err = dataClient.Search(ldap.NewSearchRequest(
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
	assertLDAPResultCode(t, err, ldap.LDAPResultUnwillingToPerform)
	managedSubtree, err := dataClient.Search(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(cn=Search Error)",
		[]string{"cn"},
		[]ldap.Control{manage},
	))
	if err != nil || len(managedSubtree.Entries) != 1 ||
		managedSubtree.Entries[0].DN != searchDN {
		t.Fatalf("managed subtree Search(errObject) = %#v, %v", managedSubtree, err)
	}

	modifyDN := "cn=Modify Error,ou=people,dc=example,dc=com"
	if err := dataClient.Add(retcodeDirectoryAdd(
		modifyDN,
		53,
		"modify",
		[]ldap.Control{manage},
	)); err != nil {
		t.Fatalf("managed Add(modify errObject): %v", err)
	}
	modify := ldap.NewModifyRequest(modifyDN, nil)
	modify.Replace("description", []string{"blocked"})
	assertLDAPResultCode(
		t,
		dataClient.Modify(modify),
		ldap.LDAPResultUnwillingToPerform,
	)
	modify.Controls = []ldap.Control{manage}
	modify.Replace("description", []string{"managed"})
	assertLDAPResultCode(
		t,
		dataClient.Modify(modify),
		ldap.LDAPResultUnwillingToPerform,
	)

	deleteDN := "cn=Delete Error,ou=people,dc=example,dc=com"
	if err := dataClient.Add(retcodeDirectoryAdd(
		deleteDN,
		53,
		"delete",
		[]ldap.Control{manage},
	)); err != nil {
		t.Fatalf("managed Add(delete errObject): %v", err)
	}
	assertLDAPResultCode(
		t,
		dataClient.Del(ldap.NewDelRequest(deleteDN, nil)),
		ldap.LDAPResultUnwillingToPerform,
	)
	assertLDAPResultCode(
		t,
		dataClient.Del(ldap.NewDelRequest(deleteDN, []ldap.Control{manage})),
		ldap.LDAPResultUnwillingToPerform,
	)

	compareDN := "cn=Compare True Directory,ou=people,dc=example,dc=com"
	if err := dataClient.Add(retcodeDirectoryAdd(
		compareDN,
		6,
		"compare",
		[]ldap.Control{manage},
	)); err != nil {
		t.Fatalf("managed Add(compare errObject): %v", err)
	}
	matched, err := dataClient.Compare(compareDN, "cn", "not-the-entry-value")
	if err != nil || !matched {
		t.Fatalf("in-directory Compare() = %t, %v", matched, err)
	}

	renameDN := "cn=Rename Error Directory,ou=people,dc=example,dc=com"
	if err := dataClient.Add(retcodeDirectoryAdd(
		renameDN,
		64,
		"modrdn",
		[]ldap.Control{manage},
	)); err != nil {
		t.Fatalf("managed Add(rename errObject): %v", err)
	}
	assertLDAPResultCode(
		t,
		dataClient.ModifyDN(ldap.NewModifyDNRequest(
			renameDN,
			"cn=Renamed Directory",
			true,
			"",
		)),
		ldap.LDAPResultNamingViolation,
	)

	bindDN := "cn=Bind Error Directory,ou=people,dc=example,dc=com"
	if err := dataClient.Add(retcodeDirectoryAdd(
		bindDN,
		49,
		"bind",
		[]ldap.Control{manage},
	)); err != nil {
		t.Fatalf("managed Add(bind errObject): %v", err)
	}
	bindClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(in-directory Bind): %v", err)
	}
	defer bindClient.Close()
	assertLDAPResultCode(
		t,
		bindClient.Bind(bindDN, "irrelevant"),
		ldap.LDAPResultInvalidCredentials,
	)

	auxDN := "uid=retcode-aux,ou=people,dc=example,dc=com"
	aux := ldap.NewAddRequest(auxDN, []ldap.Control{manage})
	aux.Attribute("objectClass", []string{"inetOrgPerson", "errAuxObject"})
	aux.Attribute("uid", []string{"retcode-aux"})
	aux.Attribute("cn", []string{"Retcode Auxiliary"})
	aux.Attribute("sn", []string{"Auxiliary"})
	aux.Attribute("errCode", []string{"52"})
	aux.Attribute("errOp", []string{"search"})
	if err := dataClient.Add(aux); err != nil {
		t.Fatalf("managed Add(errAuxObject): %v", err)
	}
	assertRetcodeSearchResult(
		t,
		dataClient,
		auxDN,
		ldap.LDAPResultUnavailable,
		"",
		"",
	)
}

func TestRetcodeOverlayInDirectoryPasswordModifyTransaction(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	configClient := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer configClient.Close()
	dataClient := bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer dataClient.Close()

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
		t.Fatalf("Add(in-directory transaction retcode overlay): %v", err)
	}

	targetDN := "cn=Extended Transaction Error,ou=people,dc=example,dc=com"
	target := retcodeDirectoryAdd(
		targetDN,
		53,
		"extended",
		[]ldap.Control{ldap.NewControlManageDsaIT(true)},
	)
	target.Attribute("errText", []string{"transaction password modify rejected"})
	if err := dataClient.Add(target); err != nil {
		t.Fatalf("managed Add(transaction errObject): %v", err)
	}
	_, err := requestDynamicRefresh(dataClient, targetDN, 30)
	assertLDAPResultCode(t, err, ldap.LDAPResultUnwillingToPerform)

	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer connection.Close()
	identifier := startRawLDAPTransaction(t, connection, 2)
	passwordValue := rawRetcodePasswordModifyRequestValue(
		[]byte(targetDN),
		[]byte("replacement"),
	)
	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			3,
			rawExtendedRequest(passwordModifyOID, passwordValue, true),
			rawTransactionSpecificationControl(identifier, true, true),
		),
		int64(ldapwire.ResultSuccess),
	)

	response := endRawLDAPTransaction(t, connection, 4, true, identifier)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultUnwillingToPerform))
	value, present := rawExtendedResponseValue(response)
	if !present {
		t.Fatal("failed retcode transaction response value is absent")
	}
	decoded, err := ldapwire.DecodeTransactionEndResponseValue(value)
	if err != nil {
		t.Fatalf("DecodeTransactionEndResponseValue(): %v", err)
	}
	if !decoded.HasFailedMessageID || decoded.FailedMessageID != 3 {
		t.Fatalf("transaction end response = %#v, want failed message ID 3", decoded)
	}
}

func TestRetcodeOverlayInDirectoryWireResponses(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	configClient := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer configClient.Close()
	dataClient := bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer dataClient.Close()
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
		t.Fatalf("Add(in-directory wire retcode overlay): %v", err)
	}

	manage := []ldap.Control{ldap.NewControlManageDsaIT(true)}
	unsolicitedDN := "cn=Directory Unsolicited,ou=people,dc=example,dc=com"
	unsolicited := retcodeDirectoryAdd(unsolicitedDN, 53, "search", manage)
	unsolicited.Attribute("errUnsolicitedOID", []string{"1.2.3.4"})
	unsolicited.Attribute("errUnsolicitedData", []string{"directory-payload"})
	preDisconnectDN := "cn=Directory Pre Disconnect,ou=people,dc=example,dc=com"
	preDisconnect := retcodeDirectoryAdd(preDisconnectDN, 53, "search", manage)
	preDisconnect.Attribute("errDisconnect", []string{"TRUE"})
	postDisconnectDN := "cn=Directory Post Disconnect,ou=people,dc=example,dc=com"
	postDisconnect := retcodeDirectoryAdd(postDisconnectDN, 53, "search", manage)
	postDisconnect.Attribute("errDisconnect", []string{"FALSE"})
	for _, add := range []*ldap.AddRequest{
		unsolicited,
		preDisconnect,
		postDisconnect,
	} {
		if err := dataClient.Add(add); err != nil {
			t.Fatalf("managed Add(%s): %v", add.DN, err)
		}
	}

	t.Run("unsolicited", func(t *testing.T) {
		connection := dialAndBindRawLDAP(
			t,
			address,
			"cn=admin,dc=example,dc=com",
			"admin-secret",
		)
		defer connection.Close()
		writeRawLDAPRequest(
			t,
			connection,
			2,
			rawRetcodeSearchRequest(t, unsolicitedDN),
		)
		response, err := ber.ReadPacket(connection)
		if err != nil {
			t.Fatalf("read in-directory unsolicited response: %v", err)
		}
		assertRetcodeWireResponse(
			t,
			response,
			0,
			ldapwire.ApplicationExtendedResponse,
			ldap.LDAPResultUnwillingToPerform,
		)
		operation := response.Children[1]
		if len(operation.Children) != 5 ||
			operation.Children[3].Data.String() != "1.2.3.4" ||
			operation.Children[4].Data.String() != "directory-payload" {
			t.Fatalf("unexpected in-directory unsolicited response: %#v", operation)
		}
	})

	t.Run("pre disconnect", func(t *testing.T) {
		connection := dialAndBindRawLDAP(
			t,
			address,
			"cn=admin,dc=example,dc=com",
			"admin-secret",
		)
		defer connection.Close()
		writeRawLDAPRequest(
			t,
			connection,
			2,
			rawRetcodeSearchRequest(t, preDisconnectDN),
		)
		assertRetcodeConnectionClosed(t, connection)
	})

	t.Run("post disconnect", func(t *testing.T) {
		connection := dialAndBindRawLDAP(
			t,
			address,
			"cn=admin,dc=example,dc=com",
			"admin-secret",
		)
		defer connection.Close()
		writeRawLDAPRequest(
			t,
			connection,
			2,
			rawRetcodeSearchRequest(t, postDisconnectDN),
		)
		response, err := ber.ReadPacket(connection)
		if err != nil {
			t.Fatalf("read in-directory post-disconnect response: %v", err)
		}
		assertRetcodeWireResponse(
			t,
			response,
			2,
			ldapwire.ApplicationSearchResultDone,
			ldap.LDAPResultUnwillingToPerform,
		)
		assertRetcodeConnectionClosed(t, connection)
	})
}

func retcodeDirectoryAdd(
	dn string,
	code int,
	operation string,
	controls []ldap.Control,
) *ldap.AddRequest {
	parsedDN, err := directory.ParseDN(dn)
	if err != nil || len(parsedDN.RDNValues()) == 0 {
		panic("invalid retcode test DN: " + dn)
	}
	request := ldap.NewAddRequest(dn, controls)
	request.Attribute("objectClass", []string{"errObject"})
	request.Attribute("cn", []string{string(parsedDN.RDNValues()[0].Value)})
	request.Attribute("errCode", []string{strconv.Itoa(code)})
	request.Attribute("errOp", []string{operation})
	return request
}

func rawRetcodeSearchRequest(t *testing.T, baseDN string) *ber.Packet {
	t.Helper()
	return rawSyncSearchRequestFor(
		t,
		baseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		"(objectClass=*)",
	)
}

func rawRetcodePasswordModifyRequestValue(
	identity, newPassword []byte,
) []byte {
	value := ber.NewSequence("PasswordModifyRequestValue")
	for _, elementValue := range []struct {
		tag   ber.Tag
		value []byte
	}{
		{tag: 0, value: identity},
		{tag: 2, value: newPassword},
	} {
		element := ber.Encode(
			ber.ClassContext,
			ber.TypePrimitive,
			elementValue.tag,
			nil,
			"password modify value",
		)
		_, _ = element.Data.Write(elementValue.value)
		value.AppendChild(element)
	}
	return value.Bytes()
}

func assertRetcodeWireResponse(
	t *testing.T,
	response *ber.Packet,
	wantMessageID int64,
	wantApplicationTag uint64,
	wantResultCode uint16,
) {
	t.Helper()
	if response == nil || len(response.Children) < 2 {
		t.Fatalf("malformed LDAP response: %#v", response)
	}
	messageID, err := ber.ParseInt64(response.Children[0].Data.Bytes())
	if err != nil {
		t.Fatalf("parse LDAP message ID: %v", err)
	}
	operation := response.Children[1]
	if messageID != wantMessageID || uint64(operation.Tag) != wantApplicationTag {
		t.Fatalf(
			"LDAP response id/tag = %d/%d, want %d/%d",
			messageID,
			operation.Tag,
			wantMessageID,
			wantApplicationTag,
		)
	}
	assertRawLDAPResult(t, response, int64(wantResultCode))
}

func assertRetcodeConnectionClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	packet, err := ber.ReadPacket(connection)
	if err == nil {
		t.Fatalf("connection remained open and returned %#v", packet)
	}
	if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		t.Fatalf("connection was not closed: %v", err)
	}
}

func retcodeLifecycleItems(searchCode int) []string {
	return []string{
		`{0}"cn=Time Limit" "` + strconv.Itoa(searchCode) +
			`" "op=search" "text=search delayed" ` +
			`"matched=dc=example,dc=com"`,
		`{1}"cn=Unwilling" "53" "op=delete,modify"`,
		`{2}"cn=Compare True" "6" "op=compare"`,
		`{3}"cn=Success" "0" "op=add"`,
		`{4}"cn=Search Only" "4" "op=search"`,
		`{5}"cn=Referral" "10" "op=search" ` +
			`"ref=ldap://remote.example"`,
		`{6}"cn=Bind Denied" "49" "op=bind" "text=denied"`,
		`{7}"cn=Rename" "64" "op=rename"`,
		`{8}"cn=Extended" "53" "op=extended"`,
		`{9}"cn=Bind Success" "0" "op=bind"`,
	}
}

func assertRetcodeBind(t *testing.T, address string) {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(retcode Bind): %v", err)
	}
	defer client.Close()
	assertLDAPResultCode(
		t,
		client.Bind(
			"cn=Bind Denied,ou=RetCodes,dc=example,dc=com",
			"irrelevant",
		),
		ldap.LDAPResultInvalidCredentials,
	)
}

func assertRetcodeSuccessfulBind(t *testing.T, address string) {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(successful retcode Bind): %v", err)
	}
	defer client.Close()
	const dn = "cn=Bind Success,ou=RetCodes,dc=example,dc=com"
	if err := client.Bind(dn, "irrelevant"); err != nil {
		t.Fatalf("successful retcode Bind(): %v", err)
	}
	identity, err := client.WhoAmI(nil)
	if err != nil || identity.AuthzID != "dn:"+dn {
		t.Fatalf("successful retcode Bind identity = %#v, %v", identity, err)
	}
}

func assertRetcodeSearchResult(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	wantCode uint16,
	wantMatched,
	wantDiagnostic string,
) {
	t.Helper()
	_, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"*"},
		nil,
	))
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != wantCode ||
		ldapErr.MatchedDN != wantMatched {
		t.Fatalf(
			"Search(%s) error = %#v, want code=%d matched=%q",
			dn,
			err,
			wantCode,
			wantMatched,
		)
	}
	if wantDiagnostic != "" && !strings.Contains(err.Error(), wantDiagnostic) {
		t.Fatalf("Search(%s) error = %v, want diagnostic %q", dn, err, wantDiagnostic)
	}
}

func assertRetcodeSyntheticList(t *testing.T, client *ldap.Conn) {
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
	if err != nil || len(result.Entries) != 3 {
		t.Fatalf("retcode list Search() = %#v, %v", result, err)
	}
	for _, entry := range result.Entries {
		if entry.GetAttributeValue("cn") == "" ||
			entry.GetAttributeValue("errCode") == "" ||
			!containsString(entry.GetAttributeValues("errOp"), "search") {
			t.Fatalf("retcode synthetic entry = %#v", entry)
		}
	}
}

func assertRetcodeReferral(t *testing.T, client *ldap.Conn) {
	t.Helper()
	_, err := client.Search(ldap.NewSearchRequest(
		"cn=Referral,ou=RetCodes,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		nil,
		nil,
	))
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) ||
		ldapErr.ResultCode != ldap.LDAPResultReferral {
		t.Fatalf("retcode referral error = %#v", err)
	}
	referrals := ldapResultReferrals(ldapErr.Packet)
	if len(referrals) != 1 ||
		!strings.Contains(referrals[0], "cn=Referral,ou=RetCodes") {
		t.Fatalf("retcode referrals = %q", referrals)
	}
}

func assertRetcodeEntryNotStored(
	t *testing.T,
	store storage.Store,
	rawDN string,
) {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%s): %v", rawDN, err)
	}
	err = store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Get(dn)
		return err
	})
	if !errors.Is(err, storage.ErrEntryNotFound) {
		t.Fatalf("stored synthetic entry error = %v", err)
	}
}
