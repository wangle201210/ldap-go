package server

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPMetaDynamicDatabaseDN = "olcDatabase={2}meta,cn=config"
	openLDAPMetaDynamicTargetDN   = "olcMetaSub={0}uri," + openLDAPMetaDynamicDatabaseDN
	openLDAPMetaDynamicUID        = "dynamic-route"
)

type openLDAPMetaDynamicStep struct {
	configCode uint16
	search     openLDAPMetaSearchObservation
}

type openLDAPMetaDynamicSameURIOutcome struct {
	databaseAddCode uint16
	targetAdd       openLDAPMetaDynamicStep
	uriModify       openLDAPMetaDynamicStep
}

type openLDAPMetaDynamicOutcome struct {
	sameURIReplace  openLDAPMetaDynamicSameURIOutcome
	databaseAddCode uint16
	targetAdd       openLDAPMetaDynamicStep
	uriModify       openLDAPMetaDynamicStep
	targetDelete    openLDAPMetaDynamicStep
	targetReadd     openLDAPMetaDynamicStep
}

type openLDAPMetaDynamicTopologyOutcome struct {
	databaseAddCode         uint16
	leftAddCode             uint16
	rightAddCode            uint16
	leftBefore              openLDAPMetaSearchObservation
	rightBefore             openLDAPMetaSearchObservation
	mutationDatabaseAddCode uint16
	mutationLeftAddCode     uint16
	mutationRightAddCode    uint16
	rightModifyCode         uint16
	leftAfter               openLDAPMetaSearchObservation
	rightAfter              openLDAPMetaSearchObservation
	rightDeleteCode         uint16
	leftAfterDelete         openLDAPMetaSearchObservation
}

func TestOpenLDAPReferenceMetaDynamicTargetLifecycle(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	var reference openLDAPMetaDynamicOutcome
	t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
		reference = runOpenLDAPMetaDynamicTargetLifecycle(t, tools, false)
		assertOpenLDAPMetaDynamicTargetReference(t, reference)
	})
	if t.Failed() {
		return
	}

	t.Run("ldap-go differential", func(t *testing.T) {
		got := runOpenLDAPMetaDynamicTargetLifecycle(t, tools, true)
		if !reflect.DeepEqual(got, reference) {
			t.Fatalf(
				"ldap-go online back-meta target lifecycle differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
				reference,
				got,
			)
		}
	})
}

func TestOpenLDAPReferenceMetaDynamicMultiTargetTopology(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	var reference openLDAPMetaDynamicTopologyOutcome
	t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
		reference = runOpenLDAPMetaDynamicMultiTargetTopology(t, tools, false)
		assertOpenLDAPMetaDynamicTopologyReference(t, reference)
	})
	if t.Failed() {
		return
	}
	t.Run("ldap-go differential", func(t *testing.T) {
		got := runOpenLDAPMetaDynamicMultiTargetTopology(t, tools, true)
		if !reflect.DeepEqual(got, reference) {
			t.Fatalf(
				"ldap-go online multi-target topology differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
				reference,
				got,
			)
		}
	})
}

func runOpenLDAPMetaDynamicMultiTargetTopology(
	t *testing.T,
	tools openLDAPReferenceTools,
	ldapGo bool,
) openLDAPMetaDynamicTopologyOutcome {
	t.Helper()
	const (
		leftUID   = "dynamic-left"
		rightUID  = "dynamic-right"
		leftBase  = "ou=left," + openLDAPMetaBaseDN
		rightBase = "ou=right," + openLDAPMetaBaseDN
	)
	leftURI, _ := startOpenLDAPMetaProvider(t, tools, leftUID, "dynamic-left")
	rightURI, _ := startOpenLDAPMetaProvider(t, tools, rightUID, "dynamic-right")
	replacementURI, _ := startOpenLDAPMetaProvider(
		t,
		tools,
		rightUID,
		"dynamic-right-replacement",
	)

	startProxy := func() (string, func()) {
		if ldapGo {
			return startLDAPGoMetaDynamicProxy(t)
		}
		return startOpenLDAPMetaDynamicProxy(t, tools)
	}

	proxyURI, stopProxy := startProxy()
	config := bindOpenLDAPMetaDynamicConfig(t, proxyURI)
	leftDN := "uid=" + leftUID + ",ou=people," + leftBase
	rightDN := "uid=" + rightUID + ",ou=people," + rightBase
	outcome := openLDAPMetaDynamicTopologyOutcome{
		databaseAddCode: monitorLDAPResultCode(config.Add(openLDAPMetaDynamicDatabaseAdd())),
		leftAddCode: monitorLDAPResultCode(config.Add(
			openLDAPMetaDynamicTopologyTargetAdd(0, leftURI, leftBase),
		)),
		rightAddCode: monitorLDAPResultCode(config.Add(
			openLDAPMetaDynamicTopologyTargetAdd(1, rightURI, rightBase),
		)),
	}
	outcome.leftBefore = observeOpenLDAPMetaDynamicDN(t, proxyURI, leftDN)
	outcome.rightBefore = observeOpenLDAPMetaDynamicDN(t, proxyURI, rightDN)
	config.Close()
	stopProxy()

	// OpenLDAP 2.6.13 aborts in back-meta/conn.c when a target URI is
	// changed after a multi-target metaconn has been created. Use a fresh
	// proxy to compare the supported pre-connection configuration path.
	proxyURI, stopProxy = startProxy()
	defer stopProxy()
	config = bindOpenLDAPMetaDynamicConfig(t, proxyURI)
	defer config.Close()
	outcome.mutationDatabaseAddCode = monitorLDAPResultCode(
		config.Add(openLDAPMetaDynamicDatabaseAdd()),
	)
	outcome.mutationLeftAddCode = monitorLDAPResultCode(config.Add(
		openLDAPMetaDynamicTopologyTargetAdd(0, leftURI, leftBase),
	))
	outcome.mutationRightAddCode = monitorLDAPResultCode(config.Add(
		openLDAPMetaDynamicTopologyTargetAdd(1, rightURI, rightBase),
	))

	rightTargetDN := openLDAPMetaDynamicTargetDNForOrder(1)
	modifyURI := ldap.NewModifyRequest(rightTargetDN, nil)
	modifyURI.Replace("olcDbURI", []string{replacementURI + "/" + rightBase})
	outcome.rightModifyCode = monitorLDAPResultCode(config.Modify(modifyURI))
	outcome.leftAfter = observeOpenLDAPMetaDynamicDN(t, proxyURI, leftDN)
	outcome.rightAfter = observeOpenLDAPMetaDynamicDN(t, proxyURI, rightDN)
	outcome.rightDeleteCode = monitorLDAPResultCode(config.Del(
		ldap.NewDelRequest(rightTargetDN, nil),
	))
	outcome.leftAfterDelete = observeOpenLDAPMetaDynamicDN(t, proxyURI, leftDN)
	return outcome
}

func assertOpenLDAPMetaDynamicTopologyReference(
	t *testing.T,
	got openLDAPMetaDynamicTopologyOutcome,
) {
	t.Helper()
	left := openLDAPMetaSearchObservation{
		code:        ldap.LDAPResultSuccess,
		dn:          "uid=dynamic-left,ou=people,ou=left," + openLDAPMetaBaseDN,
		description: "dynamic-left",
	}
	want := openLDAPMetaDynamicTopologyOutcome{
		databaseAddCode: ldap.LDAPResultSuccess,
		leftAddCode:     ldap.LDAPResultSuccess,
		rightAddCode:    ldap.LDAPResultSuccess,
		leftBefore:      left,
		rightBefore: openLDAPMetaSearchObservation{
			code:        ldap.LDAPResultSuccess,
			dn:          "uid=dynamic-right,ou=people,ou=right," + openLDAPMetaBaseDN,
			description: "dynamic-right",
		},
		mutationDatabaseAddCode: ldap.LDAPResultSuccess,
		mutationLeftAddCode:     ldap.LDAPResultSuccess,
		mutationRightAddCode:    ldap.LDAPResultSuccess,
		rightModifyCode:         ldap.LDAPResultSuccess,
		leftAfter:               left,
		rightAfter: openLDAPMetaSearchObservation{
			code: ldap.LDAPResultNoSuchObject,
		},
		rightDeleteCode: ldap.LDAPResultUnwillingToPerform,
		leftAfterDelete: left,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("OpenLDAP multi-target topology fixture drifted:\n got: %#v\nwant: %#v", got, want)
	}
}

func runOpenLDAPMetaDynamicTargetLifecycle(
	t *testing.T,
	tools openLDAPReferenceTools,
	ldapGo bool,
) openLDAPMetaDynamicOutcome {
	t.Helper()

	sameURIReplace := runOpenLDAPMetaDynamicSameURIReplace(t, tools, ldapGo)

	firstURI, _ := startOpenLDAPMetaProvider(
		t,
		tools,
		openLDAPMetaDynamicUID,
		"dynamic-first",
	)
	secondURI, _ := startOpenLDAPMetaProvider(
		t,
		tools,
		openLDAPMetaDynamicUID,
		"dynamic-second",
	)
	readdedURI, _ := startOpenLDAPMetaProvider(
		t,
		tools,
		openLDAPMetaDynamicUID,
		"dynamic-readded",
	)

	var proxyURI string
	var stopProxy func()
	if ldapGo {
		proxyURI, stopProxy = startLDAPGoMetaDynamicProxy(t)
	} else {
		proxyURI, stopProxy = startOpenLDAPMetaDynamicProxy(t, tools)
	}
	defer stopProxy()

	config := bindOpenLDAPMetaDynamicConfig(t, proxyURI)
	defer config.Close()

	outcome := openLDAPMetaDynamicOutcome{
		sameURIReplace: sameURIReplace,
		databaseAddCode: monitorLDAPResultCode(config.Add(
			openLDAPMetaDynamicDatabaseAdd(),
		)),
	}
	outcome.targetAdd = openLDAPMetaDynamicStep{
		configCode: monitorLDAPResultCode(config.Add(
			openLDAPMetaDynamicTargetAdd(firstURI),
		)),
		search: observeOpenLDAPMetaDynamicSearch(t, proxyURI),
	}

	modifyURI := ldap.NewModifyRequest(openLDAPMetaDynamicTargetDN, nil)
	modifyURI.Replace("olcDbURI", []string{
		secondURI + "/" + openLDAPMetaBaseDN,
	})
	outcome.uriModify = openLDAPMetaDynamicStep{
		configCode: monitorLDAPResultCode(config.Modify(modifyURI)),
		search:     observeOpenLDAPMetaDynamicSearch(t, proxyURI),
	}

	outcome.targetDelete = openLDAPMetaDynamicStep{
		configCode: monitorLDAPResultCode(config.Del(
			ldap.NewDelRequest(openLDAPMetaDynamicTargetDN, nil),
		)),
		search: observeOpenLDAPMetaDynamicSearch(t, proxyURI),
	}

	outcome.targetReadd = openLDAPMetaDynamicStep{
		configCode: monitorLDAPResultCode(config.Add(
			openLDAPMetaDynamicTargetAdd(readdedURI),
		)),
		search: observeOpenLDAPMetaDynamicSearch(t, proxyURI),
	}
	return outcome
}

func runOpenLDAPMetaDynamicSameURIReplace(
	t *testing.T,
	tools openLDAPReferenceTools,
	ldapGo bool,
) openLDAPMetaDynamicSameURIOutcome {
	t.Helper()

	providerURI, _ := startOpenLDAPMetaProvider(
		t,
		tools,
		openLDAPMetaDynamicUID,
		"dynamic-same",
	)
	var proxyURI string
	var stopProxy func()
	if ldapGo {
		proxyURI, stopProxy = startLDAPGoMetaDynamicProxy(t)
	} else {
		proxyURI, stopProxy = startOpenLDAPMetaDynamicProxy(t, tools)
	}
	defer stopProxy()

	config := bindOpenLDAPMetaDynamicConfig(t, proxyURI)
	defer config.Close()
	outcome := openLDAPMetaDynamicSameURIOutcome{
		databaseAddCode: monitorLDAPResultCode(config.Add(
			openLDAPMetaDynamicDatabaseAdd(),
		)),
	}
	outcome.targetAdd = openLDAPMetaDynamicStep{
		configCode: monitorLDAPResultCode(config.Add(
			openLDAPMetaDynamicTargetAdd(providerURI),
		)),
		search: observeOpenLDAPMetaDynamicSearch(t, proxyURI),
	}
	sameURI := ldap.NewModifyRequest(openLDAPMetaDynamicTargetDN, nil)
	sameURI.Replace("olcDbURI", []string{
		providerURI + "/" + openLDAPMetaBaseDN,
	})
	outcome.uriModify = openLDAPMetaDynamicStep{
		configCode: monitorLDAPResultCode(config.Modify(sameURI)),
		search:     observeOpenLDAPMetaDynamicSearch(t, proxyURI),
	}
	return outcome
}

func assertOpenLDAPMetaDynamicTargetReference(
	t *testing.T,
	got openLDAPMetaDynamicOutcome,
) {
	t.Helper()
	successfulSearch := openLDAPMetaSearchObservation{
		code:        ldap.LDAPResultSuccess,
		dn:          strings.ToLower(openLDAPMetaDynamicEntryDN()),
		description: "dynamic-first",
	}
	missingSearch := openLDAPMetaSearchObservation{
		code: ldap.LDAPResultNoSuchObject,
	}
	want := openLDAPMetaDynamicOutcome{
		sameURIReplace: openLDAPMetaDynamicSameURIOutcome{
			databaseAddCode: ldap.LDAPResultSuccess,
			targetAdd: openLDAPMetaDynamicStep{
				configCode: ldap.LDAPResultSuccess,
				search: openLDAPMetaSearchObservation{
					code:        ldap.LDAPResultSuccess,
					dn:          strings.ToLower(openLDAPMetaDynamicEntryDN()),
					description: "dynamic-same",
				},
			},
			uriModify: openLDAPMetaDynamicStep{
				configCode: ldap.LDAPResultSuccess,
				search:     missingSearch,
			},
		},
		databaseAddCode: ldap.LDAPResultSuccess,
		targetAdd: openLDAPMetaDynamicStep{
			configCode: ldap.LDAPResultSuccess,
			search:     successfulSearch,
		},
		uriModify: openLDAPMetaDynamicStep{
			configCode: ldap.LDAPResultSuccess,
			search:     missingSearch,
		},
		// OpenLDAP 2.6.13 exposes no online delete handler for meta targets.
		targetDelete: openLDAPMetaDynamicStep{
			configCode: ldap.LDAPResultUnwillingToPerform,
			search:     missingSearch,
		},
		targetReadd: openLDAPMetaDynamicStep{
			configCode: ldap.LDAPResultEntryAlreadyExists,
			search:     missingSearch,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"OpenLDAP online back-meta target fixture drifted:\n got: %#v\nwant: %#v",
			got,
			want,
		)
	}
}

func observeOpenLDAPMetaDynamicSearch(
	t *testing.T,
	proxyURI string,
) openLDAPMetaSearchObservation {
	return observeOpenLDAPMetaDynamicDN(t, proxyURI, openLDAPMetaDynamicEntryDN())
}

func observeOpenLDAPMetaDynamicDN(
	t *testing.T,
	proxyURI string,
	dn string,
) openLDAPMetaSearchObservation {
	t.Helper()
	client, err := ldap.DialURL(proxyURI)
	if err != nil {
		return openLDAPMetaSearchObservation{code: ldap.ErrorNetwork}
	}
	defer client.Close()
	client.SetTimeout(5 * time.Second)
	return searchOpenLDAPMetaEntry(t, client, dn)
}

func bindOpenLDAPMetaDynamicConfig(t *testing.T, uri string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial online back-meta configuration %s: %v", uri, err)
	}
	client.SetTimeout(5 * time.Second)
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		client.Close()
		t.Fatalf("bind online back-meta configuration: %v", err)
	}
	return client
}

func openLDAPMetaDynamicDatabaseAdd() *ldap.AddRequest {
	request := ldap.NewAddRequest(openLDAPMetaDynamicDatabaseDN, nil)
	request.Attribute("objectClass", []string{
		"olcDatabaseConfig",
		"olcMetaConfig",
	})
	request.Attribute("olcDatabase", []string{"{2}meta"})
	request.Attribute("olcSuffix", []string{openLDAPMetaBaseDN})
	request.Attribute("olcRootDN", []string{"cn=admin," + openLDAPMetaBaseDN})
	request.Attribute("olcRootPW", []string{"secret"})
	return request
}

func openLDAPMetaDynamicTargetAdd(providerURI string) *ldap.AddRequest {
	request := ldap.NewAddRequest(openLDAPMetaDynamicTargetDN, nil)
	request.Attribute("objectClass", []string{"olcMetaTargetConfig"})
	request.Attribute("olcMetaSub", []string{"{0}uri"})
	request.Attribute("olcDbURI", []string{
		providerURI + "/" + openLDAPMetaBaseDN,
	})
	request.Attribute("olcDbRewrite", []string{
		`suffixmassage "` + openLDAPMetaBaseDN + `" "dc=example,dc=com"`,
	})
	request.Attribute("olcDbIDAssertBind", []string{
		`bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none`,
	})
	request.Attribute("olcDbIDAssertAuthzFrom", []string{"*"})
	return request
}

func openLDAPMetaDynamicTopologyTargetAdd(
	order int,
	providerURI string,
	localBase string,
) *ldap.AddRequest {
	marker := fmt.Sprintf("{%d}uri", order)
	request := ldap.NewAddRequest(openLDAPMetaDynamicTargetDNForOrder(order), nil)
	request.Attribute("objectClass", []string{"olcMetaTargetConfig"})
	request.Attribute("olcMetaSub", []string{marker})
	request.Attribute("olcDbURI", []string{providerURI + "/" + localBase})
	request.Attribute("olcDbRewrite", []string{
		`suffixmassage "` + localBase + `" "dc=example,dc=com"`,
	})
	return request
}

func openLDAPMetaDynamicTargetDNForOrder(order int) string {
	return fmt.Sprintf(
		"olcMetaSub={%d}uri,%s",
		order,
		openLDAPMetaDynamicDatabaseDN,
	)
}

func openLDAPMetaDynamicEntryDN() string {
	return "uid=" + openLDAPMetaDynamicUID + ",ou=people," + openLDAPMetaBaseDN
}

func startOpenLDAPMetaDynamicProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
) (string, func()) {
	t.Helper()
	return startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		`database config
rootdn "cn=config"
rootpw config-secret
access to * by * manage`,
		"",
		"",
	)
}

func startLDAPGoMetaDynamicProxy(t *testing.T) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoMetaDynamicConfiguration(t, store)
	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, stop
}

func seedLDAPGoMetaDynamicConfiguration(t *testing.T, store storage.Store) {
	t.Helper()
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
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=placeholder,dc=test")},
				{Description: "olcRootDN", Values: stringValues("cn=admin,dc=placeholder,dc=test")},
				{Description: "olcRootPW", Values: stringValues("secret")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{
			"dc=placeholder,dc=test",
			"cn=config",
		})
	}); err != nil {
		t.Fatalf("seed ldap-go online back-meta configuration: %v", err)
	}
}
