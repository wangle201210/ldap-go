package server

import (
	"context"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type monitoringObservation struct {
	code          uint16
	values        []string
	databases     []string
	context       string
	mdbRegistered bool
	countPresent  bool
	overlays      []string
}

func TestOpenLDAPReferenceDatabaseMonitoring(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	version, err := exec.Command(tools.slapd, "-VV").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "slapd 2.6.13 ") {
		t.Fatalf("requires OpenLDAP 2.6.13: %v\n%s", err, version)
	}
	for _, initial := range []string{"", "TRUE", "FALSE"} {
		t.Run("startup="+initial, func(t *testing.T) {
			directive := ""
			overlays := ""
			if initial != "" {
				directive = "monitoring " + initial + "\n"
				overlays = "overlay syncprov\noverlay seqmod\n"
			}
			uri, stop := startOpenLDAPReferenceServerWithConfig(t, tools, nil,
				"database config\nrootdn cn=config\nrootpw config-secret",
				directive+overlays+"database monitor\naccess to * by * read", "")
			defer stop()
			reference := observeDatabaseMonitoring(t, uri)
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedOnlineConfiguration(t, store)
			seedMonitorConfiguration(t, store)
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				if overlays != "" {
					if err := writer.Put(directory.Entry{
						DN: "olcOverlay={1}seqmod,olcDatabase={1}mdb,cn=config",
						Attributes: []directory.Attribute{
							{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
							{Description: "olcOverlay", Values: stringValues("{1}seqmod")},
						},
					}, false); err != nil {
						return err
					}
					if err := writer.Put(directory.Entry{
						DN: "olcOverlay={0}syncprov,olcDatabase={1}mdb,cn=config",
						Attributes: []directory.Attribute{
							{Description: "objectClass", Values: stringValues("olcSyncProvConfig")},
							{Description: "olcOverlay", Values: stringValues("{0}syncprov")},
						},
					}, false); err != nil {
						return err
					}
				}
				return writer.Put(directory.Entry{
					DN: "olcDatabase={-1}frontend,cn=config",
					Attributes: []directory.Attribute{
						{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcFrontendConfig")},
						{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
					},
				}, false)
			}); err != nil {
				t.Fatal(err)
			}
			// slapd.conf conversion emits the backend defaults in cn=config.
			for _, target := range monitoringConfigDNs {
				value := "FALSE"
				if strings.Contains(target, "mdb") {
					value = "TRUE"
					if initial != "" {
						value = initial
					}
				}
				setMonitoringValues(t, store, target, value)
			}
			_, address, stopGo := startConfigurationCapabilityServer(t, store)
			defer stopGo()
			implementation := observeDatabaseMonitoring(t, "ldap://"+address)
			if !reflect.DeepEqual(reference, implementation) {
				for index := range reference {
					if !reflect.DeepEqual(reference[index], implementation[index]) {
						t.Fatalf("step %d:\nOpenLDAP: %#v\nldap-go:  %#v", index, reference[index], implementation[index])
					}
				}
			}
		})
	}
}

var monitoringConfigDNs = []string{
	"olcDatabase={-1}frontend,cn=config",
	"olcDatabase={0}config,cn=config",
	"olcDatabase={1}mdb,cn=config",
	"olcDatabase={2}monitor,cn=config",
}

func observeDatabaseMonitoring(t *testing.T, uri string) []monitoringObservation {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	observe := func(code uint16) monitoringObservation {
		t.Helper()
		result := monitoringObservation{code: code}
		for _, dn := range monitoringConfigDNs {
			entry := monitorSearch(t, client, dn, ldap.ScopeBaseObject, "(objectClass=*)", []string{"olcMonitoring"}).Entries[0]
			result.values = append(result.values, strings.Join(entry.GetAttributeValues("olcMonitoring"), ","))
		}
		result.context = monitorSearch(t, client, "", ldap.ScopeBaseObject, "(objectClass=*)", []string{"monitorContext"}).Entries[0].GetAttributeValue("monitorContext")
		entries := monitorSearch(t, client, "cn=Databases,cn=Monitor", ldap.ScopeSingleLevel, "(objectClass=*)", []string{"cn", "namingContexts", "monitorContext", "objectClass", "olmMDBEntries"})
		for _, entry := range entries.Entries {
			result.databases = append(result.databases, entry.DN+"|"+entry.GetAttributeValue("namingContexts")+"|"+entry.GetAttributeValue("monitorContext"))
			if entry.GetAttributeValue("cn") == "Database 1" {
				result.mdbRegistered = ldapEntryHasValue(entry, "objectClass", "olmMDBDatabase")
				count := entry.GetAttributeValue("olmMDBEntries")
				result.countPresent = count != ""
				if count != "" {
					content := monitorSearch(t, client, "dc=example,dc=com", ldap.ScopeWholeSubtree, "(objectClass=*)", []string{"1.1"})
					if count != strconv.Itoa(len(content.Entries)) {
						t.Fatalf("%s: monitor entry count %s != content count %d", uri, count, len(content.Entries))
					}
					matched, err := client.Compare(entry.DN, "olmMDBEntries", count)
					if err != nil || !matched {
						t.Fatalf("compare monitor count: %t, %v", matched, err)
					}
				}
			}
		}
		sort.Strings(result.databases)
		overlays := monitorSearch(t, client, "cn=Database 1,cn=Databases,cn=Monitor", ldap.ScopeSingleLevel, "(objectClass=*)", []string{"monitoredInfo", "namingContexts"})
		for _, entry := range overlays.Entries {
			result.overlays = append(result.overlays, entry.DN+"|"+entry.GetAttributeValue("monitoredInfo")+"|"+entry.GetAttributeValue("namingContexts"))
		}
		sort.Strings(result.overlays)
		return result
	}
	results := []monitoringObservation{observe(0)}
	for _, target := range monitoringConfigDNs {
		for _, step := range []struct {
			operation string
			values    []string
		}{
			{"replace", []string{"FALSE"}},
			{"replace", []string{"TRUE"}},
			{"replace", []string{"MAYBE"}},
			{"replace", []string{"FALSE", "TRUE"}},
			{"replace", []string{"TRUE", "TRUE"}},
			{"transient-invalid", nil},
			{"replace", []string{"false"}},
			{"replace", []string{" TRUE"}},
			{"delete", []string{"FALSE"}},
			{"delete", nil},
			{"delete", nil},
			{"unrelated", nil},
			{"add", []string{"TRUE"}},
			{"add", []string{"TRUE"}},
			{"add", []string{"FALSE"}},
			{"rollback", nil},
			{"replace", nil},
		} {
			request := ldap.NewModifyRequest(target, nil)
			switch step.operation {
			case "replace":
				request.Replace("olcMonitoring", step.values)
			case "add":
				request.Add("olcMonitoring", step.values)
			case "delete":
				request.Delete("olcMonitoring", step.values)
			case "unrelated":
				request = ldap.NewModifyRequest("cn=config", nil)
				request.Replace("olcLogLevel", []string{"0"})
			case "rollback":
				request.Replace("olcMonitoring", []string{"FALSE"})
				request.Delete("description", []string{"not-present"})
			case "transient-invalid":
				request.Replace("olcMonitoring", []string{"TRUE", "FALSE"})
				request.Replace("olcMonitoring", []string{"TRUE"})
			default:
				t.Fatalf("unknown step %s", step.operation)
			}
			code := monitorLDAPResultCode(client.Modify(request))
			results = append(results, observe(code))
		}
	}
	wrongEntry := ldap.NewModifyRequest("cn=config", nil)
	for _, change := range []struct{ attribute, value string }{
		{"olcMonitoring", "TRUE"},
		{"olcDisabled", "TRUE"},
		{"olcDisabled", "FALSE"},
		{"olcMonitoring", "FALSE"},
		{"olcDisabled", "TRUE"},
		{"olcDisabled", "FALSE"},
	} {
		request := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
		request.Replace(change.attribute, []string{change.value})
		results = append(results, observe(monitorLDAPResultCode(client.Modify(request))))
	}
	wrongEntry.Replace("olcMonitoring", []string{"TRUE"})
	results = append(results, observe(monitorLDAPResultCode(client.Modify(wrongEntry))))
	return results
}
