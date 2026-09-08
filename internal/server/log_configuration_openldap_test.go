package server

import (
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceLogFileSyntaxAndFormats(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	reference := startOpenLDAPDynamicConfigReferralServer(t, tools)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	instance, address, stop := startMonitorLogRoutingServer(t, store, nil)
	defer stop()
	servers := []struct {
		uri    string
		logger *slog.Logger
	}{{reference, nil}, {"ldap://" + address, instance.config.Logger}}
	type outcome struct {
		codes  []uint16
		values [][]string
	}
	var observations []outcome
	for _, server := range servers {
		client, err := ldap.DialURL(server.uri)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		client.SetTimeout(5 * time.Second)
		if err := client.Bind("cn=config", "config-secret"); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "slapd.log")
		request := ldap.NewModifyRequest("cn=config", nil)
		request.Replace("olcLogFile", []string{path})
		request.Replace("olcLogFileOnly", []string{"TRUE"})
		request.Replace("olcLogLevel", []string{"ANY"})
		if err := client.Modify(request); err != nil {
			t.Fatal(err)
		}
		observed := outcome{}
		for _, format := range []string{"default", "debug", "SYSLOG-UTC", "syslog-localtime", "rfc3339-utc"} {
			request := ldap.NewModifyRequest("cn=config", nil)
			request.Replace("olcLogFileFormat", []string{format})
			observed.codes = append(observed.codes, ldapOperationResultCode(client.Modify(request)))
			observed.values = append(observed.values, readConfiguredAttribute(t, client, "olcLogFileFormat"))
			information, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if server.logger != nil {
				server.logger.Error("format marker")
			} else {
				_, err = client.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
					0, 0, false, "(objectClass=*)", []string{"namingContexts"}, nil))
				if err != nil {
					t.Fatal(err)
				}
			}
			contents := readLogFile(t, path)[information.Size():]
			pattern := `(?m)^[0-9a-f]+\.[0-9a-f]{8} (?:0x)?[0-9a-f]+ `
			switch strings.ToLower(format) {
			case "syslog-utc", "syslog-localtime":
				pattern = `(?m)^[A-Z][a-z]{2} [0-9]{2} [0-9:]{8} \S+ slapd\[[0-9]+\]: `
			case "rfc3339-utc":
				pattern = `(?m)^[0-9-]{10}T[0-9:]{8}\.[0-9]{9}Z \S+ slapd\[[0-9]+\]: `
			}
			if !regexp.MustCompile(pattern).Match(contents) {
				t.Fatalf("%s %s format did not match %s: %.500q", server.uri, format, pattern, contents)
			}
		}
		// OpenLDAP 2.6.13 can deadlock when rotation limits change while another
		// thread logs (logging.c conditionally locks and unlocks on those limits).
		// Exercise parser semantics quietly; stress the Go lifecycle separately.
		quiet := ldap.NewModifyRequest("cn=config", nil)
		quiet.Replace("olcLogLevel", []string{"0"})
		if err := client.Modify(quiet); err != nil {
			t.Fatal(err)
		}
		for _, format := range []string{" debug ", `"syslog-utc"`, "debug extra", "json", "'debug'", `\debug`} {
			request := ldap.NewModifyRequest("cn=config", nil)
			request.Replace("olcLogFileFormat", []string{format})
			observed.codes = append(observed.codes, ldapOperationResultCode(client.Modify(request)))
			observed.values = append(observed.values, readConfiguredAttribute(t, client, "olcLogFileFormat"))
		}
		for _, value := range []string{"+2 +1 +0", "02 01 00", "0x2 0X1 0", "99 0 1", "1 1 0", "2 1 0",
			`"2" "1" "0"`, " 2\t1 0 ", "0 1 0", "100 1 0", "2 0 0", "2 -1 0", "2 1 -1", "2 1", "2 1 0 0", "2 1_0 0", "0o2 1 0", "2 08 0", "2 4294967296 0"} {
			request := ldap.NewModifyRequest("cn=config", nil)
			request.Replace("olcLogFileRotate", []string{value})
			code := ldapOperationResultCode(client.Modify(request))
			values := readConfiguredAttribute(t, client, "olcLogFileRotate")
			observed.codes = append(observed.codes, code)
			observed.values = append(observed.values, values)
		}
		observations = append(observations, observed)
	}
	if !reflect.DeepEqual(observations[0], observations[1]) {
		t.Fatalf("syntax differential:\nOpenLDAP: %#v\nldap-go: %#v", observations[0], observations[1])
	}
}
