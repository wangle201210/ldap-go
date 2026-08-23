package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPSearchRepeatedTemporaryValueFlags(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	for _, flags := range [][]string{{"-tt"}, {"-t", "-t"}, {"-ttt"}} {
		t.Run(strings.Join(flags, "_"), func(t *testing.T) {
			directory := t.TempDir()
			arguments := []string{
				"ldapsearch", "-H", uri, "-x",
				"-D", clientToolRootDN, "-w", clientToolRootPassword,
				"-b", "uid=alice," + clientToolPeopleDN, "-s", "base", "-LLL",
			}
			arguments = append(arguments, flags...)
			arguments = append(
				arguments,
				"-T", directory,
				"(objectClass=*)", "cn", "jpegPhoto",
			)
			stdout, stderr, exitCode := runLDAPClientCommand(arguments, "")
			if exitCode != 0 || stderr != "" {
				t.Fatalf("ldapsearch %v exit=%d stdout=%q stderr=%q", flags, exitCode, stdout, stderr)
			}
			if strings.Contains(stdout, "cn: Alice Example") ||
				strings.Contains(stdout, base64Value([]byte{0x00, 0xff, 0x10})) ||
				strings.Count(stdout, ":< file:") != 2 {
				t.Fatalf("ldapsearch %v did not externalize every value: %q", flags, stdout)
			}
			files, err := os.ReadDir(directory)
			if err != nil || len(files) != 2 {
				t.Fatalf("ldapsearch %v temporary files = %v, %v", flags, files, err)
			}
		})
	}
}

func TestLDAPSearchResponseControlsRemainOpaque(t *testing.T) {
	fixture := startLDAPClientWireFixture(t, ldapSearchControlFixtureHandler)
	for _, level := range [][]string{{}, {"-L"}, {"-LL"}, {"-LLL"}} {
		t.Run(strings.Join(level, "_"), func(t *testing.T) {
			arguments := []string{
				"ldapsearch", "-H", fixture.uri, "-x", "-b", "dc=example,dc=com",
				"-s", "base",
			}
			arguments = append(arguments, level...)
			arguments = append(arguments, "(objectClass=*)", "cn")
			stdout, stderr, exitCode := runLDAPClientCommand(arguments, "")
			if exitCode != 0 || stderr != "" {
				t.Fatalf("ldapsearch %v exit=%d stdout=%q stderr=%q", level, exitCode, stdout, stderr)
			}
			prefix := "control: "
			ldifLevel := 0
			if len(level) == 1 {
				ldifLevel = len(level[0]) - 1
			}
			if ldifLevel == 1 {
				prefix = "# control: "
			}
			if ldifLevel >= 2 {
				if strings.Contains(stdout, "control:") {
					t.Fatalf("ldapsearch %v rendered suppressed controls: %q", level, stdout)
				}
				return
			}
			entryControl := prefix + "1.2.3.4 false " + base64.StdEncoding.EncodeToString([]byte{0, 1, 2})
			resultControl := prefix + "1.2.3.5 false " + base64.StdEncoding.EncodeToString([]byte("opaque"))
			if strings.Count(stdout, entryControl) != 1 || strings.Count(stdout, resultControl) != 1 {
				t.Fatalf("ldapsearch %v response controls = %q", level, stdout)
			}
			if strings.Contains(stdout, "Control Type") || strings.Contains(stdout, "Paging") {
				t.Fatalf("unknown controls were semantically decoded: %q", stdout)
			}
		})
	}
}

func TestLDAPSearchIntermediateResponseRendering(t *testing.T) {
	responses := []ldapSearchWireResponse{{
		tag:                 ldap.ApplicationIntermediateResponse,
		intermediateOID:     "1.2.840.113556.1.4.9999",
		intermediateData:    []byte{0x00, 0xff, 0x01},
		hasIntermediateData: true,
		controls: []ldapSearchResponseControl{{
			oid:      "1.2.3.6",
			critical: false,
			value:    []byte("raw"),
			hasValue: true,
		}},
	}}
	for _, test := range []struct {
		name  string
		level int
		want  string
	}{
		{
			name:  "default",
			level: 0,
			want: "# extended partial response\n" +
				"partial: 1.2.840.113556.1.4.9999\n" +
				"data:: AP8B\n" +
				"control: 1.2.3.6 false cmF3\n\n",
		},
		{
			name:  "ldif",
			level: 1,
			want: "# extended partial response\n" +
				"# partial: 1.2.840.113556.1.4.9999\n" +
				"# data:: AP8B\n" +
				"# control: 1.2.3.6 false cmF3\n\n",
		},
		{name: "ldif_without_comments", level: 2, want: ""},
		{name: "minimal", level: 3, want: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			writer := &ldapSearchLDIFOutput{writer: &output, level: test.level}
			if err := writer.writeIntermediateResponses(responses); err != nil {
				t.Fatal(err)
			}
			if got := output.String(); got != test.want {
				t.Fatalf("intermediate output = %q, want %q", got, test.want)
			}
		})
	}
}

func TestLDAPSearchKnownResponseControlAndSyncInfoRendering(t *testing.T) {
	fixture := startLDAPClientWireFixture(t, ldapSearchKnownControlFixtureHandler)
	tests := []struct {
		name        string
		level       []string
		contains    []string
		notContains []string
	}{
		{
			name: "default",
			contains: []string{
				"control: " + ldap.ControlTypeSyncState + " false ",
				"# SyncState control, UUID 00112233-4455-6677-8899-aabbccddeeff modified\n",
				"# ==> preread\n",
				"# SyncInfo Received: refresh present\n",
				"# refresh done, switching to persist stage\n",
				"pagedresults: estimate=7 cookie=bmV4dA==\n",
				"sortResult: (0) Success\n",
				"vlvResult: pos=2 count=9 context=Y3R4 (0) Success\n",
				"ppolicy: expire=60 error=2 (Password must be changed)\n",
				"# ==> postread\n",
				"# SyncDone control refreshDeletes=1\n",
			},
			notContains: []string{"partial: " + ldap.ControlTypeSyncInfo},
		},
		{
			name:  "ldif",
			level: []string{"-L"},
			contains: []string{
				"# control: " + ldap.ControlTypeSyncState + " false ",
				"# ==> preread\n",
				"# SyncInfo Received\n",
				"# pagedresults: estimate=7 cookie=bmV4dA==\n",
				"# sortResult: (0) Success\n",
				"# vlvResult: pos=2 count=9 context=Y3R4 (0) Success\n",
				"# ppolicy: expire=60 error=2 (Password must be changed)\n",
				"# ==> postread\n",
			},
			notContains: []string{"# SyncState control", "# SyncDone control"},
		},
		{
			name:  "ldif_no_comments",
			level: []string{"-LL"},
			contains: []string{
				"# ==> preread\n",
				"# pagedresults: estimate=7 cookie=bmV4dA==\n",
				"# sortResult: (0) Success\n",
				"# vlvResult: pos=2 count=9 context=Y3R4 (0) Success\n",
				"# ppolicy: expire=60 error=2 (Password must be changed)\n",
				"# ==> postread\n",
			},
			notContains: []string{"control:", "SyncInfo Received", "SyncState control", "SyncDone control"},
		},
		{
			name:  "minimal",
			level: []string{"-LLL"},
			contains: []string{
				"# ==> preread\n",
				"# pagedresults: estimate=7 cookie=bmV4dA==\n",
				"# sortResult: (0) Success\n",
				"# vlvResult: pos=2 count=9 context=Y3R4 (0) Success\n",
				"# ppolicy: expire=60 error=2 (Password must be changed)\n",
				"# ==> postread\n",
			},
			notContains: []string{"control:", "SyncInfo Received", "SyncState control", "SyncDone control"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arguments := []string{
				"ldapsearch", "-H", fixture.uri, "-x", "-b", "dc=example,dc=com",
				"-s", "base",
			}
			arguments = append(arguments, test.level...)
			arguments = append(arguments, "(objectClass=*)", "cn")
			stdout, stderr, exitCode := runLDAPClientCommand(arguments, "")
			if exitCode != 0 || stderr != "" {
				t.Fatalf("ldapsearch %s exit=%d stdout=%q stderr=%q", test.name, exitCode, stdout, stderr)
			}
			for _, expected := range test.contains {
				if !strings.Contains(stdout, expected) {
					t.Fatalf("ldapsearch %s output lacks %q: %q", test.name, expected, stdout)
				}
			}
			for _, unexpected := range test.notContains {
				if strings.Contains(stdout, unexpected) {
					t.Fatalf("ldapsearch %s output contains %q: %q", test.name, unexpected, stdout)
				}
			}
		})
	}
}

func TestLDAPSearchMalformedKnownControlRemainsRaw(t *testing.T) {
	for _, level := range []int{0, 1, 2, 3} {
		var output bytes.Buffer
		writer := &ldapSearchLDIFOutput{writer: &output, level: level}
		if err := writer.writeResponseControls([]ldapSearchResponseControl{{
			oid:      ldap.ControlTypePaging,
			value:    []byte{0x30, 0x01, 0xff},
			hasValue: true,
		}}); err != nil {
			t.Fatal(err)
		}
		if level < 2 && !strings.Contains(output.String(), ldap.ControlTypePaging) {
			t.Fatalf("level %d omitted raw malformed control: %q", level, output.String())
		}
		if strings.Contains(output.String(), "pagedresults:") {
			t.Fatalf("level %d interpreted malformed paging control: %q", level, output.String())
		}
	}
}

func TestLDAPSearchObservedStartTLS(t *testing.T) {
	serverTLS, certificatePEM := newLDAPClientToolTLSConfig(t)
	uri := startLDAPClientToolServer(t, serverTLS)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapsearch", "-H", uri, "-x", "-ZZ",
		"-tls-ca", caPath, "-tls-server-name", "localhost",
		"-b", "dc=example,dc=com", "-s", "base", "-LLL",
		"(objectClass=*)", "dc",
	}, "")
	if exitCode != 0 || stderr != "" || !strings.Contains(stdout, "dc: example\n") {
		t.Fatalf("StartTLS ldapsearch exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestOpenLDAPReferenceLDAPSearchResponseControls(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") == "" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 to run the OpenLDAP ldapsearch reference test")
	}
	if got := os.Getenv("OPENLDAP_REFERENCE_VERIFIED"); got != "1" {
		t.Fatalf("OPENLDAP_REFERENCE_VERIFIED = %q, want 1", got)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPClientToolsCommit {
		t.Fatalf("OPENLDAP_COMMIT = %q, want %q", got, openLDAPClientToolsCommit)
	}
	referenceTool := filepath.Join(os.Getenv("OPENLDAP_BUILD"), "clients", "tools", "ldapsearch")
	if _, err := os.Stat(referenceTool); err != nil {
		referenceTool, err = exec.LookPath("ldapsearch")
		if err != nil {
			t.Fatalf("find OpenLDAP ldapsearch: %v", err)
		}
	}
	fixture := startLDAPClientWireFixture(t, ldapSearchControlFixtureHandler)
	for _, level := range [][]string{{}, {"-L"}, {"-LL"}, {"-LLL"}} {
		arguments := []string{
			"-H", fixture.uri, "-x", "-b", "dc=example,dc=com", "-s", "base",
		}
		arguments = append(arguments, level...)
		arguments = append(arguments, "(objectClass=*)", "cn")
		assertLDAPSearchMatchesOpenLDAP(t, referenceTool, arguments)
	}

	knownFixture := startLDAPClientWireFixture(t, ldapSearchKnownControlFixtureHandler)
	for _, level := range [][]string{{}, {"-L"}, {"-LL"}, {"-LLL"}} {
		arguments := []string{
			"-H", knownFixture.uri, "-x", "-b", "dc=example,dc=com", "-s", "base",
		}
		arguments = append(arguments, level...)
		arguments = append(arguments, "(objectClass=*)", "cn")
		assertLDAPSearchMatchesOpenLDAP(t, referenceTool, arguments)
	}

	source := os.Getenv("OPENLDAP_SOURCE")
	assertOpenLDAPClientSourceAnchors(t, source, "clients/tools/ldapsearch.c", []string{
		"case 't':\t/* write attribute values to TMPDIR files */",
		"++vals2tmp;",
		"vals2tmp > 1 || ( vals2tmp &&",
		"tool_print_ctrls( ld, ctrls );",
		"case LDAP_RES_INTERMEDIATE:",
		"print_partial( ld, msg );",
	})
}

func ldapSearchKnownControlFixtureHandler(message ldapwire.Message) ([][]byte, error) {
	if _, ok := message.Request.(ldapwire.SearchRequest); !ok {
		return nil, nil
	}
	uuid := ldapwire.SyncUUID{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	entry := directory.Entry{
		DN: "dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "cn",
			Values:      [][]byte{[]byte("Example")},
		}},
	}
	readEntry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "cn",
			Values:      [][]byte{[]byte("Alice Example")},
		}},
	}
	return [][]byte{
		ldapwire.EncodeSearchResultEntry(message.ID, entry, []ldapwire.Control{
			{
				OID: ldap.ControlTypeSyncState,
				Value: ldapwire.EncodeSyncStateValue(ldapwire.SyncStateValue{
					State:     ldapwire.SyncStateModify,
					EntryUUID: uuid,
					Cookie:    []byte("state-cookie"),
					HasCookie: true,
				}),
				HasValue: true,
			},
			{OID: ldapControlPreRead, Value: ldapwire.EncodeReadControlValue(readEntry), HasValue: true},
		}),
		ldapwire.EncodeIntermediateResponse(
			message.ID,
			ldap.ControlTypeSyncInfo,
			ldapwire.EncodeSyncInfoValue(ldapwire.SyncInfoValue{
				Kind:        ldapwire.SyncInfoRefreshPresent,
				Cookie:      []byte("sync-cookie"),
				HasCookie:   true,
				RefreshDone: true,
			}),
			[]ldapwire.Control{{OID: "1.2.3.9", Value: []byte("ignored"), HasValue: true}},
		),
		ldapwire.EncodeSearchResultDone(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			[]ldapwire.Control{
				{OID: ldap.ControlTypePaging, Value: ldapwire.EncodePagedResultsValue(7, []byte("next")), HasValue: true},
				{OID: ldap.ControlTypeServerSideSortingResult, Value: ldapwire.EncodeSortResultValue(ldapwire.ResultSuccess, ""), HasValue: true},
				{OID: ldap.ControlTypeVLVResponse, Value: ldapwire.EncodeVirtualListViewResponseValue(ldapwire.VirtualListViewResponse{TargetPosition: 2, ContentCount: 9, Result: ldapwire.ResultSuccess, ContextID: []byte("ctx"), HasContextID: true}), HasValue: true},
				{OID: ldap.ControlTypeBeheraPasswordPolicy, Value: ldapwire.EncodePasswordPolicyResponseValue(60, -1, 2), HasValue: true},
				{OID: ldapControlPostRead, Value: ldapwire.EncodeReadControlValue(readEntry), HasValue: true},
				{OID: ldap.ControlTypeSyncDone, Value: ldapwire.EncodeSyncDoneValue(ldapwire.SyncDoneValue{Cookie: []byte("done-cookie"), HasCookie: true, RefreshDeletes: true}), HasValue: true},
			},
		),
	}, nil
}

func ldapSearchControlFixtureHandler(message ldapwire.Message) ([][]byte, error) {
	if _, ok := message.Request.(ldapwire.SearchRequest); !ok {
		return nil, nil
	}
	entry := directory.Entry{
		DN: "dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "cn",
			Values:      [][]byte{[]byte("Example")},
		}},
	}
	return [][]byte{
		ldapwire.EncodeSearchResultEntry(message.ID, entry, []ldapwire.Control{{
			OID:      "1.2.3.4",
			Value:    []byte{0, 1, 2},
			HasValue: true,
		}}),
		ldapwire.EncodeSearchResultDone(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			[]ldapwire.Control{{
				OID:      "1.2.3.5",
				Value:    []byte("opaque"),
				HasValue: true,
			}},
		),
	}, nil
}
