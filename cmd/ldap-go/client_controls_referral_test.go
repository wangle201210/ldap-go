package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const openLDAPClientToolsCommit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

func TestLDAPControlSpecValuesCriticalityAndPresence(t *testing.T) {
	valuePath := filepath.Join(t.TempDir(), "control-value.bin")
	fileValue := []byte{0x00, 0xff, 0x01, 'x'}
	if err := os.WriteFile(valuePath, fileValue, 0o600); err != nil {
		t.Fatalf("write control value: %v", err)
	}
	fileURI := (&url.URL{Scheme: "file", Path: valuePath}).String()

	controls, err := parseLDAPControlSpecs([]string{
		"!1.2.3",
		"1.2.4=YWJj",
		"1.2.5=:plain text",
		"!1.2.6=::AP8B",
		"1.2.7=:<" + fileURI,
		"1.2.8=:",
	}, ldapControlValueOpenLDAPGeneral)
	if err != nil {
		t.Fatalf("parse controls: %v", err)
	}
	defer clearLDAPControls(controls)

	want := []struct {
		oid      string
		critical bool
		hasValue bool
		value    []byte
	}{
		{oid: "1.2.3", critical: true},
		{oid: "1.2.4", hasValue: true, value: []byte("abc")},
		{oid: "1.2.5", hasValue: true, value: []byte("plain text")},
		{oid: "1.2.6", critical: true, hasValue: true, value: []byte{0x00, 0xff, 0x01}},
		{oid: "1.2.7", hasValue: true, value: fileValue},
		{oid: "1.2.8", hasValue: true, value: []byte{}},
	}
	if len(controls) != len(want) {
		t.Fatalf("controls = %d, want %d", len(controls), len(want))
	}
	for index, expected := range want {
		control, ok := controls[index].(*ldapRawControl)
		if !ok {
			t.Fatalf("control %d has type %T", index, controls[index])
		}
		if control.oid != expected.oid || control.critical != expected.critical ||
			control.hasValue != expected.hasValue || !bytes.Equal(control.value, expected.value) {
			t.Errorf("control %d = %#v, want %#v", index, control, expected)
		}
		encoded := control.Encode()
		wantChildren := 1
		if expected.critical {
			wantChildren++
		}
		if expected.hasValue {
			wantChildren++
		}
		if len(encoded.Children) != wantChildren {
			t.Errorf("control %s BER children = %d, want %d", expected.oid, len(encoded.Children), wantChildren)
		}
	}
}

func TestLDAPControlSpecRejectsMalformedAndDuplicateValues(t *testing.T) {
	tests := []struct {
		name   string
		spec   string
		syntax ldapControlValueSyntax
	}{
		{name: "empty", spec: "", syntax: ldapControlValueLDIF},
		{name: "missing OID", spec: "!=:value", syntax: ldapControlValueLDIF},
		{name: "descriptor", spec: "noop", syntax: ldapControlValueLDIF},
		{name: "leading zero", spec: "1.02.3", syntax: ldapControlValueLDIF},
		{name: "general invalid base64", spec: "1.2.3=not-base64", syntax: ldapControlValueOpenLDAPGeneral},
		{name: "LDIF missing mode", spec: "1.2.3=value", syntax: ldapControlValueLDIF},
		{name: "remote file URI", spec: "1.2.3=:<https://example.com/value", syntax: ldapControlValueLDIF},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			control, err := parseLDAPControlSpec(test.spec, test.syntax)
			if control != nil {
				control.clear()
			}
			if err == nil {
				t.Fatalf("parseLDAPControlSpec(%q) succeeded", test.spec)
			}
		})
	}
	controls, err := parseLDAPControlSpecs(
		[]string{"1.2.3", "!1.2.3=:again"},
		ldapControlValueLDIF,
	)
	clearLDAPControls(controls)
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("duplicate controls error = %v", err)
	}
}

func TestLDAPSearchAndWriteGenericControlsOnWire(t *testing.T) {
	valuePath := filepath.Join(t.TempDir(), "wire-control.bin")
	fileValue := []byte{0xde, 0xad, 0x00, 0xbe, 0xef}
	if err := os.WriteFile(valuePath, fileValue, 0o600); err != nil {
		t.Fatalf("write wire control value: %v", err)
	}
	fileURI := (&url.URL{Scheme: "file", Path: valuePath}).String()

	searches := make(chan ldapwire.Message, 1)
	searchServer := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.SearchRequest); !ok {
			return nil, nil
		}
		searches <- message
		return [][]byte{ldapwire.EncodeSearchResultDone(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		)}, nil
	})
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapsearch", "-H", searchServer.uri, "-x", "-LLL",
		"-e", "!1.2.3=AAEC",
		"-e", "1.2.4=:common",
		"-E", "1.2.5=:<" + fileURI,
		"-E", "!1.2.6=::eHl6",
		"-E", "pr=2/noprompt",
		"-b", "", "-s", "base", "(objectClass=*)", "1.1",
	}, "")
	if exitCode != 0 || stderr != "" {
		t.Fatalf("ldapsearch controls exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	searchMessage := awaitLDAPClientWireMessage(t, searches)
	assertLDAPWireControl(t, searchMessage.Controls, "1.2.3", true, true, []byte{0, 1, 2})
	assertLDAPWireControl(t, searchMessage.Controls, "1.2.4", false, true, []byte("common"))
	assertLDAPWireControl(t, searchMessage.Controls, "1.2.5", false, true, fileValue)
	assertLDAPWireControl(t, searchMessage.Controls, "1.2.6", true, true, []byte("xyz"))
	assertLDAPWireControl(t, searchMessage.Controls, ldap.ControlTypePaging, false, true, nil)

	adds := make(chan ldapwire.Message, 1)
	addServer := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.AddRequest); !ok {
			return nil, nil
		}
		adds <- message
		return [][]byte{ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationAddResponse,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		)}, nil
	})
	stdout, stderr, exitCode = runLDAPClientCommand([]string{
		"ldapadd", "-H", addServer.uri, "-x",
		"-e", "!1.3.6.1.4.1.99999.1=:common-write",
		"-E", "1.3.6.1.4.1.99999.2=:<" + fileURI,
	}, personContentLDIF("uid=wire,"+clientToolPeopleDN, "wire", "Wire Entry"))
	if exitCode != 0 || stderr != "" || !strings.Contains(stdout, "applied 1 record") {
		t.Fatalf("ldapadd controls exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	addMessage := awaitLDAPClientWireMessage(t, adds)
	assertLDAPWireControl(
		t,
		addMessage.Controls,
		"1.3.6.1.4.1.99999.1",
		true,
		true,
		[]byte("common-write"),
	)
	assertLDAPWireControl(
		t,
		addMessage.Controls,
		"1.3.6.1.4.1.99999.2",
		false,
		true,
		fileValue,
	)
}

func TestLDAPExtendedOperationReceivesGeneralControl(t *testing.T) {
	requests := make(chan ldapwire.Message, 1)
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		request, ok := message.Request.(ldapwire.ExtendedRequest)
		if !ok {
			return nil, nil
		}
		requests <- message
		if request.Name != ldapWhoAmIOID {
			return nil, fmt.Errorf("extended request OID = %q", request.Name)
		}
		return [][]byte{ldapwire.EncodeExtendedResponse(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			ldapWhoAmIOID,
			[]byte("dn:cn=wire"),
			nil,
		)}, nil
	})
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapwhoami", "-H", fixture.uri, "-x", "-e", "!1.2.3=:whoami",
	}, "")
	if exitCode != 0 || stderr != "" || stdout != "dn:cn=wire\n" {
		t.Fatalf("ldapwhoami control exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	message := awaitLDAPClientWireMessage(t, requests)
	assertLDAPWireControl(t, message.Controls, "1.2.3", true, true, []byte("whoami"))
}

func TestLDAPSearchReferralChasingDisableRebindAndControls(t *testing.T) {
	const targetBase = "ou=target,dc=example,dc=com"
	providerRequests := make(chan ldapwire.Message, 4)
	providerBinds := make(chan ldapwire.BindRequest, 4)
	var providerSearches atomic.Int32
	provider := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		switch request := message.Request.(type) {
		case ldapwire.BindRequest:
			providerBinds <- request
			return nil, nil
		case ldapwire.SearchRequest:
			providerSearches.Add(1)
			providerRequests <- message
			entry := directory.Entry{
				DN: "uid=target," + targetBase,
				Attributes: []directory.Attribute{
					{Description: "uid", Values: [][]byte{[]byte("target")}},
				},
			}
			return [][]byte{
				ldapwire.EncodeSearchResultEntry(message.ID, entry, nil),
				ldapwire.EncodeSearchResultDone(
					message.ID,
					ldapwire.Result{Code: ldapwire.ResultSuccess},
					nil,
				),
			}, nil
		default:
			return nil, nil
		}
	})
	referralURL := provider.uri + "/" + url.PathEscape(targetBase)
	source := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.SearchRequest); !ok {
			return nil, nil
		}
		return [][]byte{
			ldapwire.EncodeSearchResultReference(message.ID, []string{referralURL}, nil),
			ldapwire.EncodeSearchResultDone(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			),
		}, nil
	})
	options := []string{
		"ldapsearch", "-H", source.uri, "-x", "-LLL", "-b", clientToolPeopleDN,
		"-s", "one", "-e", "1.2.3=:referral-control",
	}
	query := []string{"(uid=target)", "uid"}
	args := append(append([]string(nil), options...), query...)
	stdout, stderr, exitCode := runLDAPClientCommand(args, "")
	if exitCode != 0 || stderr != "" || strings.Contains(stdout, "uid=target") {
		t.Fatalf("disabled referral exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if providerSearches.Load() != 0 {
		t.Fatalf("default ldapsearch chased %d referrals", providerSearches.Load())
	}

	chasingArgs := append(append([]string(nil), options...), "-C")
	chasingArgs = append(chasingArgs, query...)
	stdout, stderr, exitCode = runLDAPClientCommand(chasingArgs, "")
	if exitCode != 0 || stderr != "" || !strings.Contains(stdout, "dn: uid=target,"+targetBase) {
		t.Fatalf("chased referral exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	bind := awaitLDAPClientWireMessageValue(t, providerBinds)
	if bind.Name != "" || bind.Authentication.IsSASL || len(bind.Authentication.Simple) != 0 {
		t.Fatalf("referral rebind = %#v, want anonymous simple bind", bind)
	}
	requestMessage := awaitLDAPClientWireMessage(t, providerRequests)
	request := requestMessage.Request.(ldapwire.SearchRequest)
	if request.BaseDN != targetBase || request.Scope != directory.ScopeBase ||
		request.Filter.Kind != directory.FilterEquality || request.Filter.Attribute != "uid" ||
		!bytes.Equal(request.Filter.Assertion, []byte("target")) {
		t.Fatalf("referral search = %#v", request)
	}
	assertLDAPWireControl(
		t,
		requestMessage.Controls,
		"1.2.3",
		false,
		true,
		[]byte("referral-control"),
	)

	disabledArgs := append(append([]string(nil), options...), "-C", "-referrals=false")
	disabledArgs = append(disabledArgs, query...)
	stdout, stderr, exitCode = runLDAPClientCommand(disabledArgs, "")
	if exitCode != 0 || stderr != "" || strings.Contains(stdout, "uid=target") {
		t.Fatalf("explicitly disabled referral exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if providerSearches.Load() != 1 {
		t.Fatalf("explicit disable left provider search count at %d", providerSearches.Load())
	}
}

func TestLDAPWriteReferralChasingPreservesDNAndControls(t *testing.T) {
	const sourceDN = "uid=source,dc=example,dc=com"
	const targetDN = "uid=target,dc=example,dc=com"
	providerDeletes := make(chan ldapwire.Message, 2)
	provider := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.DeleteRequest); !ok {
			return nil, nil
		}
		providerDeletes <- message
		return [][]byte{ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationDeleteResponse,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		)}, nil
	})
	referralURL := provider.uri + "/" + url.PathEscape(targetDN)
	source := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.DeleteRequest); !ok {
			return nil, nil
		}
		return [][]byte{ldapwire.EncodeResultResponse(
			message.ID,
			ldapwire.ApplicationDeleteResponse,
			ldapwire.Result{
				Code:      ldapwire.ResultReferral,
				Referrals: []string{referralURL},
			},
			nil,
		)}, nil
	})

	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapdelete", "-H", source.uri, "-x", "-C",
		"-e", "!1.2.3=:delete-control", sourceDN,
	}, "")
	if exitCode != 0 || stderr != "" || !strings.Contains(stdout, "deleted 1 entry") {
		t.Fatalf("ldapdelete referral exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	message := awaitLDAPClientWireMessage(t, providerDeletes)
	request := message.Request.(ldapwire.DeleteRequest)
	if request.DN != targetDN {
		t.Fatalf("referred delete DN = %q, want %q", request.DN, targetDN)
	}
	assertLDAPWireControl(t, message.Controls, "1.2.3", true, true, []byte("delete-control"))
}

func TestLDAPReferralHopLimitAndLoopDetection(t *testing.T) {
	const baseDN = "dc=example,dc=com"
	var terminalSearches atomic.Int32
	terminal := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.SearchRequest); !ok {
			return nil, nil
		}
		terminalSearches.Add(1)
		return [][]byte{ldapwire.EncodeSearchResultDone(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		)}, nil
	})
	middleReferral := terminal.uri + "/" + url.PathEscape(baseDN)
	middle := startLDAPClientWireFixture(t, searchReferralFixtureHandler(middleReferral))
	initialReferral := middle.uri + "/" + url.PathEscape(baseDN)
	initial := startLDAPClientWireFixture(t, searchReferralFixtureHandler(initialReferral))

	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapsearch", "-H", initial.uri, "-x", "-C", "-referral-hop-limit", "1",
		"-LLL", "-b", baseDN, "(objectClass=*)", "1.1",
	}, "")
	if exitCode != ldap.LDAPResultReferralLimitExceeded || stdout != "" ||
		stderr != "ldap_result: Referral Limit Exceeded (97)\n" {
		t.Fatalf("hop limit exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if terminalSearches.Load() != 0 {
		t.Fatalf("hop-limited search reached terminal %d time(s)", terminalSearches.Load())
	}

	var first, second *ldapClientWireFixture
	first = startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.SearchRequest); !ok {
			return nil, nil
		}
		referral := second.uri + "/" + url.PathEscape(baseDN)
		return searchReferralResponses(message.ID, referral), nil
	})
	second = startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.SearchRequest); !ok {
			return nil, nil
		}
		referral := first.uri + "/" + url.PathEscape(baseDN)
		return searchReferralResponses(message.ID, referral), nil
	})
	stdout, stderr, exitCode = runLDAPClientCommand([]string{
		"ldapsearch", "-H", first.uri, "-x", "-C", "-LLL", "-b", baseDN,
		"(objectClass=*)", "1.1",
	}, "")
	if exitCode != ldap.LDAPResultClientLoop || stdout != "" ||
		stderr != "ldap_result: Client Loop (96)\n" {
		t.Fatalf("referral loop exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestOpenLDAPClientControlReferralSourceContract(t *testing.T) {
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Skip("OPENLDAP_SOURCE is not set")
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPClientToolsCommit {
		t.Fatalf("OpenLDAP source commit = %q, want %q", got, openLDAPClientToolsCommit)
	}
	assertOpenLDAPClientSourceAnchors(t, source, "clients/tools/common.c", []string{
		"case 'C':\t/* referrals: obsolete */",
		"referrals ? LDAP_OPT_ON : LDAP_OPT_OFF",
		"case 'e':\t/* general extensions (controls and such) */",
		"} else if ( tool_is_oid( control ) ) {",
		"retcode = lutil_b64_pton( cvalue,",
	})
	assertOpenLDAPClientSourceAnchors(t, source, "clients/tools/ldapsearch.c", []string{
		"[!]<oid>[=:<value>|=::<b64value>] (generic control; no response handling)",
		"ldif_parse_line2( &cvalue[ -2 ], &type,",
		"tool_perror( \"ldap_result\", rc2, NULL, NULL, NULL, NULL );",
		"tool_exit( ld, rc );",
	})
	assertOpenLDAPClientSourceAnchors(t, source, "libraries/libldap/error.c", []string{
		"N_(\"Bad parameter to an ldap routine\")",
		"N_(\"Client Loop\")",
		"N_(\"Referral Limit Exceeded\")",
	})
	assertOpenLDAPClientSourceAnchors(t, source, "libraries/libldap/ldap-int.h", []string{
		"#define LDAP_DEFAULT_REFHOPLIMIT 5",
	})
	assertOpenLDAPClientSourceAnchors(t, source, "libraries/libldap/request.c", []string{
		"ldap_url_parse_ext( refarray[i], &srv, LDAP_PVT_URL_PARSE_NOEMPTY_DN )",
		"ld->ld_errno = LDAP_PARAM_ERROR;",
		"if( srv->lud_crit_exts ) {",
		"ld->ld_errno = LDAP_NOT_SUPPORTED;",
		"In the future we also need to replace the filter",
		"if ( srv->lud_dn ) {",
		"if ( lr->lr_parentcnt >= ld->ld_refhoplimit ) {",
		"rc = ldap_sasl_bind( ld, \"\", LDAP_SASL_SIMPLE, &passwd,",
		"else if ( sref ) {",
		"scope = LDAP_SCOPE_BASE;",
		"scope = LDAP_SCOPE_SUBTREE;",
	})
	assertOpenLDAPClientSourceAnchors(t, source, "libraries/libldap/url.c", []string{
		"ludp->lud_attrs = ldap_str2charray( p, \",\" );",
		"ludp->lud_scope = ldap_pvt_str2scope( p );",
		"ludp->lud_filter = LDAP_STRDUP( p );",
		"ludp->lud_exts = ldap_str2charray( p, \",\" );",
		"if( *ludp->lud_exts[i] == '!' ) {",
	})
	assertOpenLDAPClientSourceAnchors(t, source, "libraries/libldap/os-ip.c", []string{
		"srv->lud_host == NULL || *srv->lud_host == 0",
		"host = \"localhost\";",
	})
}

func assertOpenLDAPClientSourceAnchors(
	t *testing.T,
	root, relative string,
	anchors []string,
) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatalf("read OpenLDAP source %s: %v", relative, err)
	}
	for _, anchor := range anchors {
		if !bytes.Contains(data, []byte(anchor)) {
			t.Errorf("OpenLDAP source %s lacks %q", relative, anchor)
		}
	}
}

type ldapClientWireHandler func(ldapwire.Message) ([][]byte, error)

type ldapClientWireFixture struct {
	uri      string
	listener net.Listener
	done     chan struct{}
	errors   chan error
	close    sync.Once
}

func startLDAPClientWireFixture(
	t *testing.T,
	handler ldapClientWireHandler,
) *ldapClientWireFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for LDAP client wire fixture: %v", err)
	}
	fixture := &ldapClientWireFixture{
		uri:      "ldap://" + listener.Addr().String(),
		listener: listener,
		done:     make(chan struct{}),
		errors:   make(chan error, 16),
	}
	var connections sync.WaitGroup
	go func() {
		defer close(fixture.done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					fixture.report(fmt.Errorf("accept LDAP fixture connection: %w", err))
				}
				connections.Wait()
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
				for {
					message, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
					if err != nil {
						if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
							var networkError net.Error
							if !errors.As(err, &networkError) || !networkError.Timeout() {
								fixture.report(fmt.Errorf("read LDAP fixture request: %w", err))
							}
						}
						return
					}
					responses, handlerErr := handler(message)
					if handlerErr != nil {
						fixture.report(handlerErr)
					}
					if _, bind := message.Request.(ldapwire.BindRequest); bind && len(responses) == 0 {
						responses = [][]byte{ldapwire.EncodeBindResponse(
							message.ID,
							ldapwire.Result{Code: ldapwire.ResultSuccess},
							nil,
						)}
					}
					if len(responses) == 0 {
						fixture.report(fmt.Errorf("LDAP fixture has no response for %T", message.Request))
						return
					}
					for _, response := range responses {
						if err := ldapwire.Write(connection, response); err != nil {
							fixture.report(fmt.Errorf("write LDAP fixture response: %w", err))
							return
						}
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		fixture.close.Do(func() { _ = fixture.listener.Close() })
		select {
		case <-fixture.done:
		case <-time.After(5 * time.Second):
			t.Error("LDAP client wire fixture did not stop")
		}
		close(fixture.errors)
		for err := range fixture.errors {
			t.Errorf("LDAP client wire fixture: %v", err)
		}
	})
	return fixture
}

func (fixture *ldapClientWireFixture) report(err error) {
	select {
	case fixture.errors <- err:
	default:
	}
}

func awaitLDAPClientWireMessage(t *testing.T, messages <-chan ldapwire.Message) ldapwire.Message {
	t.Helper()
	return awaitLDAPClientWireMessageValue(t, messages)
}

func awaitLDAPClientWireMessageValue[T any](t *testing.T, values <-chan T) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(5 * time.Second):
		var zero T
		t.Fatal("LDAP client wire fixture timed out")
		return zero
	}
}

func assertLDAPWireControl(
	t *testing.T,
	controls []ldapwire.Control,
	oid string,
	critical, hasValue bool,
	value []byte,
) {
	t.Helper()
	for _, control := range controls {
		if control.OID != oid {
			continue
		}
		if control.Critical != critical || control.HasValue != hasValue {
			t.Fatalf("control %s = %#v", oid, control)
		}
		if value != nil && !bytes.Equal(control.Value, value) {
			t.Fatalf("control %s value = %x, want %x", oid, control.Value, value)
		}
		return
	}
	t.Fatalf("controls %#v lack %s", controls, oid)
}

func searchReferralFixtureHandler(referral string) ldapClientWireHandler {
	return func(message ldapwire.Message) ([][]byte, error) {
		if _, ok := message.Request.(ldapwire.SearchRequest); !ok {
			return nil, nil
		}
		return searchReferralResponses(message.ID, referral), nil
	}
}

func searchReferralResponses(messageID int64, referral string) [][]byte {
	return [][]byte{
		ldapwire.EncodeSearchResultReference(messageID, []string{referral}, nil),
		ldapwire.EncodeSearchResultDone(
			messageID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		),
	}
}
