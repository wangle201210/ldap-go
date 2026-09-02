package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPSearchRefreshAndPersistStreamsAndCancelsAtLimit(t *testing.T) {
	cancelResponse := make(chan struct{})
	fixture := startLDAPSyncPersistFixtureWithOptions(
		t,
		nil,
		false,
		true,
		cancelResponse,
	)
	stdout := newLDAPSyncObservedWriter()
	var stderr bytes.Buffer
	result := make(chan int, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	go func() {
		result <- runWithContext(
			ctx,
			[]string{
				"ldapsearch", "-H", fixture.uri, "-x",
				"-E", "sync=rp/csn=initial/2",
				"-b", "dc=example,dc=com", "(objectClass=*)", "cn",
			},
			strings.NewReader(""),
			stdout,
			&stderr,
			func(string) string { return "" },
		)
	}()

	search := awaitLDAPClientWireMessage(t, fixture.searches)
	syncRequest := requireLDAPSyncPersistRequest(t, search, "csn=initial")
	if syncRequest.Mode != ldapwire.SyncRefreshAndPersist {
		t.Fatalf("sync mode = %d, want refreshAndPersist", syncRequest.Mode)
	}

	fixture.send(t, ldapSyncPersistEntry(
		search.ID,
		"uid=refresh,dc=example,dc=com",
		"Refresh Entry",
		ldapwire.SyncStatePresent,
		0x10,
	))
	stdout.awaitContains(t, "dn: uid=refresh,dc=example,dc=com\n")

	fixture.send(t, ldapwire.EncodeSearchResultReference(
		search.ID,
		[]string{"ldap://ref.example/dc=example,dc=com"},
		nil,
	))
	stdout.awaitContains(t, "ref: ldap://ref.example/dc=example,dc=com\n")

	fixture.send(t, ldapwire.EncodeIntermediateResponse(
		search.ID,
		ldap.ControlTypeSyncInfo,
		ldapwire.EncodeSyncInfoValue(ldapwire.SyncInfoValue{
			Kind:        ldapwire.SyncInfoRefreshPresent,
			Cookie:      []byte("csn=refresh"),
			HasCookie:   true,
			RefreshDone: true,
		}),
		nil,
	))
	stdout.awaitContains(t, "# refresh done, switching to persist stage\n")

	fixture.send(t, ldapSyncPersistEntry(
		search.ID,
		"uid=persist-one,dc=example,dc=com",
		"Persist One",
		ldapwire.SyncStateAdd,
		0x20,
	))
	stdout.awaitContains(t, "dn: uid=persist-one,dc=example,dc=com\n")
	select {
	case cancelRequest := <-fixture.cancels:
		t.Fatalf("Cancel arrived before slimit: %#v", cancelRequest)
	default:
	}

	burst := ldapSyncPersistEntry(
		search.ID,
		"uid=persist-two,dc=example,dc=com",
		"Persist Two",
		ldapwire.SyncStateModify,
		0x30,
	)
	for index := range 64 {
		burst = append(burst, ldapSyncPersistEntry(
			search.ID,
			fmt.Sprintf("uid=after-limit-%d,dc=example,dc=com", index),
			"After Limit",
			ldapwire.SyncStateModify,
			byte(0x60+index),
		)...)
	}
	fixture.send(t, burst)
	stdout.awaitContains(t, "dn: uid=persist-two,dc=example,dc=com\n")

	cancelRequest := awaitLDAPClientWireMessage(t, fixture.cancels)
	extended, ok := cancelRequest.Request.(ldapwire.ExtendedRequest)
	if !ok || extended.Name != ldapCancelOID || !extended.HasValue {
		t.Fatalf("Cancel request = %#v", cancelRequest)
	}
	target, err := ldapwire.DecodeCancelRequestValue(extended.Value)
	if err != nil || target != search.ID {
		t.Fatalf("Cancel target = %d, %v; want %d", target, err, search.ID)
	}
	select {
	case code := <-result:
		t.Fatalf("ldapsearch exited before the Cancel result: %d", code)
	case <-time.After(50 * time.Millisecond):
	}
	close(cancelResponse)

	select {
	case code := <-result:
		if code != 0 || stderr.String() != "" {
			t.Fatalf("ldapsearch exit=%d stderr=%q\nstdout:\n%s", code, stderr.String(), stdout.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ldapsearch did not finish after successful Cancel")
	}
	select {
	case <-fixture.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("slimit search connection or server goroutine remained after Cancel")
	}
	for _, expected := range []string{
		"# numResponses: 5\n",
		"# numEntries: 3\n",
		"# numPartial: 1\n",
		"# numReferences: 1\n",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("stream output lacks %q:\n%s", expected, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "uid=after-limit-") {
		t.Fatalf("stream printed responses beyond slimit:\n%s", stdout.String())
	}
}

func TestLDAPSearchRefreshAndPersistHonorsContextCancellation(t *testing.T) {
	fixture := startLDAPSyncPersistFixture(t)
	stdout := newLDAPSyncObservedWriter()
	var stderr bytes.Buffer
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan int, 1)
	go func() {
		result <- runWithContext(
			ctx,
			[]string{
				"ldapsearch", "-H", fixture.uri, "-x", "-E", "sync=rp",
				"-b", "dc=example,dc=com", "(objectClass=*)",
			},
			strings.NewReader(""),
			stdout,
			&stderr,
			func(string) string { return "" },
		)
	}()
	awaitLDAPClientWireMessage(t, fixture.searches)
	cancel()
	select {
	case code := <-result:
		if code != 1 || !strings.Contains(stderr.String(), context.Canceled.Error()) {
			t.Fatalf("canceled ldapsearch exit=%d stderr=%q", code, stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled refreshAndPersist search did not stop")
	}
	select {
	case <-fixture.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("server-side refreshAndPersist request remained after context cancellation")
	}
}

func TestLDAPSearchRefreshAndPersistContextInterruptsCancelWait(t *testing.T) {
	fixture := startLDAPSyncPersistFixtureWithOptions(t, nil, false, false, nil)
	stdout := newLDAPSyncObservedWriter()
	var stderr bytes.Buffer
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan int, 1)
	go func() {
		result <- runWithContext(
			ctx,
			[]string{
				"ldapsearch", "-H", fixture.uri, "-x", "-E", "sync=rp//0",
				"-b", "dc=example,dc=com", "(objectClass=*)",
			},
			strings.NewReader(""),
			stdout,
			&stderr,
			func(string) string { return "" },
		)
	}()
	search := awaitLDAPClientWireMessage(t, fixture.searches)
	fixture.send(t, ldapwire.EncodeIntermediateResponse(
		search.ID,
		ldap.ControlTypeSyncInfo,
		ldapwire.EncodeSyncInfoValue(ldapwire.SyncInfoValue{
			Kind:        ldapwire.SyncInfoRefreshPresent,
			RefreshDone: true,
		}),
		nil,
	))
	awaitLDAPClientWireMessage(t, fixture.cancels)
	cancel()
	select {
	case code := <-result:
		if code != 1 || !strings.Contains(stderr.String(), context.Canceled.Error()) {
			t.Fatalf("Cancel-wait interruption exit=%d stderr=%q", code, stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("context cancellation did not interrupt the RFC 3909 Cancel wait")
	}
	select {
	case <-fixture.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Cancel-wait interruption left the server connection open")
	}
}

func TestLDAPSearchRefreshAndPersistDisablesLongLivedRequestTimeout(t *testing.T) {
	fixture := startLDAPSyncPersistFixture(t)
	stdout := newLDAPSyncObservedWriter()
	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	result := make(chan int, 1)
	go func() {
		result <- runWithContext(
			ctx,
			[]string{
				"ldapsearch", "-H", fixture.uri, "-x", "-timeout", "40ms",
				"-E", "sync=rp//0", "-b", "dc=example,dc=com",
				"(objectClass=*)",
			},
			strings.NewReader(""),
			stdout,
			&stderr,
			func(string) string { return "" },
		)
	}()
	search := awaitLDAPClientWireMessage(t, fixture.searches)
	time.Sleep(160 * time.Millisecond)
	select {
	case code := <-result:
		t.Fatalf("idle persistent search inherited the 40ms timeout: exit=%d stderr=%q", code, stderr.String())
	default:
	}

	fixture.send(t, ldapwire.EncodeIntermediateResponse(
		search.ID,
		ldap.ControlTypeSyncInfo,
		ldapwire.EncodeSyncInfoValue(ldapwire.SyncInfoValue{
			Kind:        ldapwire.SyncInfoRefreshPresent,
			RefreshDone: true,
		}),
		nil,
	))
	awaitLDAPClientWireMessage(t, fixture.cancels)
	select {
	case code := <-result:
		if code != 0 || stderr.String() != "" {
			t.Fatalf("idle persistent search exit=%d stderr=%q", code, stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("idle persistent search did not finish after Cancel")
	}
}

func TestLDAPSearchRefreshAndPersistStreamsAfterSASLObserverInstall(t *testing.T) {
	const password = "sync-sasl-secret"
	fixture := startLDAPSyncPersistFixture(t)
	stdout := newLDAPSyncObservedWriter()
	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan int, 1)
	go func() {
		result <- runWithContext(
			ctx,
			[]string{
				"ldapsearch", "-H", fixture.uri,
				"-Y", "PLAIN", "-U", "alice", "-w", password,
				"-E", "sync=rp/csn=sasl/1", "-LLL",
				"-b", "dc=example,dc=com", "(objectClass=*)", "cn",
			},
			strings.NewReader(""),
			stdout,
			&stderr,
			func(string) string { return "" },
		)
	}()
	bind := awaitLDAPClientWireMessage(t, fixture.binds)
	bindRequest, ok := bind.Request.(ldapwire.BindRequest)
	if !ok || !bindRequest.Authentication.IsSASL ||
		bindRequest.Authentication.SASLMechanism != "PLAIN" {
		t.Fatalf("SASL bind = %#v", bind)
	}
	search := awaitLDAPClientWireMessage(t, fixture.searches)
	requireLDAPSyncPersistRequest(t, search, "csn=sasl")
	fixture.send(t, ldapwire.EncodeIntermediateResponse(
		search.ID,
		ldap.ControlTypeSyncInfo,
		ldapwire.EncodeSyncInfoValue(ldapwire.SyncInfoValue{
			Kind:        ldapwire.SyncInfoRefreshPresent,
			RefreshDone: true,
		}),
		nil,
	))
	fixture.send(t, ldapSyncPersistEntry(
		search.ID,
		"uid=sasl-persist,dc=example,dc=com",
		"SASL Persist",
		ldapwire.SyncStateAdd,
		0x40,
	))
	stdout.awaitContains(t, "dn: uid=sasl-persist,dc=example,dc=com\n")
	if target := requireLDAPSyncCancelTarget(
		t,
		awaitLDAPClientWireMessage(t, fixture.cancels),
	); target != search.ID {
		t.Fatalf("SASL Cancel target = %d, want %d", target, search.ID)
	}
	select {
	case code := <-result:
		if code != 0 || stderr.String() != "" {
			t.Fatalf("SASL persistent search exit=%d stderr=%q", code, stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SASL persistent search did not finish")
	}
	select {
	case <-fixture.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("SASL persistent search transport remained open")
	}
}

func TestLDAPSearchRefreshAndPersistOverObservedTLS(t *testing.T) {
	for _, test := range []struct {
		name     string
		startTLS bool
	}{
		{name: "LDAPS"},
		{name: "StartTLS", startTLS: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverTLS, certificatePEM := newLDAPClientToolTLSConfig(t)
			fixture := startLDAPSyncPersistFixtureWithOptions(
				t,
				serverTLS,
				test.startTLS,
				true,
				nil,
			)
			caPath := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(caPath, certificatePEM, 0o600); err != nil {
				t.Fatal(err)
			}
			arguments := []string{"ldapsearch", "-H", fixture.uri, "-x"}
			if test.startTLS {
				arguments = append(arguments, "-ZZ")
			}
			arguments = append(arguments,
				"-tls-ca", caPath, "-tls-server-name", "localhost",
				"-E", "sync=rp/csn=tls/1", "-LLL",
				"-b", "dc=example,dc=com", "(objectClass=*)", "cn",
			)
			stdout := newLDAPSyncObservedWriter()
			var stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			result := make(chan int, 1)
			go func() {
				result <- runWithContext(
					ctx,
					arguments,
					strings.NewReader(""),
					stdout,
					&stderr,
					func(string) string { return "" },
				)
			}()
			awaitLDAPClientWireMessage(t, fixture.binds)
			search := awaitLDAPClientWireMessage(t, fixture.searches)
			requireLDAPSyncPersistRequest(t, search, "csn=tls")
			fixture.send(t, ldapwire.EncodeIntermediateResponse(
				search.ID,
				ldap.ControlTypeSyncInfo,
				ldapwire.EncodeSyncInfoValue(ldapwire.SyncInfoValue{
					Kind:        ldapwire.SyncInfoRefreshPresent,
					RefreshDone: true,
				}),
				nil,
			))
			fixture.send(t, ldapSyncPersistEntry(
				search.ID,
				"uid=tls-persist,dc=example,dc=com",
				"TLS Persist",
				ldapwire.SyncStateModify,
				0x50,
			))
			stdout.awaitContains(t, "dn: uid=tls-persist,dc=example,dc=com\n")
			if target := requireLDAPSyncCancelTarget(
				t,
				awaitLDAPClientWireMessage(t, fixture.cancels),
			); target != search.ID {
				t.Fatalf("TLS Cancel target = %d, want %d", target, search.ID)
			}
			select {
			case code := <-result:
				if code != 0 || stderr.String() != "" {
					t.Fatalf("TLS persistent search exit=%d stderr=%q", code, stderr.String())
				}
			case <-time.After(2 * time.Second):
				t.Fatal("TLS persistent search did not finish")
			}
			select {
			case <-fixture.closed:
			case <-time.After(2 * time.Second):
				t.Fatal("TLS persistent search transport remained open")
			}
		})
	}
}

func TestLDAPSearchRefreshAndPersistParserBoundaries(t *testing.T) {
	tests := []struct {
		value string
		mode  ldapwire.SyncMode
		limit int64
		valid bool
	}{
		{value: "sync=ro/csn=one", mode: ldapwire.SyncRefreshOnly, limit: -1, valid: true},
		{value: "sync=rp", mode: ldapwire.SyncRefreshAndPersist, limit: -1, valid: true},
		{value: "sync=rp/", mode: ldapwire.SyncRefreshAndPersist, limit: -1, valid: true},
		{value: "sync=rp//0", mode: ldapwire.SyncRefreshAndPersist, limit: 0, valid: true},
		{value: "sync=rp/csn=one/17", mode: ldapwire.SyncRefreshAndPersist, limit: 17, valid: true},
		{value: "!sync=rp//2147483647", mode: ldapwire.SyncRefreshAndPersist, limit: 2147483647, valid: true},
		{value: "sync=rp//-1", mode: ldapwire.SyncRefreshAndPersist, limit: -1, valid: true},
		{value: "sync=rp//-2", mode: ldapwire.SyncRefreshAndPersist, limit: -2, valid: true},
		{value: "sync=rp//2147483648"},
		{value: "sync=rp//not-a-number"},
		{value: "sync=rp/cookie/1/extra"},
		{value: "sync=ro/cookie/1"},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			options, control, err := parseLDAPSearchSyncExtensionValue(test.value)
			if !test.valid {
				if err == nil || control != nil {
					t.Fatalf("invalid sync extension = %#v, %#v, %v", options, control, err)
				}
				return
			}
			if err != nil || control == nil {
				t.Fatalf("parse sync extension: %#v, %v", control, err)
			}
			defer clearLDAPControls([]ldap.Control{control})
			if options.mode != test.mode || options.responseLimit != test.limit {
				t.Fatalf("sync options = %#v, want mode=%d limit=%d", options, test.mode, test.limit)
			}
		})
	}
}

func TestLDAPSearchRefreshOnlyKeepsBufferedOutput(t *testing.T) {
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		if _, search := message.Request.(ldapwire.SearchRequest); !search {
			return nil, nil
		}
		return [][]byte{
			ldapSyncPersistEntry(
				message.ID,
				"uid=refresh-only,dc=example,dc=com",
				"Refresh Only",
				ldapwire.SyncStatePresent,
				0x70,
			),
			ldapwire.EncodeSearchResultDone(
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultSuccess},
				nil,
			),
		}, nil
	})
	baseArguments := []string{
		"ldapsearch", "-H", fixture.uri, "-x", "-LLL",
		"-b", "dc=example,dc=com", "(objectClass=*)", "cn",
	}
	plainOut, plainErr, plainCode := runLDAPClientCommand(baseArguments, "")
	refreshArgs := append([]string(nil), baseArguments[:4]...)
	refreshArgs = append(refreshArgs, "-E", "sync=ro/csn=refresh-only")
	refreshArgs = append(refreshArgs, baseArguments[4:]...)
	refreshOut, refreshErr, refreshCode := runLDAPClientCommand(refreshArgs, "")
	if plainCode != 0 || refreshCode != 0 || plainErr != "" || refreshErr != "" {
		t.Fatalf(
			"plain=%d/%q refreshOnly=%d/%q",
			plainCode,
			plainErr,
			refreshCode,
			refreshErr,
		)
	}
	if refreshOut != plainOut {
		t.Fatalf("refreshOnly changed buffered output:\nplain: %q\nro:    %q", plainOut, refreshOut)
	}
}

func TestLDAPSearchResponseObserverReleasesStreamingResponses(t *testing.T) {
	observer := &ldapSearchResponseObserver{
		responses: make(map[int64][]ldapSearchWireResponse),
	}
	request := ber.NewSequence("LDAP Request")
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(7), "Message ID",
	))
	request.AppendChild(ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldap.ApplicationSearchRequest,
		nil,
		"Search Request",
	))
	observer.observeWrite(request.Bytes())

	response := ldapwire.EncodeIntermediateResponse(
		7,
		ldap.ControlTypeSyncInfo,
		ldapwire.EncodeSyncInfoValue(ldapwire.SyncInfoValue{
			Kind:      ldapwire.SyncInfoNewCookie,
			Cookie:    []byte("bounded"),
			HasCookie: true,
		}),
		nil,
	)
	for range 10000 {
		observer.observeRead(response)
		messageID, _, ok := observer.takeNextSearchResponse()
		if !ok || messageID != 7 {
			t.Fatalf("stream response = id %d, ok %v", messageID, ok)
		}
		observer.mu.Lock()
		pending := len(observer.responses)
		buffered := len(observer.readBuffer)
		observer.mu.Unlock()
		if pending != 0 || buffered != 0 {
			t.Fatalf("observer retained pending=%d buffered=%d", pending, buffered)
		}
	}
	observer.finishSearchResponses(7)
	if len(observer.searchIDs) != 0 || len(observer.responses) != 0 {
		t.Fatalf("finished observer retained ids=%v responses=%v", observer.searchIDs, observer.responses)
	}
}

func TestOpenLDAPReferenceLDAPSearchRefreshAndPersistNegativeLimit(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") == "" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 to run the OpenLDAP sync differential")
	}
	if got := os.Getenv("OPENLDAP_REFERENCE_VERIFIED"); got != "1" {
		t.Fatalf("OPENLDAP_REFERENCE_VERIFIED = %q, want 1", got)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPClientToolsCommit {
		t.Fatalf("OPENLDAP_COMMIT = %q, want %q", got, openLDAPClientToolsCommit)
	}
	referenceTool := filepath.Join(os.Getenv("OPENLDAP_BUILD"), "clients", "tools", "ldapsearch")
	if _, err := os.Stat(referenceTool); err != nil {
		var lookupErr error
		referenceTool, lookupErr = exec.LookPath("ldapsearch")
		if lookupErr != nil {
			t.Fatalf("find OpenLDAP ldapsearch: %v", lookupErr)
		}
	}
	version, err := exec.Command(referenceTool, "-VV").CombinedOutput()
	if err != nil || !bytes.Contains(version, []byte("ldapsearch 2.6.13")) {
		t.Fatalf("OpenLDAP reference is not ldapsearch 2.6.13: %v\n%s", err, version)
	}
	arguments := []string{
		"-x", "-E", "sync=rp/csn=negative/-2",
		"-b", "dc=example,dc=com", "(objectClass=*)", "cn",
	}

	referenceFixture := startLDAPSyncPersistFixtureWithOptions(t, nil, false, false, nil)
	referenceStdout := newLDAPSyncObservedWriter()
	var referenceStderr bytes.Buffer
	referenceCommand := exec.Command(
		referenceTool,
		append([]string{"-H", referenceFixture.uri}, arguments...)...,
	)
	referenceCommand.Stdout = referenceStdout
	referenceCommand.Stderr = &referenceStderr
	if err := referenceCommand.Start(); err != nil {
		t.Fatal(err)
	}
	referenceSearch := awaitLDAPClientWireMessage(t, referenceFixture.searches)
	referenceSync := requireLDAPSyncPersistRequest(t, referenceSearch, "csn=negative")
	referenceFixture.send(t, ldapwire.EncodeIntermediateResponse(
		referenceSearch.ID,
		ldap.ControlTypeSyncInfo,
		ldapwire.EncodeSyncInfoValue(ldapwire.SyncInfoValue{
			Kind:        ldapwire.SyncInfoRefreshPresent,
			RefreshDone: true,
		}),
		nil,
	))
	referenceStdout.awaitContains(t, "# refresh done, switching to persist stage\n")
	referenceCancel := awaitLDAPClientWireMessage(t, referenceFixture.cancels)
	referenceTarget := requireLDAPSyncCancelTarget(t, referenceCancel)
	if err := referenceCommand.Process.Kill(); err != nil {
		t.Fatalf("stop OpenLDAP after observing negative slimit Cancel: %v", err)
	}
	_ = referenceCommand.Wait()

	localFixture := startLDAPSyncPersistFixture(t)
	localStdout := newLDAPSyncObservedWriter()
	var localStderr bytes.Buffer
	localResult := make(chan int, 1)
	go func() {
		localResult <- runWithContext(
			t.Context(),
			append(
				[]string{"ldapsearch", "-H", localFixture.uri},
				arguments...,
			),
			strings.NewReader(""),
			localStdout,
			&localStderr,
			func(string) string { return "" },
		)
	}()
	localSearch := awaitLDAPClientWireMessage(t, localFixture.searches)
	localSync := requireLDAPSyncPersistRequest(t, localSearch, "csn=negative")
	localFixture.send(t, ldapwire.EncodeIntermediateResponse(
		localSearch.ID,
		ldap.ControlTypeSyncInfo,
		ldapwire.EncodeSyncInfoValue(ldapwire.SyncInfoValue{
			Kind:        ldapwire.SyncInfoRefreshPresent,
			RefreshDone: true,
		}),
		nil,
	))
	localStdout.awaitContains(t, "# refresh done, switching to persist stage\n")
	localCancel := awaitLDAPClientWireMessage(t, localFixture.cancels)
	localTarget := requireLDAPSyncCancelTarget(t, localCancel)
	select {
	case exitCode := <-localResult:
		if exitCode != 0 || localStderr.String() != "" {
			t.Fatalf("ldap-go ldapsearch exit=%d stderr=%q", exitCode, localStderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ldap-go negative slimit search did not finish")
	}

	if referenceSync.Mode != localSync.Mode ||
		referenceTarget != referenceSearch.ID || localTarget != localSearch.ID {
		t.Fatalf(
			"sync/cancel mismatch: OpenLDAP mode=%d target=%d search=%d; ldap-go mode=%d target=%d search=%d",
			referenceSync.Mode,
			referenceTarget,
			referenceSearch.ID,
			localSync.Mode,
			localTarget,
			localSearch.ID,
		)
	}
	referenceControl := requireLDAPSyncRequestControl(t, referenceSearch)
	localControl := requireLDAPSyncRequestControl(t, localSearch)
	if referenceControl.Critical != localControl.Critical ||
		referenceControl.HasValue != localControl.HasValue ||
		!bytes.Equal(referenceControl.Value, localControl.Value) {
		t.Fatalf(
			"Sync Request differs:\nOpenLDAP: %#v\nldap-go:  %#v",
			referenceControl,
			localControl,
		)
	}
	marker := "# refresh done, switching to persist stage\n"
	referencePrefix := ldapSyncOutputThrough(t, referenceStdout.String(), marker)
	localPrefix := ldapSyncOutputThrough(t, localStdout.String(), marker)
	if localPrefix != referencePrefix {
		t.Fatalf(
			"stream output before negative slimit Cancel differs:\nOpenLDAP: %q\nldap-go:  %q",
			referencePrefix,
			localPrefix,
		)
	}

	assertOpenLDAPClientSourceAnchors(
		t,
		os.Getenv("OPENLDAP_SOURCE"),
		"clients/tools/ldapsearch.c",
		[]string{
			"ival = strtol( slimitp, &next, 10 );",
			"sync_slimit = ival;",
			"nresponses_psearch = 0;",
			"nresponses_psearch >= sync_slimit",
			"ldap_extended_operation(ld, LDAP_EXOP_CANCEL,",
		},
	)
}

type ldapSyncPersistFixture struct {
	uri        string
	listener   net.Listener
	outbound   chan []byte
	binds      chan ldapwire.Message
	searches   chan ldapwire.Message
	cancels    chan ldapwire.Message
	done       chan error
	closed     chan struct{}
	mu         sync.Mutex
	conn       net.Conn
	tls        *tls.Config
	startTLS   bool
	respond    bool
	cancelGate <-chan struct{}
}

type ldapSyncReadResult struct {
	message ldapwire.Message
	err     error
}

func startLDAPSyncPersistFixture(t *testing.T) *ldapSyncPersistFixture {
	return startLDAPSyncPersistFixtureWithOptions(t, nil, false, true, nil)
}

func startLDAPSyncPersistFixtureWithOptions(
	t *testing.T,
	tlsConfig *tls.Config,
	startTLS, respondToCancel bool,
	cancelGate <-chan struct{},
) *ldapSyncPersistFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	scheme := "ldap://"
	if tlsConfig != nil && !startTLS {
		scheme = "ldaps://"
	}
	if cancelGate == nil {
		ready := make(chan struct{})
		close(ready)
		cancelGate = ready
	}
	fixture := &ldapSyncPersistFixture{
		uri:        scheme + listener.Addr().String(),
		listener:   listener,
		outbound:   make(chan []byte),
		binds:      make(chan ldapwire.Message, 1),
		searches:   make(chan ldapwire.Message, 1),
		cancels:    make(chan ldapwire.Message, 1),
		done:       make(chan error, 1),
		closed:     make(chan struct{}),
		tls:        tlsConfig,
		startTLS:   startTLS,
		respond:    respondToCancel,
		cancelGate: cancelGate,
	}
	go fixture.serve()
	t.Cleanup(func() {
		_ = fixture.listener.Close()
		fixture.mu.Lock()
		if fixture.conn != nil {
			_ = fixture.conn.Close()
		}
		fixture.mu.Unlock()
		select {
		case err := <-fixture.done:
			if err != nil {
				t.Errorf("sync fixture: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("sync fixture did not stop")
		}
	})
	return fixture
}

func (fixture *ldapSyncPersistFixture) serve() {
	defer close(fixture.closed)
	connection, err := fixture.listener.Accept()
	if err != nil {
		fixture.done <- err
		return
	}
	fixture.mu.Lock()
	fixture.conn = connection
	fixture.mu.Unlock()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	if fixture.tls != nil && fixture.startTLS {
		request, readErr := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
		if readErr != nil {
			fixture.done <- readErr
			return
		}
		extended, ok := request.Request.(ldapwire.ExtendedRequest)
		if !ok || extended.Name != ldapStartTLSOID {
			fixture.done <- fmt.Errorf("pre-TLS request is %#v, want StartTLS", request)
			return
		}
		if err := ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
			request.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			"",
			nil,
			nil,
		)); err != nil {
			fixture.done <- err
			return
		}
	}
	if fixture.tls != nil {
		secured := tls.Server(connection, fixture.tls.Clone())
		if err := secured.Handshake(); err != nil {
			fixture.done <- err
			return
		}
		connection = secured
		fixture.mu.Lock()
		fixture.conn = connection
		fixture.mu.Unlock()
	}

	requests := make(chan ldapSyncReadResult, 1)
	readerDone := make(chan struct{})
	stopReader := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			message, readErr := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
			select {
			case requests <- ldapSyncReadResult{message: message, err: readErr}:
			case <-stopReader:
				return
			}
			if readErr != nil {
				return
			}
		}
	}()
	defer func() {
		close(stopReader)
		_ = connection.Close()
		<-readerDone
	}()

	read := <-requests
	if read.err != nil {
		fixture.done <- read.err
		return
	}
	if _, ok := read.message.Request.(ldapwire.BindRequest); !ok {
		fixture.done <- fmt.Errorf("first request is %T, want Bind", read.message.Request)
		return
	}
	fixture.binds <- read.message
	if err := ldapwire.Write(connection, ldapwire.EncodeBindResponse(
		read.message.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	)); err != nil {
		fixture.done <- err
		return
	}

	read = <-requests
	if read.err != nil {
		fixture.done <- read.err
		return
	}
	if _, ok := read.message.Request.(ldapwire.SearchRequest); !ok {
		fixture.done <- fmt.Errorf("second request is %T, want Search", read.message.Request)
		return
	}
	fixture.searches <- read.message
	searchID := read.message.ID

	for {
		select {
		case encoded := <-fixture.outbound:
			if err := ldapwire.Write(connection, encoded); err != nil {
				fixture.done <- err
				return
			}
		case read = <-requests:
			if read.err != nil {
				if errors.Is(read.err, io.EOF) || errors.Is(read.err, net.ErrClosed) {
					fixture.done <- nil
				} else {
					fixture.done <- read.err
				}
				return
			}
			extended, ok := read.message.Request.(ldapwire.ExtendedRequest)
			if !ok || extended.Name != ldapCancelOID || !extended.HasValue {
				fixture.done <- fmt.Errorf("request after Search is %#v", read.message)
				return
			}
			target, decodeErr := ldapwire.DecodeCancelRequestValue(extended.Value)
			if decodeErr != nil {
				fixture.done <- decodeErr
				return
			}
			if target != searchID {
				fixture.done <- fmt.Errorf("Cancel target %d, want search %d", target, searchID)
				return
			}
			fixture.cancels <- read.message
			if fixture.respond {
				<-fixture.cancelGate
				if err := ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
					read.message.ID,
					ldapwire.Result{Code: ldapwire.ResultSuccess},
					"",
					nil,
					nil,
				)); err != nil {
					fixture.done <- err
					return
				}
			}
			for {
				read = <-requests
				if read.err != nil {
					if !fixture.respond || errors.Is(read.err, io.EOF) ||
						errors.Is(read.err, net.ErrClosed) {
						fixture.done <- nil
					} else {
						fixture.done <- read.err
					}
					return
				}
				if _, unbind := read.message.Request.(ldapwire.UnbindRequest); unbind {
					fixture.done <- nil
					return
				}
				if fixture.respond {
					if repeated, ok := read.message.Request.(ldapwire.ExtendedRequest); ok &&
						repeated.Name == ldapCancelOID && repeated.HasValue {
						repeatedTarget, err := ldapwire.DecodeCancelRequestValue(repeated.Value)
						if err != nil || repeatedTarget != searchID {
							fixture.done <- fmt.Errorf(
								"repeated Cancel target=%d err=%v, want %d",
								repeatedTarget,
								err,
								searchID,
							)
							return
						}
						if err := ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
							read.message.ID,
							ldapwire.Result{Code: ldapwire.ResultSuccess},
							"",
							nil,
							nil,
						)); err != nil {
							fixture.done <- err
							return
						}
						continue
					}
				}
				fixture.done <- fmt.Errorf(
					"request after Cancel response is %#v",
					read.message,
				)
				return
			}
		}
	}
}

func (fixture *ldapSyncPersistFixture) send(t *testing.T, response []byte) {
	t.Helper()
	select {
	case fixture.outbound <- response:
	case <-time.After(2 * time.Second):
		t.Fatal("sync fixture did not accept response")
	}
}

func requireLDAPSyncPersistRequest(
	t *testing.T,
	message ldapwire.Message,
	wantCookie string,
) ldapwire.SyncRequestValue {
	t.Helper()
	for _, control := range message.Controls {
		if control.OID != ldapSyncRequestOID {
			continue
		}
		request, err := ldapwire.DecodeSyncRequestValue(control.Value)
		if err != nil {
			t.Fatal(err)
		}
		if string(request.Cookie) != wantCookie || !request.HasCookie {
			t.Fatalf("sync cookie = %q present=%v, want %q", request.Cookie, request.HasCookie, wantCookie)
		}
		return request
	}
	t.Fatalf("Search controls %#v lack Sync Request", message.Controls)
	return ldapwire.SyncRequestValue{}
}

func requireLDAPSyncRequestControl(
	t *testing.T,
	message ldapwire.Message,
) ldapwire.Control {
	t.Helper()
	for _, control := range message.Controls {
		if control.OID == ldapSyncRequestOID {
			return control
		}
	}
	t.Fatalf("Search controls %#v lack Sync Request", message.Controls)
	return ldapwire.Control{}
}

func requireLDAPSyncCancelTarget(t *testing.T, message ldapwire.Message) int64 {
	t.Helper()
	extended, ok := message.Request.(ldapwire.ExtendedRequest)
	if !ok || extended.Name != ldapCancelOID || !extended.HasValue {
		t.Fatalf("Cancel request = %#v", message)
	}
	target, err := ldapwire.DecodeCancelRequestValue(extended.Value)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func ldapSyncOutputThrough(t *testing.T, output, marker string) string {
	t.Helper()
	end := strings.Index(output, marker)
	if end < 0 {
		t.Fatalf("sync output lacks %q: %q", marker, output)
	}
	return output[:end+len(marker)]
}

func ldapSyncPersistEntry(
	messageID int64,
	dn, commonName string,
	state ldapwire.SyncState,
	uuidByte byte,
) []byte {
	var entryUUID ldapwire.SyncUUID
	for index := range entryUUID {
		entryUUID[index] = uuidByte + byte(index)
	}
	return ldapwire.EncodeSearchResultEntry(
		messageID,
		directory.Entry{
			DN: dn,
			Attributes: []directory.Attribute{{
				Description: "cn",
				Values:      [][]byte{[]byte(commonName)},
			}},
		},
		[]ldapwire.Control{{
			OID: ldap.ControlTypeSyncState,
			Value: ldapwire.EncodeSyncStateValue(ldapwire.SyncStateValue{
				State:     state,
				EntryUUID: entryUUID,
				Cookie:    []byte("csn=" + commonName),
				HasCookie: true,
			}),
			HasValue: true,
		}},
	)
}

type ldapSyncObservedWriter struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	changed chan struct{}
}

func newLDAPSyncObservedWriter() *ldapSyncObservedWriter {
	return &ldapSyncObservedWriter{changed: make(chan struct{}, 1)}
}

func (writer *ldapSyncObservedWriter) Write(value []byte) (int, error) {
	writer.mu.Lock()
	written, err := writer.buffer.Write(value)
	writer.mu.Unlock()
	select {
	case writer.changed <- struct{}{}:
	default:
	}
	return written, err
}

func (writer *ldapSyncObservedWriter) String() string {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.buffer.String()
}

func (writer *ldapSyncObservedWriter) awaitContains(t *testing.T, expected string) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		if strings.Contains(writer.String(), expected) {
			return
		}
		select {
		case <-writer.changed:
		case <-deadline.C:
			t.Fatalf("stream output did not contain %q:\n%s", expected, writer.String())
		}
	}
}
