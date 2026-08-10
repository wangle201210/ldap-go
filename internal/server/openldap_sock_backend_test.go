package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPSockReferenceVersion = "2.6.13"
	openLDAPSockReferenceCommit  = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

	openLDAPSockBaseDN      = "dc=sock,dc=example"
	openLDAPSockBindDN      = "uid=operator," + openLDAPSockBaseDN
	openLDAPSockCreatedDN   = "uid=created," + openLDAPSockBaseDN
	openLDAPSockRenamedDN   = "uid=renamed," + openLDAPSockBaseDN
	openLDAPSockPassword    = "sock-secret"
	openLDAPSockPasswordOID = "1.3.6.1.4.1.4203.1.11.1"
)

type openLDAPSockClientResult struct {
	bindCode       uint16
	searchCode     uint16
	searchEntries  []string
	addCode        uint16
	modifyCode     uint16
	compareCode    uint16
	compareMatched bool
	modifyDNCode   uint16
	deleteCode     uint16
	extendedCode   uint16
	unbindCode     uint16
}

type openLDAPSockCapturedRequest struct {
	command string
	fields  map[string][]string
	raw     string
}

type openLDAPSockFixture struct {
	path     string
	listener net.Listener
	requests chan openLDAPSockCapturedRequest
	failures chan error
	done     chan struct{}
}

func TestOpenLDAPReferenceSockBackend(t *testing.T) {
	tools := requireOpenLDAPSockReferenceTools(t)
	fixture := startOpenLDAPSockFixture(t)

	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		fmt.Sprintf(`access to * by * read

database sock
suffix "%s"
socketpath "%s"
extensions binddn peername ssf connid
access to * by * manage`, openLDAPSockBaseDN, fixture.path),
		"",
	)
	defer stopOpenLDAP()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoSockReferenceConfiguration(t, store, fixture.path)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{})
	defer stopLDAPGo()

	openLDAPResult := observeOpenLDAPSockScenario(t, openLDAPURI)
	openLDAPRequests := fixture.take(t, 9)
	want := openLDAPSockClientResult{
		bindCode:       ldap.LDAPResultSuccess,
		searchCode:     ldap.LDAPResultSuccess,
		searchEntries:  []string{"uid=socket-user," + openLDAPSockBaseDN + "|cn=Socket User;description=from socket fixture;sn=User;uid=socket-user"},
		addCode:        ldap.LDAPResultSuccess,
		modifyCode:     ldap.LDAPResultSuccess,
		compareCode:    ldap.LDAPResultSuccess,
		compareMatched: true,
		modifyDNCode:   ldap.LDAPResultSuccess,
		deleteCode:     ldap.LDAPResultSuccess,
		extendedCode:   ldap.LDAPResultSuccess,
		unbindCode:     ldap.LDAPResultSuccess,
	}
	if !reflect.DeepEqual(openLDAPResult, want) {
		t.Fatalf("OpenLDAP sock client result = %#v, want %#v", openLDAPResult, want)
	}
	assertOpenLDAPSockRequests(t, "OpenLDAP", openLDAPRequests)

	ldapGoResult := observeOpenLDAPSockScenario(t, "ldap://"+ldapGoAddress)
	ldapGoRequests := fixture.take(t, 9)
	if !reflect.DeepEqual(ldapGoResult, openLDAPResult) {
		t.Fatalf(
			"ldap-go sock client result = %#v, want OpenLDAP %#v",
			ldapGoResult,
			openLDAPResult,
		)
	}
	assertOpenLDAPSockRequests(t, "ldap-go", ldapGoRequests)

	for index := range openLDAPRequests {
		openLDAPFields := comparableOpenLDAPSockFields(openLDAPRequests[index])
		ldapGoFields := comparableOpenLDAPSockFields(ldapGoRequests[index])
		if !reflect.DeepEqual(ldapGoFields, openLDAPFields) {
			t.Fatalf(
				"%s socket fields differ\nOpenLDAP: %#v\nldap-go:  %#v\nOpenLDAP request:\n%s\nldap-go request:\n%s",
				openLDAPRequests[index].command,
				openLDAPFields,
				ldapGoFields,
				openLDAPRequests[index].raw,
				ldapGoRequests[index].raw,
			)
		}
	}
}

func requireOpenLDAPSockReferenceTools(t *testing.T) openLDAPReferenceTools {
	t.Helper()
	tools := requireOpenLDAPReferenceTools(t)
	if got := os.Getenv("OPENLDAP_REFERENCE_VERIFIED"); got != "1" {
		t.Fatalf("OPENLDAP_REFERENCE_VERIFIED = %q, want 1", got)
	}
	if got := os.Getenv("OPENLDAP_ACTUAL_VERSION"); got != openLDAPSockReferenceVersion {
		t.Fatalf("OPENLDAP_ACTUAL_VERSION = %q, want %q", got, openLDAPSockReferenceVersion)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPSockReferenceCommit {
		t.Fatalf("OPENLDAP_COMMIT = %q, want %q", got, openLDAPSockReferenceCommit)
	}

	output, err := exec.Command(tools.slapd, "-VVV").CombinedOutput()
	if len(output) == 0 {
		t.Skipf("inspect OpenLDAP backends: %v", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.EqualFold(strings.TrimSpace(line), "sock") {
			return tools
		}
	}
	t.Skip("the pinned OpenLDAP slapd was not built with the sock backend")
	return openLDAPReferenceTools{}
}

func startOpenLDAPSockFixture(t *testing.T) *openLDAPSockFixture {
	t.Helper()
	directoryPath, err := os.MkdirTemp("", "ldap-go-sock-")
	if err != nil {
		t.Fatalf("create sock fixture directory: %v", err)
	}
	path := filepath.Join(directoryPath, "backend.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		_ = os.RemoveAll(directoryPath)
		t.Fatalf("listen on sock fixture %s: %v", path, err)
	}
	fixture := &openLDAPSockFixture{
		path:     path,
		listener: listener,
		requests: make(chan openLDAPSockCapturedRequest, 32),
		failures: make(chan error, 1),
		done:     make(chan struct{}),
	}
	go fixture.serve()
	t.Cleanup(func() {
		_ = fixture.listener.Close()
		<-fixture.done
		_ = os.RemoveAll(directoryPath)
	})
	return fixture
}

func (fixture *openLDAPSockFixture) serve() {
	defer close(fixture.done)
	for {
		connection, err := fixture.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			fixture.report(fmt.Errorf("accept sock request: %w", err))
			return
		}
		if err := fixture.handle(connection); err != nil {
			fixture.report(err)
			return
		}
	}
}

func (fixture *openLDAPSockFixture) handle(connection net.Conn) error {
	defer connection.Close()
	scanner := bufio.NewScanner(connection)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	lines := make([]string, 0, 32)
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			break
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read sock request: %w", err)
	}
	if len(lines) == 0 {
		return errors.New("read empty sock request")
	}
	request, err := parseOpenLDAPSockRequest(lines)
	if err != nil {
		return err
	}
	fixture.requests <- request
	if request.command == "UNBIND" {
		return nil
	}
	if _, err := connection.Write([]byte(openLDAPSockFixtureResponse(request.command))); err != nil {
		return fmt.Errorf("write %s sock response: %w", request.command, err)
	}
	return nil
}

func (fixture *openLDAPSockFixture) report(err error) {
	select {
	case fixture.failures <- err:
	default:
	}
}

func (fixture *openLDAPSockFixture) take(
	t *testing.T,
	count int,
) []openLDAPSockCapturedRequest {
	t.Helper()
	requests := make([]openLDAPSockCapturedRequest, 0, count)
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for len(requests) < count {
		select {
		case request := <-fixture.requests:
			requests = append(requests, request)
		case err := <-fixture.failures:
			t.Fatalf("sock fixture failed after %d requests: %v", len(requests), err)
		case <-timer.C:
			t.Fatalf("timed out after receiving %d/%d sock requests", len(requests), count)
		}
	}
	return requests
}

func parseOpenLDAPSockRequest(lines []string) (openLDAPSockCapturedRequest, error) {
	logicalLines := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(line, " ") {
			if len(logicalLines) == 0 {
				return openLDAPSockCapturedRequest{}, errors.New("sock request starts with an LDIF continuation")
			}
			logicalLines[len(logicalLines)-1] += strings.TrimPrefix(line, " ")
			continue
		}
		logicalLines = append(logicalLines, line)
	}
	request := openLDAPSockCapturedRequest{
		command: strings.ToUpper(logicalLines[0]),
		fields:  make(map[string][]string),
		raw:     strings.Join(lines, "\n") + "\n\n",
	}
	for _, line := range logicalLines[1:] {
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimPrefix(value, " ")
		key := strings.ToLower(strings.TrimSpace(name))
		request.fields[key] = append(request.fields[key], value)
	}
	return request, nil
}

func openLDAPSockFixtureResponse(command string) string {
	if command == "SEARCH" {
		return `# generated by the differential fixture
DEBUG: SEARCH response
dn: uid=socket-user,dc=sock,dc=example
objectClass: inetOrgPerson
uid: socket-user
cn: Socket User
sn: User
description: from socket fixture

RESULT
code: 0
matched:
info: search complete

`
	}
	code := 0
	if command == "COMPARE" {
		code = ldap.LDAPResultCompareTrue
	}
	return fmt.Sprintf("RESULT\ncode: %d\nmatched:\ninfo: %s complete\n\n", code, strings.ToLower(command))
}

func seedLDAPGoSockReferenceConfiguration(
	t *testing.T,
	store storage.Store,
	socketPath string,
) {
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
			},
		},
		{
			DN: "olcDatabase={1}sock,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcDbSocketConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}sock")},
				{Description: "olcSuffix", Values: stringValues(openLDAPSockBaseDN)},
				{Description: "olcDbSocketPath", Values: stringValues(socketPath)},
				{Description: "olcDbSocketExtensions", Values: stringValues("binddn", "peername", "ssf", "connid")},
				{Description: "olcAccess", Values: stringValues("{0}to * by * manage")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{openLDAPSockBaseDN, "cn=config"})
	}); err != nil {
		t.Fatalf("seed ldap-go sock configuration: %v", err)
	}
}

func observeOpenLDAPSockScenario(t *testing.T, uri string) openLDAPSockClientResult {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	client.SetTimeout(3 * time.Second)
	defer client.Close()

	result := openLDAPSockClientResult{}
	result.bindCode = monitorLDAPResultCode(client.Bind(openLDAPSockBindDN, openLDAPSockPassword))

	search, err := client.Search(ldap.NewSearchRequest(
		openLDAPSockBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		7,
		3,
		false,
		"(&(objectClass=inetOrgPerson)(uid=socket-user))",
		[]string{"uid", "cn", "sn", "description"},
		nil,
	))
	result.searchCode = monitorLDAPResultCode(err)
	if search != nil {
		result.searchEntries = normalizedOpenLDAPSockEntries(search.Entries)
	}

	add := ldap.NewAddRequest(openLDAPSockCreatedDN, nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"created"})
	add.Attribute("cn", []string{"Created User"})
	add.Attribute("sn", []string{"User"})
	result.addCode = monitorLDAPResultCode(client.Add(add))

	modify := ldap.NewModifyRequest(openLDAPSockCreatedDN, nil)
	modify.Replace("description", []string{"updated by socket"})
	result.modifyCode = monitorLDAPResultCode(client.Modify(modify))

	result.compareMatched, err = client.Compare(
		openLDAPSockCreatedDN,
		"description",
		"updated by socket",
	)
	result.compareCode = monitorLDAPResultCode(err)

	result.modifyDNCode = monitorLDAPResultCode(client.ModifyDN(
		ldap.NewModifyDNRequest(openLDAPSockCreatedDN, "uid=renamed", true, ""),
	))
	result.deleteCode = monitorLDAPResultCode(client.Del(
		ldap.NewDelRequest(openLDAPSockRenamedDN, nil),
	))

	_, err = client.PasswordModify(ldap.NewPasswordModifyRequest(
		openLDAPSockBindDN,
		"",
		"rotated-secret",
	))
	result.extendedCode = monitorLDAPResultCode(err)
	result.unbindCode = monitorLDAPResultCode(client.Unbind())
	return result
}

func normalizedOpenLDAPSockEntries(entries []*ldap.Entry) []string {
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		attributes := make([]string, 0, len(entry.Attributes))
		for _, attribute := range entry.Attributes {
			values := append([]string(nil), attribute.Values...)
			sort.Strings(values)
			attributes = append(
				attributes,
				strings.ToLower(attribute.Name)+"="+strings.Join(values, ","),
			)
		}
		sort.Strings(attributes)
		result = append(result, strings.ToLower(entry.DN)+"|"+strings.Join(attributes, ";"))
	}
	sort.Strings(result)
	return result
}

func assertOpenLDAPSockRequests(
	t *testing.T,
	implementation string,
	requests []openLDAPSockCapturedRequest,
) {
	t.Helper()
	wantCommands := []string{
		"BIND",
		"SEARCH",
		"ADD",
		"MODIFY",
		"COMPARE",
		"MODRDN",
		"DELETE",
		"EXTENDED",
		"UNBIND",
	}
	for index, command := range wantCommands {
		request := requests[index]
		if request.command != command {
			t.Fatalf("%s sock request %d command = %q, want %q\n%s", implementation, index, request.command, command, request.raw)
		}
		assertOpenLDAPSockField(t, implementation, request, "msgid", strconv.Itoa(index+1))
		assertOpenLDAPSockField(t, implementation, request, "suffix", openLDAPSockBaseDN)
		assertOpenLDAPSockField(t, implementation, request, "ssf", "0")
		wantBindDN := openLDAPSockBindDN
		if command == "BIND" {
			wantBindDN = ""
		}
		assertOpenLDAPSockField(t, implementation, request, "binddn", wantBindDN)
		peerNames := request.fields["peername"]
		if len(peerNames) != 1 || !strings.HasPrefix(peerNames[0], "IP=127.0.0.1:") {
			t.Fatalf("%s %s peername = %#v, want one IPv4 peer name\n%s", implementation, command, peerNames, request.raw)
		}
		connectionIDs := request.fields["connid"]
		if len(connectionIDs) != 1 {
			t.Fatalf("%s %s connid = %#v, want one value\n%s", implementation, command, connectionIDs, request.raw)
		}
		if _, err := strconv.ParseUint(connectionIDs[0], 10, 64); err != nil {
			t.Fatalf("%s %s connid = %q: %v\n%s", implementation, command, connectionIDs[0], err, request.raw)
		}
	}

	assertOpenLDAPSockFields(t, implementation, requests[0], map[string][]string{
		"dn":      {openLDAPSockBindDN},
		"method":  {"128"},
		"credlen": {strconv.Itoa(len(openLDAPSockPassword))},
		"cred":    {openLDAPSockPassword},
	})
	assertOpenLDAPSockFields(t, implementation, requests[1], map[string][]string{
		"base":      {openLDAPSockBaseDN},
		"scope":     {"2"},
		"deref":     {"0"},
		"sizelimit": {"7"},
		"timelimit": {"3"},
		"filter":    {"(&(objectClass=inetOrgPerson)(uid=socket-user))"},
		"attrsonly": {"0"},
		"attrs":     {"uid cn sn description"},
	})
	assertOpenLDAPSockFields(t, implementation, requests[2], map[string][]string{
		"dn":          {openLDAPSockCreatedDN},
		"objectclass": {"inetOrgPerson"},
		"uid":         {"created"},
		"cn":          {"Created User"},
		"sn":          {"User"},
	})
	assertOpenLDAPSockFields(t, implementation, requests[3], map[string][]string{
		"dn":          {openLDAPSockCreatedDN},
		"replace":     {"description"},
		"description": {"updated by socket"},
	})
	assertOpenLDAPSockFields(t, implementation, requests[4], map[string][]string{
		"dn":          {openLDAPSockCreatedDN},
		"description": {"updated by socket"},
	})
	assertOpenLDAPSockFields(t, implementation, requests[5], map[string][]string{
		"dn":           {openLDAPSockCreatedDN},
		"newrdn":       {"uid=renamed"},
		"deleteoldrdn": {"1"},
	})
	assertOpenLDAPSockField(t, implementation, requests[6], "dn", openLDAPSockRenamedDN)
	assertOpenLDAPSockField(t, implementation, requests[7], "oid", openLDAPSockPasswordOID)
	values := requests[7].fields["value"]
	if len(values) != 1 {
		t.Fatalf("%s EXTENDED value = %#v, want one value\n%s", implementation, values, requests[7].raw)
	}
	decoded, err := base64.StdEncoding.DecodeString(values[0])
	if err != nil {
		t.Fatalf("%s EXTENDED value is not base64: %v\n%s", implementation, err, requests[7].raw)
	}
	for _, fragment := range [][]byte{[]byte(openLDAPSockBindDN), []byte("rotated-secret")} {
		if !bytes.Contains(decoded, fragment) {
			t.Fatalf("%s EXTENDED value does not contain %q\n%s", implementation, fragment, requests[7].raw)
		}
	}
}

func assertOpenLDAPSockFields(
	t *testing.T,
	implementation string,
	request openLDAPSockCapturedRequest,
	want map[string][]string,
) {
	t.Helper()
	for name, values := range want {
		got := request.fields[name]
		if !reflect.DeepEqual(got, values) {
			t.Fatalf("%s %s %s = %#v, want %#v\n%s", implementation, request.command, name, got, values, request.raw)
		}
	}
}

func assertOpenLDAPSockField(
	t *testing.T,
	implementation string,
	request openLDAPSockCapturedRequest,
	name string,
	want string,
) {
	t.Helper()
	assertOpenLDAPSockFields(t, implementation, request, map[string][]string{name: {want}})
}

func comparableOpenLDAPSockFields(
	request openLDAPSockCapturedRequest,
) map[string][]string {
	common := []string{"msgid", "binddn", "suffix", "ssf"}
	operation := map[string][]string{
		"BIND":     {"dn", "method", "credlen", "cred"},
		"SEARCH":   {"base", "scope", "deref", "sizelimit", "timelimit", "filter", "attrsonly", "attrs"},
		"ADD":      {"dn", "objectclass", "uid", "cn", "sn"},
		"MODIFY":   {"dn", "replace", "description"},
		"COMPARE":  {"dn", "description"},
		"MODRDN":   {"dn", "newrdn", "deleteoldrdn", "newsuperior"},
		"DELETE":   {"dn"},
		"EXTENDED": {"oid", "value"},
		"UNBIND":   nil,
	}
	fields := make(map[string][]string)
	for _, name := range append(common, operation[request.command]...) {
		if values, found := request.fields[name]; found {
			fields[name] = append([]string(nil), values...)
		}
	}
	return fields
}
