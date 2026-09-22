package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const smallIndexedPeopleDN = "ou=people,dc=example,dc=com"
const smallIndexedRootDN = "cn=admin,dc=example,dc=com"

func newSmallIndexedFixture(t testing.TB, people int) (*Server, *connectionState) {
	t.Helper()
	store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ParseAndRegisterAttributeType(
		"( 1.2.3.4 NAME 'c-description' SUP description COLLECTIVE )",
	); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		entries := []directory.Entry{
			{DN: "dc=example,dc=com", Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("domain")},
				{Description: "dc", Values: stringValues("example")},
			}},
			{DN: smallIndexedPeopleDN, Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit")},
				{Description: "ou", Values: stringValues("people")},
			}},
			{DN: "ou=archive,dc=example,dc=com", Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit")},
				{Description: "ou", Values: stringValues("archive")},
			}},
			{DN: "olcDatabase={1}mdb,cn=config", Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				{Description: "olcDbIndex", Values: stringValues("uid,cn,sn,objectClass,uidNumber eq")},
				{Description: "olcAccess", Values: stringValues("to * by * none")},
			}},
		}
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		for i := range people {
			uid := fmt.Sprintf("person-%05d", i)
			uids := []string{uid}
			if i < 4 {
				uids = append(uids, "four")
			}
			if i < 5 {
				uids = append(uids, "five")
			}
			if err := writer.Put(directory.Entry{
				DN: "uid=" + uid + "," + smallIndexedPeopleDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("inetOrgPerson")},
					{Description: "uid", Values: stringValues(uids...)},
					{Description: "cn", Values: stringValues(fmt.Sprintf("Person %05d", i))},
					{Description: "cn;lang-en", Values: stringValues(fmt.Sprintf("English %05d", i))},
					{Description: "sn", Values: stringValues("Example")},
					{Description: "uidNumber", Values: stringValues(fmt.Sprint(i))},
					{Description: "jpegPhoto", Values: [][]byte{{0, byte(i), 255}}},
					{Description: "description", Values: stringValues("original")},
				},
			}, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{Store: store, Schema: registry, RootDN: smallIndexedRootDN,
		RootPassword: []byte("secret"), MaxSearchEntries: people + 20})
	if err != nil {
		t.Fatal(err)
	}
	state := &connectionState{runtime: server.runtime.Load(), boundDN: smallIndexedRootDN}
	base, err := normalizeConnectionSearchRequestBase(state, smallIndexedPeopleDN)
	if err != nil {
		t.Fatal(err)
	}
	routes := databaseSearchRoutesFromNormalizedBase(state.runtime.databases, base, directory.ScopeWholeSubtree)
	if err := server.ensureSearchEqualityIndexes(t.Context(), state.runtime, routes); err != nil {
		t.Fatal(err)
	}
	return server, state
}

func smallIndexedSDKRequest(filter string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(smallIndexedPeopleDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, []string{"uid", "cn", "sn", "jpegPhoto"}, nil)
}

// Force the general handler with the same prelude and caches as a wrapper miss.
// This is test-only: no control, filter, identity, or production switch changes.
func smallIndexedTestPrelude(server *Server, state *connectionState, message ldapwire.Message) (searchRequestPrelude, *runtimeDatabase) {
	request := message.Request.(ldapwire.SearchRequest)
	base, err := normalizeConnectionSearchRequestBase(state, request.BaseDN)
	if err != nil || len(message.Controls) != 0 || state.passwordPolicyRestrictedDN != "" {
		return searchRequestPrelude{}, nil
	}
	prelude := searchRequestPrelude{base: base, baseReady: true, evaluated: true}
	database := databaseForNormalizedDN(state.runtime, base)
	if database != nil && base.Depth() > 0 {
		request.BaseDN = base.String()
		prelude.fingerprint, prelude.cacheable = server.rootEqualitySearchCacheFingerprint(state, *database, request, nil)
		prelude.revision, prelude.hasRevision = server.currentStorageSnapshotRevision(context.Background())
		prelude.cacheable = prelude.cacheable && prelude.hasRevision
	}
	return prelude, database
}

type smallIndexedCapture struct {
	net.Conn
	bytes.Buffer
	onWrite func()
	err     error
}

func (capture *smallIndexedCapture) Read(value []byte) (int, error) {
	return capture.Buffer.Read(value)
}

func (capture *smallIndexedCapture) Write(value []byte) (int, error) {
	if capture.onWrite != nil {
		capture.onWrite()
	}
	if capture.err != nil {
		return 0, capture.err
	}
	return capture.Buffer.Write(value)
}

type smallIndexedOutcome struct {
	wire         []byte
	handlerError string
	handled      bool
	code         int
	entries      int
	diagnostic   string
	memory       int64
	rejections   uint64
}

func smallIndexedEvaluate(server *Server, state *connectionState, message ldapwire.Message, mode string) smallIndexedOutcome {
	capture := &smallIndexedCapture{}
	observation := &operationAuditObservation{}
	operation := newTrackedOperation(context.Background(), message)
	operation.start()
	defer operation.finish()
	connection := &operationResponseConnection{Conn: capture, operation: operation, audit: observation}
	request := message.Request.(ldapwire.SearchRequest)
	prelude, database := smallIndexedTestPrelude(server, state, message)
	var handled bool
	var err error
	if mode == "wrapper" {
		err = server.handleSearch(operation.ctx, connection, state, message, request)
	} else {
		if mode == "small" && prelude.cacheable {
			handled, err = server.trySmallIndexedSearch(operation.ctx, connection, state, message, request, prelude, database)
			if !handled && capture.Len() != 0 {
				panic("small indexed fallback wrote a response")
			}
		}
		if !handled {
			err = server.handleUncachedSearch(operation.ctx, connection, state, message, request, prelude)
		}
	}
	outcome := smallIndexedOutcome{wire: bytes.Clone(capture.Bytes()), handled: handled,
		code: observation.result, entries: observation.entries, diagnostic: observation.diagnostic,
		memory: server.searchMemoryLimiter.active.Load(), rejections: server.searchMemoryLimiter.rejected.Load()}
	if err != nil {
		outcome.handlerError = err.Error()
	}
	return outcome
}

func smallIndexedSDKSearch(t *testing.T, server *Server, state *connectionState, request *ldap.SearchRequest, mode string) (*ldap.SearchResult, error, smallIndexedOutcome) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	done := make(chan smallIndexedOutcome, 1)
	go func() {
		defer serverSide.Close()
		message, err := ldapwire.ReadMessage(serverSide, 1<<20)
		if err != nil {
			done <- smallIndexedOutcome{handlerError: err.Error()}
			return
		}
		outcome := smallIndexedEvaluate(server, state, message, mode)
		if len(outcome.wire) > 0 {
			_, _ = serverSide.Write(outcome.wire)
		}
		done <- outcome
	}()
	client := ldap.NewConn(clientSide, false)
	client.Start()
	client.SetTimeout(5 * time.Second)
	defer client.Close()
	result, err := client.Search(request)
	return result, err, <-done
}

func TestSmallIndexedSearchSDKDifferential(t *testing.T) {
	server, state := newSmallIndexedFixture(t, 8)
	tests := []struct {
		name   string
		filter string
		change func(*ldap.SearchRequest)
		fast   bool
	}{
		{name: "single", filter: "(uid=person-00000)", fast: true},
		{name: "absent", filter: "(uid=absent)", fast: true},
		{name: "four duplicates", filter: "(uid=four)", fast: true},
		{name: "five duplicates", filter: "(uid=five)"},
		{name: "other indexed attribute", filter: "(cn=  PERSON   00000  )", fast: true},
		{name: "filter alias", filter: "(userid=PERSON-00000)", fast: true},
		{name: "filter OID", filter: "(0.9.2342.19200300.100.1.1=person-00000)", fast: true},
		{name: "integer matching", filter: "(uidNumber=0)", fast: true},
		{name: "noncanonical integer", filter: "(uidNumber=0000)"},
		{name: "invalid matching assertion", filter: "(uidNumber=invalid)"},
		{name: "unindexed", filter: "(description=original)"},
		{name: "non equality", filter: "(uid=person*)"},
		{name: "single level", fast: true, change: func(r *ldap.SearchRequest) { r.Scope = ldap.ScopeSingleLevel }},
		{name: "base", fast: true, change: func(r *ldap.SearchRequest) {
			r.BaseDN = "uid=person-00000," + smallIndexedPeopleDN
			r.Scope = ldap.ScopeBaseObject
		}},
		{name: "out of scope", fast: true, change: func(r *ldap.SearchRequest) { r.BaseDN = "ou=archive,dc=example,dc=com" }},
		{name: "normalized base", fast: true, change: func(r *ldap.SearchRequest) { r.BaseDN = "OU=PEOPLE,DC=EXAMPLE,DC=COM" }},
		{name: "base OID", fast: true, change: func(r *ldap.SearchRequest) { r.BaseDN = "2.5.4.11=people,dc=example,dc=com" }},
		{name: "types only", fast: true, change: func(r *ldap.SearchRequest) { r.TypesOnly = true }},
		{name: "no attributes", fast: true, change: func(r *ldap.SearchRequest) { r.Attributes = []string{"1.1"} }},
		{name: "selection alias OID options", fast: true, change: func(r *ldap.SearchRequest) { r.Attributes = []string{"userid", "2.5.4.3;lang-en", "jpegPhoto"} }},
		{name: "unknown selection", fast: true, change: func(r *ldap.SearchRequest) { r.Attributes = []string{"unknownAttribute"} }},
		{name: "empty selection", change: func(r *ldap.SearchRequest) { r.Attributes = nil }},
		{name: "user wildcard", change: func(r *ldap.SearchRequest) { r.Attributes = []string{"*"} }},
		{name: "operational wildcard", change: func(r *ldap.SearchRequest) { r.Attributes = []string{"+"} }},
		{name: "operational selection", change: func(r *ldap.SearchRequest) { r.Attributes = []string{"subschemaSubentry"} }},
		{name: "collective selection", change: func(r *ldap.SearchRequest) { r.Attributes = []string{"c-description"} }},
		{name: "object class selection", change: func(r *ldap.SearchRequest) { r.Attributes = []string{"@inetOrgPerson"} }},
		{name: "request size limit", filter: "(uid=four)", change: func(r *ldap.SearchRequest) { r.SizeLimit = 2 }},
		{name: "request time limit", change: func(r *ldap.SearchRequest) { r.TimeLimit = 1 }},
		{name: "alias dereferencing", change: func(r *ldap.SearchRequest) { r.DerefAliases = ldap.DerefAlways }},
		{name: "children scope", change: func(r *ldap.SearchRequest) { r.Scope = int(directory.ScopeChildren) }},
		{name: "unknown critical control", change: func(r *ldap.SearchRequest) { r.Controls = []ldap.Control{ldap.NewControlString("1.2.3.999", true, "")} }},
		{name: "unknown noncritical control", change: func(r *ldap.SearchRequest) {
			r.Controls = []ldap.Control{ldap.NewControlString("1.2.3.999", false, "")}
		}},
		{name: "missing base", change: func(r *ldap.SearchRequest) { r.BaseDN = "ou=missing," + smallIndexedPeopleDN }},
		{name: "root DSE", change: func(r *ldap.SearchRequest) { r.BaseDN = ""; r.Scope = ldap.ScopeBaseObject }},
		{name: "subschema", change: func(r *ldap.SearchRequest) { r.BaseDN = "cn=Subschema"; r.Scope = ldap.ScopeBaseObject }},
		{name: "config", change: func(r *ldap.SearchRequest) { r.BaseDN = "cn=config"; r.Scope = ldap.ScopeBaseObject }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filter := test.filter
			if filter == "" {
				filter = "(uid=person-00000)"
			}
			request := smallIndexedSDKRequest(filter)
			if test.change != nil {
				test.change(request)
			}
			state.runtime.searchResults = newSearchResultCache(32 << 20)
			want, wantErr, general := smallIndexedSDKSearch(t, server, state, request, "general")
			state.runtime.searchResults = newSearchResultCache(32 << 20)
			got, gotErr, small := smallIndexedSDKSearch(t, server, state, request, "small")
			if small.handled != test.fast {
				t.Fatalf("fast path handled=%t, want %t; handler error=%s", small.handled, test.fast, small.handlerError)
			}
			if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
				t.Fatalf("SDK mismatch: got %#v / %v, want %#v / %v", got, gotErr, want, wantErr)
			}
			small.handled = false
			if !reflect.DeepEqual(small, general) {
				t.Fatalf("wire/audit/effect mismatch:\nsmall: %#v\ngeneral: %#v", small, general)
			}
			state.runtime.searchResults = newSearchResultCache(32 << 20)
			_, _, wrapper := smallIndexedSDKSearch(t, server, state, request, "wrapper")
			if !reflect.DeepEqual(wrapper, general) {
				t.Fatal("dispatch attachment differs from general handler")
			}
		})
	}
}

func smallIndexedMessage(filter string) ldapwire.Message {
	compiled, err := ldap.CompileFilter(filter)
	if err != nil {
		panic(err)
	}
	decoded, err := ldapwire.DecodeFilter(compiled.Bytes())
	if err != nil {
		panic(err)
	}
	return ldapwire.Message{ID: 1, Request: ldapwire.SearchRequest{BaseDN: smallIndexedPeopleDN,
		Scope: directory.ScopeWholeSubtree, Filter: decoded, Attributes: []string{"uid", "cn", "sn", "jpegPhoto"}}}
}

func smallIndexedPut(t testing.TB, server *Server, state *connectionState, entry directory.Entry, replace bool) {
	t.Helper()
	dn, err := state.runtime.schema.NormalizeDN(entry.DN)
	if err != nil {
		t.Fatal(err)
	}
	database := databaseForNormalizedDN(state.runtime, dn)
	if err := server.config.Store.Update(t.Context(), func(writer storage.Writer) error {
		return writerForDatabase(writer, *database).Put(entry, replace)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSmallIndexedSearchSpecialAndInheritedSemantics(t *testing.T) {
	for _, kind := range []string{"alias", "referral", "subentry", "referral base", "alias base", "subentry base",
		"frontend retcode", "frontend valueSort", "frontend collect", "frontend nestgroup", "collective source", "source flags"} {
		t.Run(kind, func(t *testing.T) {
			server, state := newSmallIndexedFixture(t, 8)
			request := smallIndexedSDKRequest("(uid=person-00000)")
			request.Attributes = append(request.Attributes, "description", "member")
			base, _ := state.runtime.schema.NormalizeDN(smallIndexedPeopleDN)
			personDN := "uid=person-00000," + smallIndexedPeopleDN
			frontend := runtimeDatabase{name: "{-1}frontend"}
			switch kind {
			case "frontend retcode":
				dn, _ := state.runtime.schema.NormalizeDN(personDN)
				frontend.retcodes = []retcodeRuntimeConfiguration{{parent: base, items: []retcodeItem{{
					dn: dn, code: ldapwire.ResultBusy, text: "frontend retcode", operations: retcodeOperationSearch,
				}}}}
				request.BaseDN, request.Scope = personDN, ldap.ScopeBaseObject
			case "frontend valueSort":
				frontend.valueSort = &valueSortRuntimeConfiguration{rules: []valueSortRule{{
					attribute: "uid", base: base, kind: valueSortAlpha,
				}}}
			case "frontend collect":
				configuration, err := loadCollectRuntimeConfiguration(directory.Entry{Attributes: []directory.Attribute{{
					Description: "olcCollectInfo", Values: stringValues(smallIndexedPeopleDN + " description"),
				}}})
				if err == nil {
					err = validateCollectSchema(state.runtime.schema, &configuration)
				}
				if err != nil {
					t.Fatal(err)
				}
				frontend.collect = &configuration
				smallIndexedPut(t, server, state, directory.Entry{DN: smallIndexedPeopleDN, Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("organizationalUnit")},
					{Description: "ou", Values: stringValues("people")},
					{Description: "description", Values: stringValues("inherited template")},
				}}, true)
			case "frontend nestgroup":
				configuration := nestGroupRuntimeConfiguration{id: "frontend-nestgroup", memberAttribute: "member",
					memberOfAttribute: "memberOf", bases: []directory.DN{base}, flags: nestGroupMemberValues}
				frontend.nestGroups = []nestGroupRuntimeConfiguration{configuration}
				if err := validateNestGroupSchema(state.runtime.schema, frontend.nestGroups); err != nil {
					t.Fatal(err)
				}
				for i := range 2 {
					member := personDN
					if i == 0 {
						member = "cn=group1," + smallIndexedPeopleDN
					}
					smallIndexedPut(t, server, state, directory.Entry{DN: fmt.Sprintf("cn=group%d,%s", i, smallIndexedPeopleDN),
						Attributes: []directory.Attribute{
							{Description: "objectClass", Values: stringValues("groupOfNames")},
							{Description: "cn", Values: stringValues(fmt.Sprintf("group%d", i))},
							{Description: "uid", Values: stringValues(fmt.Sprintf("group%d", i))},
							{Description: "member", Values: stringValues(member)},
						}}, false)
				}
				request.Filter = "(uid=group0)"
			case "collective source":
				smallIndexedPut(t, server, state, directory.Entry{DN: smallIndexedPeopleDN, Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("organizationalUnit")},
					{Description: "ou", Values: stringValues("people")},
					{Description: "administrativeRole", Values: stringValues("collectiveAttributeSpecificArea")},
				}}, true)
				smallIndexedPut(t, server, state, collectiveServerSource("cn=source,"+smallIndexedPeopleDN, "{}",
					directory.Attribute{Description: "c-description", Values: stringValues("collective value")}), false)
			case "source flags":
				dn, _ := state.runtime.schema.NormalizeDN(personDN)
				database := databaseForNormalizedDN(state.runtime, dn)
				if err := server.config.Store.Update(t.Context(), func(writer storage.Writer) error {
					tx := writerForDatabase(writer, *database)
					entry, err := tx.Get(dn)
					if err != nil {
						return err
					}
					for i := range entry.Attributes {
						entry.Attributes[i].RawNormalized = i%2 == 0
					}
					return tx.Put(entry, true)
				}); err != nil {
					t.Fatal(err)
				}
			default:
				class := strings.TrimSuffix(kind, " base")
				entry := directory.Entry{DN: "cn=special," + smallIndexedPeopleDN, Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues(class)},
					{Description: "cn", Values: stringValues("special")},
					{Description: "uid", Values: stringValues("person-00000")},
				}}
				switch class {
				case "alias":
					entry.ReplaceValues("aliasedObjectName", stringValues(personDN))
				case "referral":
					entry.ReplaceValues("ref", stringValues("ldap://example.invalid/dc=remote"))
				case "subentry":
					entry.ReplaceValues("subtreeSpecification", stringValues("{}"))
				}
				smallIndexedPut(t, server, state, entry, false)
				if strings.HasSuffix(kind, " base") {
					request.BaseDN, request.Scope = entry.DN, ldap.ScopeBaseObject
				}
			}
			if strings.HasPrefix(kind, "frontend ") {
				state.runtime.databases = append(state.runtime.databases, frontend)
				state.runtime.features = runtimeFeaturesForDatabases(state.runtime.databases)
				message := smallIndexedMessage(request.Filter)
				wireRequest := message.Request.(ldapwire.SearchRequest)
				wireRequest.BaseDN, wireRequest.Scope = request.BaseDN, directory.Scope(request.Scope)
				wireRequest.Attributes = request.Attributes
				message.Request = wireRequest
				prelude, database := smallIndexedTestPrelude(server, state, message)
				if !prelude.cacheable {
					t.Fatal("fixture must pass cache eligibility to exercise the additional frontend guard")
				}
				observed := &smallIndexedObservedStore{Store: server.config.Store}
				server.config.Store = observed
				capture := &smallIndexedCapture{}
				handled, err := server.trySmallIndexedSearch(t.Context(), capture, state, message, wireRequest, prelude, database)
				if handled || err != nil || observed.views != 0 || observed.updates != 0 || capture.Len() != 0 ||
					len(state.runtime.searchResults.entries) != 0 || len(state.runtime.searchBases.entries) != 0 ||
					server.searchMemoryLimiter.active.Load() != 0 || server.searchMemoryLimiter.rejected.Load() != 0 {
					t.Fatalf("frontend guard must decline without effects: handled=%t err=%v views=%d writes=%d bytes=%d",
						handled, err, observed.views, observed.updates, capture.Len())
				}
			}
			want, wantErr, general := smallIndexedSDKSearch(t, server, state, request, "general")
			switch kind {
			case "frontend retcode":
				if general.code != int(ldapwire.ResultBusy) || general.diagnostic != "frontend retcode" ||
					len(state.runtime.searchResults.entries) != 0 {
					t.Fatal("general miss must return the synthetic retcode without populating the result cache")
				}
			case "frontend valueSort":
				if wantErr != nil || len(want.Entries) != 1 ||
					!slices.Equal(want.Entries[0].GetAttributeValues("uid"), []string{"five", "four", "person-00000"}) {
					t.Fatal("fixture did not exercise inherited value sorting")
				}
			case "frontend collect":
				if wantErr != nil || len(want.Entries) != 1 ||
					!slices.Contains(want.Entries[0].GetAttributeValues("description"), "inherited template") {
					t.Fatal("fixture did not exercise inherited collect projection")
				}
			case "frontend nestgroup":
				if wantErr != nil || len(want.Entries) != 1 ||
					!slices.Contains(want.Entries[0].GetAttributeValues("member"), personDN) {
					t.Fatal("fixture did not exercise inherited nested group projection")
				}
			}
			state.runtime.searchResults = newSearchResultCache(32 << 20)
			got, gotErr, small := smallIndexedSDKSearch(t, server, state, request, "small")
			if small.handled != (kind == "source flags") {
				t.Fatalf("unexpected fast-path admission: %t", small.handled)
			}
			small.handled = false
			if !reflect.DeepEqual(small, general) || !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
				t.Fatalf("special/overlay behavior changed: small=%#v general=%#v; SDK errors %v / %v", small, general, gotErr, wantErr)
			}
		})
	}
}

func TestSmallIndexedSearchFallbackGuards(t *testing.T) {
	for _, kind := range []string{"nonroot", "restricted", "shadow", "glue", "subordinate", "multiple routes", "relay",
		"database limits", "dynlist", "collect", "nestgroup", "stale index", "unversioned view"} {
		t.Run(kind, func(t *testing.T) {
			server, state := newSmallIndexedFixture(t, 8)
			message := smallIndexedMessage("(uid=person-00000)")
			request := message.Request.(ldapwire.SearchRequest)
			_, database := smallIndexedTestPrelude(server, state, message)
			switch kind {
			case "nonroot":
				state.boundDN = "uid=person-00000," + smallIndexedPeopleDN
			case "restricted":
				state.passwordPolicyRestrictedDN = state.boundDN
			case "shadow":
				database.shadow = true
			case "glue":
				database.explicitGlue = true
			case "subordinate":
				database.subordinate = true
			case "multiple routes":
				child := *database
				base, _ := state.runtime.schema.NormalizeDN("ou=child," + smallIndexedPeopleDN)
				child.suffixes, child.subordinate, child.partition = []directory.DN{base}, true, "child"
				state.runtime.databases = append(state.runtime.databases, child)
			case "relay":
				database.relay = &relayRuntimeConfiguration{}
			case "database limits":
				database.searchSizeLimits = []databaseSearchSizeLimit{{}}
			case "dynlist":
				database.dynlist = &dynlistRuntimeConfiguration{}
			case "collect":
				database.collect = &collectRuntimeConfiguration{}
			case "nestgroup":
				database.nestGroups = []nestGroupRuntimeConfiguration{{}}
			case "stale index":
				normalizer, _, err := loadDatabaseEqualityIndexes(directory.Entry{Attributes: []directory.Attribute{{
					Description: "olcDbIndex", Values: stringValues("uid,cn,sn,objectClass,description eq"),
				}}}, state.runtime.schema)
				if err != nil {
					t.Fatal(err)
				}
				database.dnNormalizer = normalizer
			}
			observed := &smallIndexedObservedStore{Store: server.config.Store, hideRevision: kind == "unversioned view"}
			server.config.Store = observed
			prelude, database := smallIndexedTestPrelude(server, state, message)
			capture := &smallIndexedCapture{}
			handled, err := server.trySmallIndexedSearch(t.Context(), capture, state, message, request, prelude, database)
			if handled || err != nil || capture.Len() != 0 || observed.updates != 0 ||
				len(state.runtime.searchResults.entries) != 0 || server.searchMemoryLimiter.active.Load() != 0 ||
				server.searchMemoryLimiter.rejected.Load() != 0 {
				t.Fatalf("guard changed effects: handled=%t err=%v bytes=%d updates=%d", handled, err, capture.Len(), observed.updates)
			}
		})
	}
}

func TestSmallIndexedSearchCachesEmptyResult(t *testing.T) {
	server, state := newSmallIndexedFixture(t, 8)
	message := smallIndexedMessage("(uid=absent)")
	prelude, _ := smallIndexedTestPrelude(server, state, message)
	observed := &smallIndexedObservedStore{Store: server.config.Store}
	server.config.Store = observed
	first := smallIndexedEvaluate(server, state, message, "small")
	entries, found := state.runtime.searchResults.get(prelude.fingerprint, prelude.revision)
	if !first.handled || first.code != 0 || first.entries != 0 || !found || len(entries) != 0 || observed.updates != 0 {
		t.Fatal("empty successful search did not populate the existing cache")
	}
	observed.views = 0
	hot := smallIndexedEvaluate(server, state, message, "wrapper")
	if !bytes.Equal(hot.wire, first.wire) || observed.views != 0 || hot.memory != 0 || hot.rejections != 0 {
		t.Fatal("empty cache hit performed a view or changed the response/accounting")
	}
}

// Count writes to storage separately from cache fills and wire writes.
type smallIndexedObservedStore struct {
	storage.Store
	views, updates int
	beforeView     func()
	afterView      func() error
	hideRevision   bool
}

type smallIndexedUnversionedReader struct{ storage.Reader }

func (smallIndexedUnversionedReader) StorageSnapshotRevision() (uint64, bool) { return 0, false }

func (store *smallIndexedObservedStore) View(ctx context.Context, fn func(storage.Reader) error) error {
	store.views++
	if store.beforeView != nil {
		store.beforeView()
	}
	err := store.Store.View(ctx, func(reader storage.Reader) error {
		if store.hideRevision {
			reader = smallIndexedUnversionedReader{reader}
		}
		return fn(reader)
	})
	if err == nil && store.afterView != nil {
		err = store.afterView()
	}
	return err
}

func (store *smallIndexedObservedStore) Update(ctx context.Context, fn func(storage.Writer) error) error {
	store.updates++
	return store.Store.Update(ctx, fn)
}

func (store *smallIndexedObservedStore) CurrentStorageSnapshotRevision() (uint64, bool) {
	return store.Store.(storage.SnapshotRevisionStore).CurrentStorageSnapshotRevision()
}

func TestSmallIndexedSearchMemoryAndSizeBoundaries(t *testing.T) {
	server, state := newSmallIndexedFixture(t, 8)
	message := smallIndexedMessage("(uid=four)")
	request := message.Request.(ldapwire.SearchRequest)
	prelude, database := smallIndexedTestPrelude(server, state, message)
	var retained int64
	capture := &smallIndexedCapture{onWrite: func() { retained = server.searchMemoryLimiter.active.Load() }}
	if handled, err := server.trySmallIndexedSearch(t.Context(), capture, state, message, request, prelude, database); !handled || err != nil {
		t.Fatalf("initial search handled=%t err=%v", handled, err)
	}
	if retained <= 0 || server.searchMemoryLimiter.active.Load() != 0 {
		t.Fatal("candidate reservation was missing or leaked")
	}
	for _, test := range []struct {
		name          string
		candidateMax  int64
		processMax    int64
		sizeLimit     int
		fast          bool
		wantRejection uint64
	}{
		{"exact candidate budget", retained, retained * 2, 8, true, 0},
		{"candidate budget minus one", retained - 1, retained * 2, 8, false, 0},
		{"exact process budget", retained * 2, retained, 8, true, 0},
		{"process budget minus one", retained * 2, retained - 1, 8, false, 1},
		{"exact size limit", retained * 2, retained * 2, 4, true, 0},
		{"size limit minus one", retained * 2, retained * 2, 3, false, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			server.config.MaxSearchCandidateBytes = test.candidateMax
			server.config.MaxSearchEntries = test.sizeLimit
			server.searchMemoryLimiter = newResourceByteLimiter(test.processMax)
			state.runtime.searchResults = newSearchResultCache(32 << 20)
			probe := &smallIndexedCapture{}
			handled, err := server.trySmallIndexedSearch(t.Context(), probe, state, message, request, prelude, database)
			if err != nil || handled != test.fast || (!handled && probe.Len() != 0) ||
				server.searchMemoryLimiter.active.Load() != 0 || server.searchMemoryLimiter.rejected.Load() != 0 {
				t.Fatalf("probe handled=%t err=%v bytes=%d active=%d rejected=%d", handled, err, probe.Len(),
					server.searchMemoryLimiter.active.Load(), server.searchMemoryLimiter.rejected.Load())
			}
			if !handled && len(state.runtime.searchResults.entries) != 0 {
				t.Fatal("fallback cached a partial success")
			}
			general := smallIndexedEvaluate(server, state, message, "general")
			server.searchMemoryLimiter.rejected.Store(0)
			small := smallIndexedEvaluate(server, state, message, "small")
			small.handled = false
			if !reflect.DeepEqual(general, small) || small.rejections != test.wantRejection {
				t.Fatalf("quota behavior mismatch: small=%#v general=%#v", small, general)
			}
		})
	}
}

func TestSmallIndexedSearchReadAndWriteFailures(t *testing.T) {
	server, state := newSmallIndexedFixture(t, 8)
	message := smallIndexedMessage("(uid=person-00000)")
	prelude, database := smallIndexedTestPrelude(server, state, message)
	request := message.Request.(ldapwire.SearchRequest)
	observed := &smallIndexedObservedStore{Store: server.config.Store}
	server.config.Store = observed
	for _, phase := range []string{"already canceled", "canceled on view", "view failure after selection", "wire failure"} {
		t.Run(phase, func(t *testing.T) {
			state.runtime.searchResults = newSearchResultCache(32 << 20)
			state.runtime.searchBases = newSearchBaseCache()
			observed.beforeView, observed.afterView = nil, nil
			observed.views, observed.updates = 0, 0
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			capture := &smallIndexedCapture{}
			failure := errors.New("injected failure")
			switch phase {
			case "already canceled":
				cancel()
			case "canceled on view":
				observed.beforeView = cancel
			case "view failure after selection":
				observed.afterView = func() error { return failure }
			case "wire failure":
				capture.err = failure
			}
			handled, err := server.trySmallIndexedSearch(ctx, capture, state, message, request, prelude, database)
			if phase == "wire failure" {
				if !handled || !errors.Is(err, failure) || observed.views != 1 {
					t.Fatalf("wire failure must terminate, handled=%t err=%v views=%d", handled, err, observed.views)
				}
			} else if handled || err != nil || len(state.runtime.searchResults.entries) != 0 || len(state.runtime.searchBases.entries) != 0 {
				t.Fatalf("read failure must fall back without publishing success: handled=%t err=%v", handled, err)
			}
			if capture.Len() != 0 || observed.updates != 0 || server.searchMemoryLimiter.active.Load() != 0 || server.searchMemoryLimiter.rejected.Load() != 0 {
				t.Fatal("failure wrote a response/storage or changed memory accounting")
			}
		})
	}
}

func TestSmallIndexedSearchSnapshotRevisionAndOwnership(t *testing.T) {
	server, state := newSmallIndexedFixture(t, 8)
	message := smallIndexedMessage("(uid=four)")
	request := message.Request.(ldapwire.SearchRequest)
	request.Attributes = []string{"uid", "description", "jpegPhoto"}
	message.Request = request
	prelude, database := smallIndexedTestPrelude(server, state, message)
	first := smallIndexedEvaluate(server, state, message, "small")
	if !first.handled || first.handlerError != "" || first.entries != 4 {
		t.Fatalf("initial lookup = %#v", first)
	}
	old, found := state.runtime.searchResults.get(prelude.fingerprint, prelude.revision)
	if !found || len(old) != 4 {
		t.Fatal("successful lookup did not fill the existing cache")
	}
	for i, entry := range old {
		if !bytes.Equal(entry.Values("jpegPhoto")[0], []byte{0, byte(i), 255}) {
			t.Fatal("borrowed callback descriptors or values escaped into another entry")
		}
	}
	if err := server.config.Store.Update(t.Context(), func(writer storage.Writer) error {
		tx := writerForDatabase(writer, *database)
		for _, cached := range old {
			dn, err := state.runtime.schema.NormalizeDN(cached.DN)
			if err != nil {
				return err
			}
			entry, err := tx.Get(dn)
			if err != nil {
				return err
			}
			entry.ReplaceValues("description", stringValues(strings.Repeat("changed", 100)))
			if err := tx.Put(entry, true); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	revision, _ := server.currentStorageSnapshotRevision(t.Context())
	if revision == prelude.revision {
		t.Fatal("fixture update did not advance the revision")
	}
	if _, found := state.runtime.searchResults.get(prelude.fingerprint, revision); found {
		t.Fatal("old cached result survived revision invalidation")
	}
	// Deliberately pass the pre-update prelude: publication must use the view's
	// actual revision, not the wrapper's earlier observation.
	capture := &smallIndexedCapture{}
	if handled, err := server.trySmallIndexedSearch(t.Context(), capture, state, message, request, prelude, database); !handled || err != nil {
		t.Fatalf("changed revision handled=%t err=%v", handled, err)
	}
	updated, found := state.runtime.searchResults.get(prelude.fingerprint, revision)
	if !found || len(updated) != 4 || string(updated[0].Values("description")[0]) != strings.Repeat("changed", 100) {
		t.Fatal("new snapshot was not published under its actual revision")
	}
	if string(old[0].Values("description")[0]) != "original" {
		t.Fatal("write transaction mutated a previously published result")
	}
	observed := &smallIndexedObservedStore{Store: server.config.Store}
	server.config.Store = observed
	hot := smallIndexedEvaluate(server, state, message, "wrapper")
	if hot.handlerError != "" || observed.views != 0 || !bytes.Equal(hot.wire, capture.Bytes()) {
		t.Fatal("wrapper did not reuse the fast path's result cache")
	}
}

func BenchmarkSmallIndexedColdSearch(b *testing.B) {
	server, state := newSmallIndexedFixture(b, 8)
	_, database := smallIndexedTestPrelude(server, state, smallIndexedMessage("(uid=person-00000)"))
	if err := storage.UpdateBulk(b.Context(), server.config.Store, func(writer storage.Writer) error {
		tx := writerForDatabase(writer, *database)
		dn, err := state.runtime.schema.NormalizeDN("uid=person-00007," + smallIndexedPeopleDN)
		if err != nil {
			return err
		}
		template, err := tx.Get(dn)
		if err != nil {
			return err
		}
		for i := 8; i < 10000; i++ {
			uid := fmt.Sprintf("person-%05d", i)
			entry := template.Clone()
			entry.DN = "uid=" + uid + "," + smallIndexedPeopleDN
			entry.ReplaceValues("uid", stringValues(uid))
			entry.ReplaceValues("cn", stringValues(fmt.Sprintf("Person %05d", i)))
			entry.ReplaceValues("cn;lang-en", stringValues(fmt.Sprintf("English %05d", i)))
			entry.ReplaceValues("uidNumber", stringValues(fmt.Sprint(i)))
			if err := tx.Put(entry.WithoutDNIdentity(), false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	messages := make([]ldapwire.Message, 10000)
	for i := range messages {
		messages[i] = smallIndexedMessage(fmt.Sprintf("(uid=person-%05d)", i))
	}
	for _, mode := range []string{"general", "wrapper"} {
		b.Run(mode, func(b *testing.B) {
			capture := &smallIndexedCapture{}
			index := 0
			b.ReportAllocs()
			for b.Loop() {
				message := messages[index%len(messages)]
				index++
				// Only the result cache is cold; base/schema/index caches remain
				// available to both paths, as in repeated distinct lookups.
				clear(state.runtime.searchResults.entries)
				state.runtime.searchResults.bytes = 0
				capture.Reset()
				request := message.Request.(ldapwire.SearchRequest)
				var err error
				if mode == "wrapper" {
					err = server.handleSearch(b.Context(), capture, state, message, request)
				} else {
					prelude, _ := smallIndexedTestPrelude(server, state, message)
					err = server.handleUncachedSearch(b.Context(), capture, state, message, request, prelude)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
