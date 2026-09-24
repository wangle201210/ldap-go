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

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
	bolt "go.etcd.io/bbolt"
)

const smallNonRootReaderDN = "uid=reader," + smallIndexedPeopleDN

func newSmallNonRootFixture(t *testing.T, count int, memberCounts ...int) *readOnlySearchFixture {
	t.Helper()
	fixture := newReadOnlySearchFixture(t, count, memberCounts...)
	fixture.state.boundDN, fixture.state.protocolVersion = smallNonRootReaderDN, 3
	smallNonRootPolicy(t, fixture, "{0}to attrs=userPassword by * none", "{1}to * by users read by * none")
	for i := range fixture.groups {
		fixture.groups[i].ReplaceValues("cn;lang-en", stringValues(fmt.Sprintf("English group %d", i)))
		smallIndexedPut(t, fixture.server, fixture.state, fixture.groups[i], true)
	}
	smallNonRootReady(t, fixture)
	return fixture
}

func smallNonRootPolicy(t *testing.T, fixture *readOnlySearchFixture, rules ...string) {
	t.Helper()
	fixture.state.runtime.access = defaultProjectionPolicy(t, defaultProjectionRules(t, rules...), nil)
	if !fixture.state.runtime.access.CanBatchValues() {
		t.Fatal("explicit ACL must remain eligible for value batching")
	}
}

func smallNonRootReady(t *testing.T, fixture *readOnlySearchFixture) {
	t.Helper()
	base, err := normalizeConnectionSearchRequestBase(fixture.state, smallIndexedPeopleDN)
	if err != nil {
		t.Fatal(err)
	}
	routes := databaseSearchRoutesFromNormalizedBase(fixture.state.runtime.databases, base, directory.ScopeWholeSubtree)
	if err := fixture.server.ensureSearchEqualityIndexes(t.Context(), fixture.state.runtime, routes); err != nil {
		t.Fatal(err)
	}
	revision, available := fixture.server.currentStorageSnapshotRevision(t.Context())
	if !fixture.database.equalityIndexInit.readyFor(revision, available) || fixture.state.protocolVersion != 3 ||
		fixture.state.boundDN == "" || fixture.state.boundDN == smallIndexedRootDN ||
		!plainBoltSearchStore(fixture.server.config.Store) {
		t.Fatal("fixture must use a bound LDAPv3 nonroot user and current Bolt equality indexes")
	}
}

func smallNonRootNoCaches(t *testing.T, fixture *readOnlySearchFixture) {
	t.Helper()
	if len(fixture.state.runtime.searchResults.entries) != 0 || len(fixture.state.runtime.searchBases.entries) != 0 {
		t.Fatal("nonroot search published a result or base cache entry")
	}
}

// Both drivers use the same prelude and connection/audit encoder. The baseline
// calls the old general handler directly, without changing the ACL or reader.
func smallNonRootEvaluate(ctx context.Context, server *Server, state *connectionState, message ldapwire.Message, mode string) smallIndexedOutcome {
	capture := &smallIndexedCapture{}
	observation := &operationAuditObservation{}
	operation := newTrackedOperation(ctx, message)
	operation.start()
	defer operation.finish()
	connection := &operationResponseConnection{Conn: capture, operation: operation, audit: observation}
	request := message.Request.(ldapwire.SearchRequest)
	prelude, _ := smallIndexedTestPrelude(server, state, message)
	beforeMemory := server.searchMemoryLimiter.active.Load()
	beforeRejected := server.searchMemoryLimiter.rejected.Load()
	var handled bool
	var err error
	if mode == "wrapper" {
		err = server.handleSearch(operation.ctx, connection, state, message, request)
	} else {
		if mode == "small" {
			base, baseErr := normalizeConnectionSearchRequestBase(state, request.BaseDN)
			if database := databaseForNormalizedDN(state.runtime, base); baseErr == nil && database != nil {
				handled, err = server.trySmallNonRootSearch(operation.ctx, connection, state, message, request, base, database)
			}
		}
		if !handled {
			if err != nil || capture.Len() != 0 || server.searchMemoryLimiter.active.Load() != beforeMemory ||
				server.searchMemoryLimiter.rejected.Load() != beforeRejected {
				err = fmt.Errorf("declined fast path had effects: err=%v bytes=%d active=%d rejected=%d", err,
					capture.Len(), server.searchMemoryLimiter.active.Load(), server.searchMemoryLimiter.rejected.Load()-beforeRejected)
			} else {
				err = server.handleUncachedSearch(operation.ctx, connection, state, message, request, prelude)
			}
		}
	}
	outcome := smallIndexedOutcome{wire: bytes.Clone(capture.Bytes()), handled: handled,
		code: observation.result, entries: observation.entries, diagnostic: observation.diagnostic,
		memory: server.searchMemoryLimiter.active.Load() - beforeMemory, rejections: server.searchMemoryLimiter.rejected.Load() - beforeRejected}
	if err != nil {
		outcome.handlerError = err.Error()
	}
	return outcome
}

func smallNonRootSDKSearch(t *testing.T, fixture *readOnlySearchFixture, request *ldap.SearchRequest, mode string) (*ldap.SearchResult, error, smallIndexedOutcome) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	done := make(chan smallIndexedOutcome, 1)
	ctx := t.Context()
	go func() {
		defer serverSide.Close()
		message, err := ldapwire.ReadMessage(serverSide, 1<<20)
		if err != nil {
			done <- smallIndexedOutcome{handlerError: err.Error()}
			return
		}
		outcome := smallNonRootEvaluate(ctx, fixture.server, fixture.state, message, mode)
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
	outcome := <-done
	smallNonRootNoCaches(t, fixture)
	return result, err, outcome
}

func smallNonRootDifferential(t *testing.T, fixture *readOnlySearchFixture, request *ldap.SearchRequest, fast bool) (*ldap.SearchResult, error, smallIndexedOutcome) {
	t.Helper()
	revision, available := fixture.server.currentStorageSnapshotRevision(t.Context())
	if !fixture.database.equalityIndexInit.readyFor(revision, available) {
		t.Fatal("differential must start with ready indexes; general search must not prime the fast path")
	}
	// Run the fast path first so even the general handler's read-side caches
	// cannot make an ineligible fixture look eligible.
	got, gotErr, small := smallNonRootSDKSearch(t, fixture, request, "small")
	if small.handled != fast || (fast && small.handlerError != "") || small.memory != 0 {
		t.Fatalf("small search: handled=%t want=%t handler=%q memory=%d", small.handled, fast, small.handlerError, small.memory)
	}
	want, wantErr, general := smallNonRootSDKSearch(t, fixture, request, "general")
	compared := small
	compared.handled = false
	if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || !reflect.DeepEqual(compared, general) {
		t.Fatalf("small/general mismatch: SDK equal=%t errors=%v / %v; wire equal=%t code=%d/%d entries=%d/%d diagnostic=%q/%q handler=%q/%q memory=%d/%d rejections=%d/%d",
			reflect.DeepEqual(got, want), gotErr, wantErr, bytes.Equal(small.wire, general.wire), small.code, general.code,
			small.entries, general.entries, small.diagnostic, general.diagnostic, small.handlerError, general.handlerError,
			small.memory, general.memory, small.rejections, general.rejections)
	}
	wrapped, wrappedErr, wrapper := smallNonRootSDKSearch(t, fixture, request, "wrapper")
	if !reflect.DeepEqual(wrapped, want) || fmt.Sprint(wrappedErr) != fmt.Sprint(wantErr) || !reflect.DeepEqual(wrapper, general) {
		t.Fatalf("dispatch/general mismatch: SDK equal=%t errors=%v / %v; wire equal=%t code=%d/%d entries=%d/%d handler=%q/%q",
			reflect.DeepEqual(wrapped, want), wrappedErr, wantErr, bytes.Equal(wrapper.wire, general.wire), wrapper.code,
			general.code, wrapper.entries, general.entries, wrapper.handlerError, general.handlerError)
	}
	if after, known := fixture.server.currentStorageSnapshotRevision(t.Context()); !known || after != revision {
		t.Fatal("search changed the storage snapshot revision")
	}
	return got, gotErr, small
}

func smallNonRootAssertResult(t *testing.T, result *ldap.SearchResult, err error, outcome smallIndexedOutcome, code uint16, entries int) {
	t.Helper()
	if outcome.code != int(code) || outcome.entries != entries || result == nil || len(result.Entries) != entries ||
		(code == 0 && err != nil) || (code != 0 && !ldap.IsErrorWithCode(err, code)) {
		t.Fatalf("result: code=%d entries=%d SDK=%#v error=%v, want code=%d entries=%d", outcome.code, outcome.entries, result, err, code, entries)
	}
}

func TestSmallNonRootSearchSDKDifferential(t *testing.T) {
	for _, count := range []int{0, 1, 4, 5} {
		t.Run(fmt.Sprintf("postings=%d", count), func(t *testing.T) {
			fixture := newSmallNonRootFixture(t, count)
			for _, filter := range []string{"(uid=borrowed-groups)", "(member=" + readOnlySearchMember + ")"} {
				t.Run(filter, func(t *testing.T) {
					request := readOnlySearchRequest(filter, []string{"cn", "uid", "member", "jpegPhoto"}, false)
					request.SizeLimit = count + 1
					result, err, outcome := smallNonRootDifferential(t, fixture, request, count <= 4)
					smallNonRootAssertResult(t, result, err, outcome, ldap.LDAPResultSuccess, count)
					// cn selects its option-qualified descriptions as well.
					expected := *request
					expected.Attributes = append(slices.Clone(request.Attributes), "cn;lang-en")
					fixture.assertEntries(t, result, &expected, "explicit")
				})
			}
		})
	}
	fixture := newSmallNonRootFixture(t, 4, 1000, 105, 1003, 106)
	for _, test := range []struct {
		name, filter string
		change       func(*ldap.SearchRequest)
		entries      int
		fallback     bool
	}{
		{name: "base objectClass presence", filter: "(objectClass=*)", entries: 1, change: func(r *ldap.SearchRequest) {
			r.BaseDN, r.Scope = fixture.groups[0].DN, ldap.ScopeBaseObject
		}},
		{name: "base entry equality", entries: 1, change: func(r *ldap.SearchRequest) {
			r.BaseDN, r.Scope = fixture.groups[0].DN, ldap.ScopeBaseObject
		}},
		{name: "base equality zero hits", filter: "(uid=absent)", change: func(r *ldap.SearchRequest) {
			r.BaseDN, r.Scope = fixture.groups[0].DN, ldap.ScopeBaseObject
		}},
		{name: "single level", entries: 4, change: func(r *ldap.SearchRequest) { r.Scope = ldap.ScopeSingleLevel }},
		{name: "all postings outside scope", change: func(r *ldap.SearchRequest) { r.BaseDN = "ou=archive,dc=example,dc=com" }},
		{name: "normalized base", entries: 4, change: func(r *ldap.SearchRequest) { r.BaseDN = "OU=PEOPLE,DC=EXAMPLE,DC=COM" }},
		{name: "base OID", entries: 4, change: func(r *ldap.SearchRequest) { r.BaseDN = "2.5.4.11=people,dc=example,dc=com" }},
		{name: "filter alias", filter: "(userid=BORROWED-GROUPS)", entries: 4},
		{name: "filter OID", filter: "(0.9.2342.19200300.100.1.1=borrowed-groups)", entries: 4},
		{name: "member DN normalization", filter: "(member=UID=SHARED,OU=PEOPLE,DC=EXAMPLE,DC=COM)", entries: 4},
		{name: "selection aliases and OIDs", entries: 4, change: func(r *ldap.SearchRequest) {
			r.Attributes = []string{"userid", "2.5.4.3", "jpegPhoto"}
		}},
		{name: "selection aliases and options", entries: 4, fallback: true, change: func(r *ldap.SearchRequest) {
			r.Attributes = []string{"userid", "2.5.4.3;lang-en", "jpegPhoto"}
		}},
		{name: "unknown selection", entries: 4, change: func(r *ldap.SearchRequest) { r.Attributes = []string{"unknownAttribute"} }},
		{name: "no attributes", entries: 4, change: func(r *ldap.SearchRequest) { r.Attributes = []string{"1.1"} }},
	} {
		for _, typesOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/typesOnly=%t", test.name, typesOnly), func(t *testing.T) {
				filter := test.filter
				if filter == "" {
					filter = "(uid=borrowed-groups)"
				}
				request := readOnlySearchRequest(filter, []string{"cn", "member", "jpegPhoto"}, typesOnly)
				if test.change != nil {
					test.change(request)
				}
				result, err, outcome := smallNonRootDifferential(t, fixture, request, !test.fallback)
				smallNonRootAssertResult(t, result, err, outcome, ldap.LDAPResultSuccess, test.entries)
				for _, entry := range result.Entries {
					if test.name == "no attributes" || test.name == "unknown selection" {
						if len(entry.Attributes) != 0 {
							t.Fatalf("unexpected attributes for %s: %#v", test.name, entry.Attributes)
						}
					} else if len(entry.Attributes) == 0 {
						t.Fatal("projection silently dropped all requested attributes")
					}
					if typesOnly {
						for _, attribute := range entry.Attributes {
							if len(attribute.ByteValues) != 0 || len(attribute.Values) != 0 {
								t.Fatal("typesOnly leaked attribute values")
							}
						}
					}
				}
			})
		}
	}
}

func TestSmallNonRootSearchRawPostingBoundPrecedesScopeAndACL(t *testing.T) {
	for _, count := range []int{4, 5} {
		for _, scope := range []int{ldap.ScopeBaseObject, ldap.ScopeSingleLevel, ldap.ScopeWholeSubtree} {
			t.Run(fmt.Sprintf("postings=%d/scope=%d", count, scope), func(t *testing.T) {
				fixture := newSmallNonRootFixture(t, count)
				// Keep one match under people; the raw index also contains the
				// archive entries, even when scope and ACL both exclude them.
				for _, original := range fixture.groups[1:] {
					entry := original.Clone()
					entry.DN = strings.Replace(entry.DN, smallIndexedPeopleDN, "ou=archive,dc=example,dc=com", 1)
					dn, err := fixture.state.runtime.schema.NormalizeDN(original.DN)
					if err != nil {
						t.Fatal(err)
					}
					if err := fixture.server.config.Store.Update(t.Context(), func(writer storage.Writer) error {
						tx := writerForDatabase(writer, *fixture.database)
						if err := tx.Delete(dn); err != nil {
							return err
						}
						return tx.Put(entry.WithoutDNIdentity(), false)
					}); err != nil {
						t.Fatal(err)
					}
				}
				smallNonRootPolicy(t, fixture, `{0}to dn.subtree="ou=archive,dc=example,dc=com" by * none`, "{1}to * by users read by * none")
				smallNonRootReady(t, fixture)
				request := readOnlySearchRequest("(uid=borrowed-groups)", []string{"cn"}, false)
				request.Scope = scope
				if scope == ldap.ScopeBaseObject {
					request.BaseDN = fixture.groups[0].DN
				}
				result, err, outcome := smallNonRootDifferential(t, fixture, request, count == 4)
				smallNonRootAssertResult(t, result, err, outcome, ldap.LDAPResultSuccess, 1)
				if result.Entries[0].DN != fixture.groups[0].DN {
					t.Fatal("search returned an out-of-scope entry")
				}
				request.BaseDN, request.Scope = smallIndexedPeopleDN, ldap.ScopeBaseObject
				result, err, outcome = smallNonRootDifferential(t, fixture, request, count == 4)
				smallNonRootAssertResult(t, result, err, outcome, ldap.LDAPResultSuccess, 0)
			})
		}
	}
}

func TestSmallNonRootSearchBaseSearchAndDisclose(t *testing.T) {
	for _, disclose := range []bool{false, true} {
		for _, filter := range []string{"(uid=borrowed-groups)", "(uid=absent)", "(objectClass=*)"} {
			t.Run(fmt.Sprintf("disclose=%t/%s", disclose, filter), func(t *testing.T) {
				fixture := newSmallNonRootFixture(t, 1)
				grant, code := "none", uint16(ldap.LDAPResultNoSuchObject)
				if disclose {
					grant, code = "=d", ldap.LDAPResultInsufficientAccessRights
				}
				smallNonRootPolicy(t, fixture,
					fmt.Sprintf(`{0}to dn.exact="%s" attrs=entry by users %s by * none`, smallIndexedPeopleDN, grant),
					"{1}to * by users read by * none")
				request := readOnlySearchRequest(filter, []string{"cn", "ou"}, false)
				if filter == "(objectClass=*)" {
					request.Scope = ldap.ScopeBaseObject
				}
				result, err, outcome := smallNonRootDifferential(t, fixture, request, false)
				smallNonRootAssertResult(t, result, err, outcome, code, 0)
				if ldapErr, ok := errors.AsType[*ldap.Error](err); !ok || ldapErr.MatchedDN != "" {
					t.Fatalf("existing but unsearchable base disclosed a matched DN: %v", err)
				}
			})
		}
	}
}

func TestSmallNonRootSearchEntryAndAttributeACL(t *testing.T) {
	for _, count := range []int{4, 5} {
		for _, denied := range []string{"entry read", "entry all", "attribute read", "filter search"} {
			for _, typesOnly := range []bool{false, true} {
				t.Run(fmt.Sprintf("postings=%d/%s/typesOnly=%t", count, denied, typesOnly), func(t *testing.T) {
					fixture := newSmallNonRootFixture(t, count)
					var rule string
					want := count
					switch denied {
					case "entry read", "entry all":
						grant := "search"
						if denied == "entry all" {
							grant = "none"
						}
						rule = fmt.Sprintf(`{0}to dn.exact="%s" attrs=entry by users %s by * none`, fixture.groups[1].DN, grant)
						want--
					case "attribute read":
						rule = "{0}to attrs=description,userPassword,member by users search by * none"
					case "filter search":
						rule = "{0}to attrs=uid,member by * none"
						want = 0
					}
					smallNonRootPolicy(t, fixture, rule, "{1}to * by users read by * none")
					for _, filter := range []string{"(uid=borrowed-groups)", "(member=" + readOnlySearchMember + ")"} {
						request := readOnlySearchRequest(filter, []string{"cn", "member", "description", "userPassword"}, typesOnly)
						result, err, outcome := smallNonRootDifferential(t, fixture, request, count <= 4)
						smallNonRootAssertResult(t, result, err, outcome, ldap.LDAPResultSuccess, want)
						for _, entry := range result.Entries {
							if (denied == "entry read" || denied == "entry all") && entry.DN == fixture.groups[1].DN {
								t.Fatal("entry ACL denial was ignored")
							}
							if denied == "attribute read" && (len(entry.Attributes) != 2 ||
								slices.ContainsFunc(entry.Attributes, func(a *ldap.EntryAttribute) bool { return a.Name != "cn" && a.Name != "cn;lang-en" })) {
								t.Fatalf("attribute ACL leaked types or values: %#v", entry.Attributes)
							}
						}
					}
				})
			}
		}
	}
}

func TestSmallNonRootSearchFallbackSDKDifferential(t *testing.T) {
	for _, test := range []struct {
		name, filter string
		change       func(*readOnlySearchFixture, *ldap.SearchRequest)
	}{
		{name: "unknown assertion attribute", filter: "(unknownAttribute=anything)"},
		{name: "malformed DN assertion", filter: "(member=not-a-dn)"},
		{name: "invalid UTF8 assertion", filter: `(uid=\ff)`},
		{name: "unindexed assertion", filter: "(description=private-group-00)"},
		{name: "non equality", filter: "(uid=borrowed*)"},
		{name: "non base presence", filter: "(objectClass=*)"},
		{name: "empty selection", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) { r.Attributes = nil }},
		{name: "user wildcard", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) { r.Attributes = []string{"*"} }},
		{name: "operational wildcard", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) { r.Attributes = []string{"+"} }},
		{name: "operational selection", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) { r.Attributes = []string{"subschemaSubentry"} }},
		{name: "collective selection", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) { r.Attributes = []string{"c-description"} }},
		{name: "class selection", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) { r.Attributes = []string{"@groupOfNames"} }},
		{name: "request time", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) { r.TimeLimit = 1 }},
		{name: "alias dereference", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) { r.DerefAliases = ldap.DerefAlways }},
		{name: "children scope", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) { r.Scope = int(directory.ScopeChildren) }},
		{name: "critical control", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) {
			r.Controls = []ldap.Control{ldap.NewControlString("1.2.3.999", true, "")}
		}},
		{name: "noncritical control", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) {
			r.Controls = []ldap.Control{ldap.NewControlString("1.2.3.999", false, "")}
		}},
		{name: "manage DSA IT", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) {
			r.Controls = []ldap.Control{ldap.NewControlManageDsaIT(true)}
		}},
		{name: "paging", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) {
			r.Controls = []ldap.Control{ldap.NewControlPaging(32)}
		}},
		{name: "missing base", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) { r.BaseDN = "ou=missing," + smallIndexedPeopleDN }},
		{name: "missing base zero hits", filter: "(uid=absent)", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) { r.BaseDN = "ou=missing," + smallIndexedPeopleDN }},
		{name: "root DSE", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) { r.BaseDN, r.Scope = "", ldap.ScopeBaseObject }},
		{name: "configuration", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) {
			r.BaseDN, r.Scope = "cn=config", ldap.ScopeBaseObject
		}},
		{name: "subschema", change: func(_ *readOnlySearchFixture, r *ldap.SearchRequest) {
			r.BaseDN, r.Scope = "cn=Subschema", ldap.ScopeBaseObject
		}},
		{name: "database size", change: func(f *readOnlySearchFixture, _ *ldap.SearchRequest) {
			f.database.searchSizeLimits = []databaseSearchSizeLimit{{selector: databaseSearchLimitAny, soft: 2, softSet: true}}
		}},
		{name: "database time", change: func(f *readOnlySearchFixture, _ *ldap.SearchRequest) {
			f.database.searchSizeLimits = []databaseSearchSizeLimit{{selector: databaseSearchLimitAny, timeSoft: 1, timeSoftSet: true}}
		}},
		{name: "database unchecked", change: func(f *readOnlySearchFixture, _ *ldap.SearchRequest) {
			f.database.searchSizeLimits = []databaseSearchSizeLimit{{selector: databaseSearchLimitAny, unchecked: 3, uncheckedSet: true}}
		}},
		{name: "database unlimited rule", change: func(f *readOnlySearchFixture, _ *ldap.SearchRequest) {
			f.database.searchSizeLimits = []databaseSearchSizeLimit{{selector: databaseSearchLimitAny, unchecked: -1, uncheckedSet: true}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSmallNonRootFixture(t, 4)
			filter := test.filter
			if filter == "" {
				filter = "(uid=borrowed-groups)"
			}
			request := readOnlySearchRequest(filter, []string{"cn", "member"}, false)
			if test.change != nil {
				test.change(fixture, request)
			}
			result, err, outcome := smallNonRootDifferential(t, fixture, request, false)
			switch test.name {
			case "unknown assertion attribute", "malformed DN assertion", "invalid UTF8 assertion":
				if err == nil || outcome.handlerError == "" || len(outcome.wire) != 0 || outcome.entries != 0 || outcome.rejections != 0 {
					t.Fatal("invalid assertion did not preserve the general handler's error without output")
				}
			case "database size":
				smallNonRootAssertResult(t, result, err, outcome, ldap.LDAPResultSizeLimitExceeded, 2)
			case "database unchecked":
				smallNonRootAssertResult(t, result, err, outcome, ldap.LDAPResultAdminLimitExceeded, 0)
			case "critical control":
				smallNonRootAssertResult(t, result, err, outcome, ldap.LDAPResultUnavailableCriticalExtension, 0)
			case "missing base", "missing base zero hits":
				smallNonRootAssertResult(t, result, err, outcome, ldap.LDAPResultNoSuchObject, 0)
				if ldapErr, ok := errors.AsType[*ldap.Error](err); !ok || ldapErr.MatchedDN != smallIndexedPeopleDN {
					t.Fatalf("missing base lost the disclosed ancestor: %v", err)
				}
			}
		})
	}
}

func TestSmallNonRootSearchSynthesizedFilterFallback(t *testing.T) {
	fixture := newSmallNonRootFixture(t, 1)
	filters := []struct {
		name, oid, assertion string
	}{
		{"entryDN", "1.3.6.1.1.20", fixture.groups[0].DN},
		{"hasSubordinates", "2.5.18.9", "FALSE"},
		{"subschemaSubentry", "2.5.18.10", "cn=Subschema"},
	}
	for _, test := range filters {
		for _, attribute := range []string{test.name, test.oid} {
			t.Run(attribute, func(t *testing.T) {
				request := readOnlySearchRequest("("+attribute+"="+ldap.EscapeFilter(test.assertion)+")", []string{"cn"}, false)
				request.BaseDN, request.Scope = fixture.groups[0].DN, ldap.ScopeBaseObject
				result, err, outcome := smallNonRootDifferential(t, fixture, request, false)
				if err != nil || outcome.handlerError != "" || outcome.code != int(ldapwire.ResultSuccess) {
					t.Fatalf("synthesized filter fallback failed: SDK=%v handler=%q code=%d", err, outcome.handlerError, outcome.code)
				}
				if test.name == "subschemaSubentry" && (len(result.Entries) != 1 || result.Entries[0].DN != request.BaseDN) {
					t.Fatal("fallback failed to match the synthesized subschema reference")
				}
			})
		}
	}
	// Make the same filters indexable with zero stored postings. Removing the
	// operational-attribute gate must not silently turn them into handled misses.
	normalizer, indexes, err := loadDatabaseEqualityIndexes(directory.Entry{Attributes: []directory.Attribute{{
		Description: "olcDbIndex", Values: stringValues("uid,cn,member,objectClass,entryDN,hasSubordinates,subschemaSubentry eq"),
	}}}, fixture.state.runtime.schema)
	if err != nil {
		t.Fatal(err)
	}
	fixture.database.dnNormalizer, fixture.database.equalityIndexes = normalizer, indexes
	fixture.database.equalityIndexInit = &databaseEqualityIndexInitialization{}
	smallNonRootReady(t, fixture)
	for _, test := range filters {
		for _, attribute := range []string{test.name, test.oid} {
			message := smallIndexedMessage("(" + attribute + "=" + ldap.EscapeFilter(test.assertion) + ")")
			filter := message.Request.(ldapwire.SearchRequest).Filter
			if err := fixture.server.config.Store.View(t.Context(), func(reader storage.Reader) error {
				planned, count, err := storage.ForEachBoundedReadOnlyFilterCandidate(readerForDatabase(reader, *fixture.database),
					filter, 4, func(directory.Entry) error { return errors.New("unexpected stored operational value") })
				if err != nil || !planned || count != 0 {
					return fmt.Errorf("%s must have an eligible empty index: planned=%t count=%d err=%v", attribute, planned, count, err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			smallNonRootAssertDeclines(t, t.Context(), fixture, message)
		}
	}
}

func TestSmallNonRootSearchPreservesPagingAndTransaction(t *testing.T) {
	fixture := newSmallNonRootFixture(t, 2)
	t.Cleanup(func() {
		clearPagedSearch(fixture.state)
		clearLDAPTransaction(fixture.state.transaction)
	})
	request := readOnlySearchRequest("(uid=borrowed-groups)", []string{"cn", "description"}, false)
	pageRequest := *request
	pagingControl := ldap.NewControlPaging(1)
	pageRequest.Controls = []ldap.Control{pagingControl}
	first, err, outcome := smallNonRootSDKSearch(t, fixture, &pageRequest, "wrapper")
	smallNonRootAssertResult(t, first, err, outcome, ldap.LDAPResultSuccess, 1)
	paging := fixture.state.pagedSearch
	if paging == nil || len(paging.cookie) == 0 || paging.retainedBytes <= 0 {
		t.Fatal("fixture did not create a retained paging continuation")
	}
	cookie, cursor, count := bytes.Clone(paging.cookie), paging.cursor, paging.count
	searchBytes := fixture.server.searchMemoryLimiter.active.Load()
	if searchBytes != paging.retainedBytes || paging.releaseRetained == nil {
		t.Fatal("paging state has no matching process reservation")
	}

	start := ldapwire.ExtendedRequest{Name: transactionStartOID}
	capture := &transactionResultCapture{}
	if err := fixture.server.handleTransactionStart(capture, fixture.state, ldapwire.Message{ID: 20, Request: start}, start); err != nil || capture.response == nil || capture.response.result.Code != ldapwire.ResultSuccess {
		t.Fatalf("start transaction: response=%#v err=%v", capture.response, err)
	}
	transaction := fixture.state.transaction
	queued := ldapwire.Message{ID: 21, Request: ldapwire.ModifyRequest{DN: fixture.groups[0].DN, Changes: []ldapwire.Modification{{
		Operation: ldapwire.ModificationReplace,
		Attribute: directory.Attribute{Description: "description", Values: stringValues("not committed")},
	}}}, Controls: []ldapwire.Control{{OID: transactionSpecificationControlOID, Critical: true, HasValue: true, Value: transaction.identifier}}}
	capture = &transactionResultCapture{}
	if handled, err := fixture.server.handleTransactionSpecification(capture, fixture.state, queued); !handled || err != nil || capture.response == nil || capture.response.result.Code != ldapwire.ResultSuccess {
		t.Fatalf("queue transaction: handled=%t response=%#v err=%v", handled, capture.response, err)
	}
	if len(transaction.operations) != 1 || transaction.retainedBytes <= 0 {
		t.Fatal("fixture did not retain a queued transaction operation")
	}
	queuedWire, err := ldapwire.EncodeRequestMessage(transaction.operations[0].message)
	if err != nil {
		t.Fatal(err)
	}
	pendingBytes, queuedBytes := fixture.server.pendingByteLimiter.active.Load(), transaction.queuedBytes
	if pendingBytes != transaction.retainedBytes || transaction.releaseRetained == nil {
		t.Fatal("transaction has no matching pending-byte reservation")
	}
	result, err, outcome := smallNonRootDifferential(t, fixture, request, true)
	smallNonRootAssertResult(t, result, err, outcome, ldap.LDAPResultSuccess, 2)
	for _, entry := range result.Entries {
		if !strings.HasPrefix(entry.GetAttributeValue("description"), "private-") {
			t.Fatal("search exposed a queued, uncommitted modification")
		}
	}
	if fixture.state.pagedSearch != paging || !bytes.Equal(paging.cookie, cookie) || paging.cursor != cursor || paging.count != count ||
		paging.retainedBytes != searchBytes || paging.releaseRetained == nil || fixture.server.searchMemoryLimiter.active.Load() != searchBytes {
		t.Fatal("unpaged search changed the existing paging cursor or reservation")
	}
	if fixture.state.transaction != transaction || len(transaction.operations) != 1 || len(transaction.messageIDs) != 1 ||
		transaction.queuedBytes != queuedBytes || transaction.retainedBytes != pendingBytes || transaction.releaseRetained == nil ||
		fixture.server.pendingByteLimiter.active.Load() != pendingBytes {
		t.Fatal("unpaged search changed the queued transaction or reservation")
	}
	if _, found := transaction.messageIDs[queued.ID]; !found || transaction.operations[0].boundDN != fixture.state.boundDN {
		t.Fatal("unpaged search changed the queued operation identity")
	}
	afterWire, err := ldapwire.EncodeRequestMessage(transaction.operations[0].message)
	if err != nil || !bytes.Equal(afterWire, queuedWire) {
		t.Fatal("unpaged search mutated the queued modification")
	}
	pagingControl.SetCookie(cookie)
	second, err, outcome := smallNonRootSDKSearch(t, fixture, &pageRequest, "wrapper")
	smallNonRootAssertResult(t, second, err, outcome, ldap.LDAPResultSuccess, 1)
	if second.Entries[0].DN == first.Entries[0].DN || fixture.state.pagedSearch != nil || fixture.server.searchMemoryLimiter.active.Load() != 0 ||
		fixture.state.transaction != transaction || fixture.server.pendingByteLimiter.active.Load() != pendingBytes {
		t.Fatal("original paging continuation failed or affected the open transaction")
	}
}

type smallNonRootCancelOnViewContext struct {
	context.Context
	cancel context.CancelFunc
	views  int
}

func (ctx *smallNonRootCancelOnViewContext) Value(key any) any {
	value := ctx.Context.Value(key)
	if _, subject := key.(aclSubjectContextKey); subject {
		// accessReaderFromContext reads this key inside the concrete Bolt View
		// callback, after Bolt.View's initial cancellation check has passed.
		ctx.views++
		ctx.cancel()
	}
	return value
}

func TestSmallNonRootSearchCancellationDuringView(t *testing.T) {
	fixture := newSmallNonRootFixture(t, 1)
	message := smallIndexedMessage("(uid=borrowed-groups)")
	newContext := func() *smallNonRootCancelOnViewContext {
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		return &smallNonRootCancelOnViewContext{Context: ctx, cancel: cancel}
	}
	ctx := newContext()
	smallNonRootAssertDeclines(t, ctx, fixture, message)
	if ctx.views != 1 || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("cancellation did not occur inside the admitted Bolt view")
	}
	var general smallIndexedOutcome
	for _, mode := range []string{"general", "small", "wrapper"} {
		ctx := newContext()
		outcome := smallNonRootEvaluate(ctx, fixture.server, fixture.state, message, mode)
		if ctx.views != 1 || outcome.handled || !strings.Contains(outcome.handlerError, context.Canceled.Error()) ||
			len(outcome.wire) != 0 || outcome.memory != 0 || outcome.rejections != 0 {
			t.Fatalf("%s cancellation: views=%d handled=%t error=%q bytes=%d memory=%d rejected=%d", mode, ctx.views,
				outcome.handled, outcome.handlerError, len(outcome.wire), outcome.memory, outcome.rejections)
		}
		if mode == "general" {
			general = outcome
		} else if !reflect.DeepEqual(outcome, general) {
			t.Fatalf("%s cancellation differs from the general handler", mode)
		}
		smallNonRootNoCaches(t, fixture)
	}
}

// A decline must leave the response, both caches, storage and quota counters
// untouched. Do not install an observed Store here: it would mask every other
// guard by failing the concrete-Bolt check before reaching it.
func smallNonRootAssertDeclines(t *testing.T, ctx context.Context, fixture *readOnlySearchFixture, message ldapwire.Message) {
	t.Helper()
	request := message.Request.(ldapwire.SearchRequest)
	base, err := normalizeConnectionSearchRequestBase(fixture.state, request.BaseDN)
	if err != nil {
		t.Fatal(err)
	}
	database := databaseForNormalizedDN(fixture.state.runtime, base)
	if database == nil {
		t.Fatal("guard probe requires a routed base")
	}
	revision, available := fixture.server.currentStorageSnapshotRevision(t.Context())
	beforeRejected := fixture.server.searchMemoryLimiter.rejected.Load()
	capture := &smallIndexedCapture{}
	handled, err := fixture.server.trySmallNonRootSearch(ctx, capture, fixture.state, message, request, base, database)
	if handled || err != nil || capture.Len() != 0 || fixture.server.searchMemoryLimiter.active.Load() != 0 ||
		fixture.server.searchMemoryLimiter.rejected.Load() != beforeRejected {
		t.Fatalf("decline had effects: handled=%t err=%v bytes=%d active=%d rejected=%d", handled, err, capture.Len(),
			fixture.server.searchMemoryLimiter.active.Load(), fixture.server.searchMemoryLimiter.rejected.Load()-beforeRejected)
	}
	smallNonRootNoCaches(t, fixture)
	if after, known := fixture.server.currentStorageSnapshotRevision(t.Context()); known != available || after != revision {
		t.Fatal("declined search changed storage")
	}
}

func TestSmallNonRootSearchEligibilityGuards(t *testing.T) {
	for _, kind := range []string{"anonymous", "root", "unnegotiated protocol", "LDAPv2", "restricted", "account usability",
		"empty controls present", "empty attribute", "negative size", "shadow", "subordinate", "glue", "multiple routes", "relay", "dynlist",
		"collect", "nestgroup", "custom normalizer", "not initialized", "stale index", "untracked index", "canceled", "noop"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newSmallNonRootFixture(t, 1)
			message := smallIndexedMessage("(uid=borrowed-groups)")
			ctx := t.Context()
			switch kind {
			case "anonymous":
				fixture.state.boundDN = ""
			case "root":
				fixture.state.boundDN = smallIndexedRootDN
			case "unnegotiated protocol":
				fixture.state.protocolVersion = 0
			case "LDAPv2":
				fixture.state.protocolVersion = 2
			case "restricted":
				fixture.state.passwordPolicyRestrictedDN = fixture.state.boundDN
			case "account usability":
				fixture.state.accountUsabilityRequested = true
			case "empty controls present":
				message.ControlsPresent = true
			case "empty attribute":
				request := message.Request.(ldapwire.SearchRequest)
				request.Attributes = []string{""}
				message.Request = request
			case "negative size":
				request := message.Request.(ldapwire.SearchRequest)
				request.SizeLimit = -1
				message.Request = request
			case "shadow":
				fixture.database.shadow = true
			case "subordinate":
				fixture.database.subordinate = true
			case "glue":
				fixture.database.explicitGlue = true
			case "multiple routes":
				child := *fixture.database
				base, err := fixture.state.runtime.schema.NormalizeDN("ou=child," + smallIndexedPeopleDN)
				if err != nil {
					t.Fatal(err)
				}
				child.suffixes, child.subordinate, child.partition = []directory.DN{base}, true, "child"
				fixture.state.runtime.databases = append(fixture.state.runtime.databases, child)
			case "relay":
				fixture.database.relay = &relayRuntimeConfiguration{}
			case "dynlist":
				fixture.database.dynlist = &dynlistRuntimeConfiguration{}
			case "collect":
				fixture.database.collect = &collectRuntimeConfiguration{}
			case "nestgroup":
				fixture.database.nestGroups = []nestGroupRuntimeConfiguration{{}}
			case "custom normalizer":
				fixture.database.dnNormalizer = &readOnlySearchOwnedNormalizer{fixture.normalizer}
			case "not initialized":
				fixture.database.equalityIndexInit = &databaseEqualityIndexInitialization{}
			case "stale index":
				revision, _ := fixture.server.currentStorageSnapshotRevision(t.Context())
				fixture.database.equalityIndexInit.markReady(revision-1, true)
			case "untracked index":
				fixture.database.equalityIndexInit = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "noop":
				ctx = withNoOpSearch(ctx, 0)
			}
			smallNonRootAssertDeclines(t, ctx, fixture, message)
		})
	}
}

func TestSmallNonRootSearchCustomStoreAndReaderGate(t *testing.T) {
	fixture := newSmallNonRootFixture(t, 1)
	plain := fixture.server.config.Store
	if !plainBoltSearchStore(plain) || !plainBoltSearchStore(fixture.store) ||
		plainBoltSearchStore((*storage.Bolt)(nil)) || plainBoltSearchStore((*homedirEffectStore)(nil)) ||
		plainBoltSearchStore((*accessContextStore)(nil)) || plainBoltSearchStore(nil) {
		t.Fatal("concrete wrapper admission differs from the Bolt contract")
	}
	for _, wrapped := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrapped=%t", wrapped), func(t *testing.T) {
			observed := &smallIndexedObservedStore{Store: plain, hideRevision: true}
			fixture.server.config.Store = observed
			if wrapped {
				fixture.server.config.Store = &homedirEffectStore{Store: &accessContextStore{Store: observed}}
			}
			smallNonRootAssertDeclines(t, t.Context(), fixture, smallIndexedMessage("(uid=borrowed-groups)"))
			if observed.views != 0 || observed.updates != 0 {
				t.Fatal("speculation invoked an application-defined Store callback")
			}
		})
	}
	fixture.server.config.Store = plain
	if err := plain.View(t.Context(), func(reader storage.Reader) error {
		custom := &defaultProjectionContextReader{Reader: reader}
		if localProjectionReadOnly(fixture.state.runtime, custom) ||
			localProjectionReadOnly(fixture.state.runtime, readerForDatabase(custom, *fixture.database)) || custom.calls != 0 {
			t.Fatal("custom reader context was admitted or called speculatively")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	request := readOnlySearchRequest("(uid=borrowed-groups)", []string{"cn"}, false)
	_, _, outcome := smallNonRootDifferential(t, fixture, request, true)
	if outcome.entries != 1 {
		t.Fatal("restored concrete store did not handle the eligible search")
	}
}

func TestSmallNonRootSearchSpecialBaseAndCandidateFallback(t *testing.T) {
	for _, class := range []string{"alias", "referral", "subentry"} {
		for _, baseObject := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/base=%t", class, baseObject), func(t *testing.T) {
				fixture := newSmallNonRootFixture(t, 4)
				entry := fixture.groups[2].Clone()
				entry.ReplaceValues("objectClass", stringValues(class, "extensibleObject"))
				switch class {
				case "alias":
					entry.ReplaceValues("aliasedObjectName", stringValues(fixture.groups[0].DN))
				case "referral":
					entry.ReplaceValues("ref", stringValues("ldap://example.invalid/dc=remote"))
				case "subentry":
					entry.ReplaceValues("subtreeSpecification", stringValues("{}"))
				}
				smallIndexedPut(t, fixture.server, fixture.state, entry, true)
				smallNonRootReady(t, fixture)
				request := readOnlySearchRequest("(uid=borrowed-groups)", []string{"cn", "member"}, false)
				if baseObject {
					request.BaseDN, request.Scope, request.Filter = entry.DN, ldap.ScopeBaseObject, "(objectClass=*)"
				}
				smallNonRootDifferential(t, fixture, request, false)
			})
		}
	}
}

func TestSmallNonRootSearchMissingIndexedCandidateFallback(t *testing.T) {
	fixture := newSmallNonRootFixture(t, 4)
	path := filepath.Join(t.TempDir(), "missing-candidate.db")
	if _, err := fixture.store.Backup(t.Context(), path, false); err != nil {
		t.Fatal(err)
	}
	dn, err := fixture.state.runtime.schema.NormalizeDN(fixture.groups[2].DN)
	if err != nil {
		t.Fatal(err)
	}
	// Damage only a disposable copy: leave the posting intact while removing
	// its physical row, which normal Writer.Delete intentionally cannot do.
	raw, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = raw.Update(func(tx *bolt.Tx) error {
		entries := tx.Bucket([]byte("entries"))
		key := []byte(fixture.database.partition + "\x00" + dn.Key())
		if entries.Get(key) == nil {
			return fmt.Errorf("fixture candidate %q has no physical row", dn.String())
		}
		return entries.Delete(key)
	})
	closeErr := raw.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("damage copied candidate: %v / %v", err, closeErr)
	}
	copyStore, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = copyStore.Close() })
	fixture.server.config.Store = copyStore
	revision, available := copyStore.CurrentStorageSnapshotRevision()
	// The persisted index configuration is unchanged. Mark this snapshot ready
	// so the probe reaches the dangling posting rather than the readiness gate.
	fixture.database.equalityIndexInit.markReady(revision, available)
	message := smallIndexedMessage("(uid=borrowed-groups)")
	smallNonRootAssertDeclines(t, t.Context(), fixture, message)
	request := readOnlySearchRequest("(uid=borrowed-groups)", []string{"cn"}, false)
	_, sdkErr, outcome := smallNonRootDifferential(t, fixture, request, false)
	if sdkErr == nil || !strings.Contains(outcome.handlerError, "missing entry key") || len(outcome.wire) != 0 {
		t.Fatal("dangling posting did not preserve the general handler's error without partial output")
	}
}

func TestSmallNonRootSearchPositiveSizeSDK(t *testing.T) {
	fixture := newSmallNonRootFixture(t, 1)
	for _, filter := range []string{"(objectClass=*)", "(uid=group-00)", "(member=" + readOnlySearchMember + ")"} {
		t.Run(filter, func(t *testing.T) {
			request := readOnlySearchRequest(filter, []string{"cn", "member"}, false)
			request.SizeLimit = 2 // The real SDK workload uses len(want)+1.
			if filter == "(objectClass=*)" {
				request.BaseDN, request.Scope = fixture.groups[0].DN, ldap.ScopeBaseObject
			}
			result, err, outcome := smallNonRootDifferential(t, fixture, request, true)
			smallNonRootAssertResult(t, result, err, outcome, ldap.LDAPResultSuccess, 1)
		})
	}
}

func TestSmallNonRootSearchSizeAndMemoryPrecedence(t *testing.T) {
	fixture := newSmallNonRootFixture(t, 4, 1000, 105, 1003, 106)
	smallNonRootPolicy(t, fixture,
		fmt.Sprintf(`{0}to dn.exact="%s" attrs=entry by users search by * none`, fixture.groups[1].DN),
		"{1}to * by users read by * none")
	request := readOnlySearchRequest("(member="+readOnlySearchMember+")", []string{"cn", "member"}, false)
	for _, test := range []struct {
		name                  string
		requestMax, serverMax int
		code                  uint16
		entries               int
	}{
		{"exact visible request size", 3, 20, ldap.LDAPResultSuccess, 3},
		{"below visible request size", 2, 20, ldap.LDAPResultSizeLimitExceeded, 2},
		{"exact visible server size", 6, 3, ldap.LDAPResultSuccess, 3},
		{"below visible server size", 6, 2, ldap.LDAPResultSizeLimitExceeded, 2},
		{"single surviving entry limit", 1, 20, ldap.LDAPResultSizeLimitExceeded, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			request.SizeLimit, fixture.server.config.MaxSearchEntries = test.requestMax, test.serverMax
			result, err, outcome := smallNonRootDifferential(t, fixture, request, true)
			smallNonRootAssertResult(t, result, err, outcome, test.code, test.entries)
			if outcome.rejections != 0 || outcome.diagnostic != "" {
				t.Fatal("size limit changed memory rejection accounting or diagnostics")
			}
			for _, entry := range result.Entries {
				if entry.DN == fixture.groups[1].DN {
					t.Fatal("denied candidate consumed a result slot or leaked into the response")
				}
			}
		})
	}
	request.SizeLimit, fixture.server.config.MaxSearchEntries = 2, 20
	message := smallIndexedMessage(request.Filter)
	wireRequest := message.Request.(ldapwire.SearchRequest)
	wireRequest.SizeLimit, wireRequest.Attributes = request.SizeLimit, request.Attributes
	message.Request = wireRequest
	prelude, _ := smallIndexedTestPrelude(fixture.server, fixture.state, message)
	var prefixBytes int64
	capture := &smallIndexedCapture{onWrite: func() { prefixBytes = max(prefixBytes, fixture.server.searchMemoryLimiter.active.Load()) }}
	if err := fixture.server.handleUncachedSearch(t.Context(), capture, fixture.state, message, wireRequest, prelude); err != nil || prefixBytes <= 0 {
		t.Fatalf("general partial-result reservation: bytes=%d err=%v", prefixBytes, err)
	}
	for _, test := range []struct {
		name                     string
		candidateMax, processMax int64
		code                     uint16
		entries                  int
		diagnostic               string
		rejections               uint64
	}{
		{name: "size before candidate budget", candidateMax: prefixBytes, processMax: prefixBytes * 2,
			code: ldap.LDAPResultSizeLimitExceeded, entries: 2},
		{name: "size before process budget", candidateMax: prefixBytes * 2, processMax: prefixBytes,
			code: ldap.LDAPResultSizeLimitExceeded, entries: 2},
		{name: "candidate failure before size overflow", candidateMax: prefixBytes - 1, processMax: prefixBytes * 2,
			code: ldap.LDAPResultAdminLimitExceeded, diagnostic: "search candidate budget exceeded"},
		{name: "process failure before size overflow", candidateMax: prefixBytes * 2, processMax: prefixBytes - 1,
			code: ldap.LDAPResultAdminLimitExceeded, diagnostic: "process search memory budget exceeded", rejections: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture.server.config.MaxSearchCandidateBytes = test.candidateMax
			fixture.server.searchMemoryLimiter = newResourceByteLimiter(test.processMax)
			result, err, outcome := smallNonRootDifferential(t, fixture, request, true)
			smallNonRootAssertResult(t, result, err, outcome, test.code, test.entries)
			if outcome.diagnostic != test.diagnostic || outcome.rejections != test.rejections ||
				fixture.server.searchMemoryLimiter.rejected.Load() != 3*test.rejections {
				t.Fatalf("size/memory precedence: diagnostic=%q rejected=%d total=%d", outcome.diagnostic,
					outcome.rejections, fixture.server.searchMemoryLimiter.rejected.Load())
			}
		})
	}
}

func TestSmallNonRootSearchMemoryAndCandidateBoundaries(t *testing.T) {
	for _, basePresence := range []bool{false, true} {
		t.Run(fmt.Sprintf("base=%t", basePresence), func(t *testing.T) {
			fixture := newSmallNonRootFixture(t, 4, 1000, 105, 1003, 106)
			message := smallIndexedMessage("(uid=borrowed-groups)")
			request := readOnlySearchRequest("(uid=borrowed-groups)", []string{"cn", "member", "jpegPhoto"}, false)
			maximum, entries := 4, 4
			if basePresence {
				message = smallIndexedMessage("(objectClass=*)")
				request.BaseDN, request.Scope, request.Filter = fixture.groups[0].DN, ldap.ScopeBaseObject, "(objectClass=*)"
				maximum, entries = 1, 1
			}
			wireRequest := message.Request.(ldapwire.SearchRequest)
			wireRequest.BaseDN, wireRequest.Scope, wireRequest.Attributes = request.BaseDN, directory.Scope(request.Scope), request.Attributes
			message.Request = wireRequest
			prelude, database := smallIndexedTestPrelude(fixture.server, fixture.state, message)
			var retained int64
			general := &smallIndexedCapture{onWrite: func() { retained = max(retained, fixture.server.searchMemoryLimiter.active.Load()) }}
			if err := fixture.server.handleUncachedSearch(t.Context(), general, fixture.state, message, wireRequest, prelude); err != nil || retained <= 0 {
				t.Fatalf("general candidate reservation: bytes=%d err=%v", retained, err)
			}
			var fastRetained int64
			fast := &smallIndexedCapture{onWrite: func() { fastRetained = max(fastRetained, fixture.server.searchMemoryLimiter.active.Load()) }}
			if handled, err := fixture.server.trySmallNonRootSearch(t.Context(), fast, fixture.state, message, wireRequest, prelude.base, database); !handled || err != nil || fastRetained != retained || !bytes.Equal(fast.Bytes(), general.Bytes()) {
				t.Fatalf("reservation/wire differs: handled=%t err=%v fast=%d general=%d", handled, err, fastRetained, retained)
			}
			for _, test := range []struct {
				name                     string
				candidateMax, processMax int64
				code                     uint16
				entries                  int
				diagnostic               string
				rejections               uint64
			}{
				{name: "exact candidate bytes", candidateMax: retained, processMax: retained * 2, entries: entries},
				{name: "candidate bytes minus one", candidateMax: retained - 1, processMax: retained * 2,
					code: ldap.LDAPResultAdminLimitExceeded, diagnostic: "search candidate budget exceeded"},
				{name: "exact process bytes", candidateMax: retained * 2, processMax: retained, entries: entries},
				{name: "process bytes minus one", candidateMax: retained * 2, processMax: retained - 1,
					code: ldap.LDAPResultAdminLimitExceeded, diagnostic: "process search memory budget exceeded", rejections: 1},
			} {
				t.Run(test.name, func(t *testing.T) {
					fixture.server.config.MaxSearchCandidateBytes = test.candidateMax
					fixture.server.config.MaxSearchEntries = maximum
					fixture.server.searchMemoryLimiter = newResourceByteLimiter(test.processMax)
					result, err, outcome := smallNonRootDifferential(t, fixture, request, true)
					smallNonRootAssertResult(t, result, err, outcome, test.code, test.entries)
					if outcome.diagnostic != test.diagnostic || outcome.rejections != test.rejections ||
						fixture.server.searchMemoryLimiter.rejected.Load() != 3*test.rejections {
						t.Fatalf("incorrect budget diagnostic/rejection accounting: %+v", outcome)
					}
				})
			}
		})
	}
}

func TestSmallNonRootSearchWireFailureReleasesReservation(t *testing.T) {
	fixture := newSmallNonRootFixture(t, 4)
	message := smallIndexedMessage("(uid=borrowed-groups)")
	request := message.Request.(ldapwire.SearchRequest)
	prelude, database := smallIndexedTestPrelude(fixture.server, fixture.state, message)
	failure := errors.New("injected write failure")
	var retained int64
	capture := &smallIndexedCapture{err: failure, onWrite: func() { retained = fixture.server.searchMemoryLimiter.active.Load() }}
	handled, err := fixture.server.trySmallNonRootSearch(t.Context(), capture, fixture.state, message, request, prelude.base, database)
	if !handled || !errors.Is(err, failure) || retained <= 0 || capture.Len() != 0 ||
		fixture.server.searchMemoryLimiter.active.Load() != 0 || fixture.server.searchMemoryLimiter.rejected.Load() != 0 {
		t.Fatalf("write failure: handled=%t err=%v retained=%d", handled, err, retained)
	}
	smallNonRootNoCaches(t, fixture)
}

func smallNonRootBind(t *testing.T, fixture *readOnlySearchFixture, dn, password string) {
	t.Helper()
	request := ldapwire.BindRequest{Version: 3, Name: dn, Authentication: ldapwire.Authentication{Simple: []byte(password)}}
	message := ldapwire.Message{ID: 1, Request: request}
	capture := &smallIndexedCapture{}
	if err := fixture.server.handleBind(t.Context(), capture, fixture.state, message, request); err != nil {
		t.Fatal(err)
	}
	response, err := ber.DecodePacketErr(capture.Bytes())
	if err != nil || len(response.Children) < 2 || len(response.Children[1].Children) < 1 ||
		response.Children[1].Tag != ldapwire.ApplicationBindResponse || response.Children[1].Children[0].Value != int64(ldapwire.ResultSuccess) {
		t.Fatalf("rebind failed: packet=%#v err=%v", response, err)
	}
	if fixture.state.boundDN != dn || fixture.state.protocolVersion != 3 {
		t.Fatalf("rebind did not replace the session identity: %q/v%d", fixture.state.boundDN, fixture.state.protocolVersion)
	}
}

func TestSmallNonRootSearchLiveWriteAndRebind(t *testing.T) {
	fixture := newSmallNonRootFixture(t, 4)
	const otherDN = "uid=other," + smallIndexedPeopleDN
	for _, dn := range []string{smallNonRootReaderDN, otherDN} {
		smallIndexedPut(t, fixture.server, fixture.state, directory.Entry{DN: dn, Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "cn", Values: stringValues("Reader")},
			{Description: "sn", Values: stringValues("Example")},
			{Description: "userPassword", Values: stringValues("secret")},
		}}, false)
	}
	smallNonRootPolicy(t, fixture,
		"{0}to attrs=userPassword by anonymous auth by * none",
		fmt.Sprintf(`{1}to attrs=description by dn.exact="%s" read by * none`, smallNonRootReaderDN),
		"{2}to * by users read by * none")
	smallNonRootBind(t, fixture, smallNonRootReaderDN, "secret")
	smallNonRootReady(t, fixture)
	request := readOnlySearchRequest("(uid=borrowed-groups)", []string{"cn", "description", "member", "jpegPhoto"}, false)
	original, err, outcome := smallNonRootDifferential(t, fixture, request, true)
	smallNonRootAssertResult(t, original, err, outcome, ldap.LDAPResultSuccess, 4)
	beforeWire := bytes.Clone(outcome.wire)
	for _, entry := range original.Entries {
		if !strings.HasPrefix(entry.GetAttributeValue("description"), "private-") {
			t.Fatal("initial reader ACL did not expose the original description")
		}
	}
	for i := range fixture.groups {
		entry := fixture.groups[i].Clone()
		entry.ReplaceValues("description", stringValues(strings.Repeat("changed", 100)))
		entry.ReplaceValues("member", stringValues("uid=new,"+smallIndexedPeopleDN))
		entry.ReplaceValues("jpegPhoto", [][]byte{{255, byte(i), 0}})
		smallIndexedPut(t, fixture.server, fixture.state, entry, true)
	}
	// A stale readiness marker must decline. The next dispatched general read
	// initializes the new revision and sees the write on the existing session.
	smallNonRootAssertDeclines(t, t.Context(), fixture, smallIndexedMessage("(uid=borrowed-groups)"))
	updated, err, outcome := smallNonRootSDKSearch(t, fixture, request, "wrapper")
	smallNonRootAssertResult(t, updated, err, outcome, ldap.LDAPResultSuccess, 4)
	updated, err, outcome = smallNonRootDifferential(t, fixture, request, true)
	smallNonRootAssertResult(t, updated, err, outcome, ldap.LDAPResultSuccess, 4)
	if bytes.Equal(beforeWire, outcome.wire) {
		t.Fatal("live write returned the old wire response")
	}
	for _, entry := range updated.Entries {
		if entry.GetAttributeValue("description") != strings.Repeat("changed", 100) ||
			!slices.Equal(entry.GetAttributeValues("member"), []string{"uid=new," + smallIndexedPeopleDN}) {
			t.Fatal("live search reused old attribute values")
		}
	}
	for _, entry := range original.Entries {
		if !strings.HasPrefix(entry.GetAttributeValue("description"), "private-") || entry.GetAttributeValues("member")[0] != readOnlySearchMember {
			t.Fatal("write changed the retained SDK result from the old snapshot")
		}
	}
	memberRequest := readOnlySearchRequest("(member="+readOnlySearchMember+")", []string{"cn"}, false)
	result, err, outcome := smallNonRootDifferential(t, fixture, memberRequest, true)
	smallNonRootAssertResult(t, result, err, outcome, ldap.LDAPResultSuccess, 0)
	memberRequest.Filter = "(member=uid=new," + smallIndexedPeopleDN + ")"
	result, err, outcome = smallNonRootDifferential(t, fixture, memberRequest, true)
	smallNonRootAssertResult(t, result, err, outcome, ldap.LDAPResultSuccess, 4)
	for _, dn := range []string{otherDN, smallNonRootReaderDN} {
		smallNonRootBind(t, fixture, dn, "secret")
		smallNonRootReady(t, fixture)
		result, err, outcome := smallNonRootDifferential(t, fixture, request, true)
		smallNonRootAssertResult(t, result, err, outcome, ldap.LDAPResultSuccess, 4)
		for _, entry := range result.Entries {
			want := ""
			if dn == smallNonRootReaderDN {
				want = strings.Repeat("changed", 100)
			}
			if entry.GetAttributeValue("description") != want ||
				(dn == otherDN && slices.ContainsFunc(entry.Attributes, func(a *ldap.EntryAttribute) bool { return a.Name == "description" })) {
				t.Fatalf("rebind reused the previous subject's attribute authorization: %s", dn)
			}
		}
	}
}
