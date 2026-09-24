package server

import (
	"bytes"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
	bolt "go.etcd.io/bbolt"
)

const readOnlySearchMember = "uid=shared," + smallIndexedPeopleDN

// Preserve every index, identity, and validation-cache method. The custom type
// fails localProjectionReadOnly without removing indexes or changing the ACL.
type readOnlySearchOwnedNormalizer struct {
	*databaseEqualityIndexNormalizer
}

var (
	_ storage.EqualityIndexSchema              = (*readOnlySearchOwnedNormalizer)(nil)
	_ storage.EqualityIndexValidationCache     = (*readOnlySearchOwnedNormalizer)(nil)
	_ storage.DNIdentityHintResolver           = (*readOnlySearchOwnedNormalizer)(nil)
	_ storage.EqualityIndexDNReferenceResolver = (*readOnlySearchOwnedNormalizer)(nil)
)

type readOnlySearchFixture struct {
	server     *Server
	state      *connectionState
	database   *runtimeDatabase
	normalizer *databaseEqualityIndexNormalizer
	store      *storage.Bolt
	groups     []directory.Entry
}

func newReadOnlySearchFixture(t *testing.T, count int, memberCounts ...int) *readOnlySearchFixture {
	t.Helper()
	if len(memberCounts) != 0 && len(memberCounts) != count {
		t.Fatal("member counts must specify every candidate")
	}
	server, state := newSmallIndexedFixture(t, 0)
	base, err := state.runtime.schema.NormalizeDN(smallIndexedPeopleDN)
	if err != nil {
		t.Fatal(err)
	}
	database := databaseForNormalizedDN(state.runtime, base)
	normalizer, indexes, err := loadDatabaseEqualityIndexes(directory.Entry{Attributes: []directory.Attribute{
		{Description: "olcDbIndex", Values: stringValues("uid,cn,member,objectClass eq")},
	}}, state.runtime.schema)
	if err != nil {
		t.Fatal(err)
	}
	database.dnNormalizer, database.equalityIndexes = normalizer, indexes
	database.equalityIndexInit = &databaseEqualityIndexInitialization{}
	fixture := &readOnlySearchFixture{
		server: server, state: state, database: database,
		normalizer: normalizer.(*databaseEqualityIndexNormalizer),
		store:      server.config.Store.(*homedirEffectStore).Store.(*accessContextStore).Store.(*storage.Bolt),
	}
	for i := range count {
		name := fmt.Sprintf("group-%02d", i)
		entry := directory.Entry{DN: "cn=" + name + "," + smallIndexedPeopleDN, Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("groupOfNames", "extensibleObject")},
			{Description: "cn", Values: stringValues(name), RawNormalized: i%2 == 0},
			{Description: "uid", Values: stringValues("borrowed-groups", name)},
			{Description: "member", Values: stringValues(readOnlySearchMember)},
			{Description: "description", Values: stringValues("private-" + name), RawNormalized: true},
			{Description: "userPassword", Values: stringValues("secret-" + name)},
			{Description: "jpegPhoto", Values: [][]byte{{0, byte(i), 255}}},
		}}
		smallIndexedPut(t, server, state, entry, false)
		fixture.groups = append(fixture.groups, entry)
	}
	routes := databaseSearchRoutesFromNormalizedBase(state.runtime.databases, base, directory.ScopeWholeSubtree)
	if err := server.ensureSearchEqualityIndexes(t.Context(), state.runtime, routes); err != nil {
		t.Fatal(err)
	}
	// Candidate references have their own order. Assign the requested sizes in
	// that order so overflow rows really precede inline rows during callbacks.
	var ordered []directory.Entry
	if err := server.config.Store.View(t.Context(), func(reader storage.Reader) error {
		planned, candidates, err := storage.ForEachFilterCandidate(readerForDatabase(reader, *database),
			directory.Filter{Kind: directory.FilterEquality, Attribute: "uid", Assertion: []byte("borrowed-groups")},
			func(entry directory.Entry) error {
				ordered = append(ordered, entry.Clone())
				return nil
			})
		if err == nil && (!planned || candidates != count) {
			return fmt.Errorf("fixture index plan = %t/%d, want %d", planned, candidates, count)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	fixture.groups = ordered
	for i := range fixture.groups {
		memberCount := 105 + i
		if len(memberCounts) != 0 {
			memberCount = memberCounts[i]
		}
		members := stringValues(readOnlySearchMember)
		for j := range memberCount - 1 {
			members = append(members, []byte(fmt.Sprintf("uid=member-%02d-%03d,%s", i, j, smallIndexedPeopleDN)))
		}
		fixture.groups[i].ReplaceValues("member", members)
		smallIndexedPut(t, server, state, fixture.groups[i], true)
	}
	if err := server.ensureSearchEqualityIndexes(t.Context(), state.runtime, routes); err != nil {
		t.Fatal(err)
	}
	state.runtime.access = acl.DefaultPolicy()
	return fixture
}

func (fixture *readOnlySearchFixture) policy(t *testing.T, name string) {
	t.Helper()
	switch name {
	case "default":
		fixture.state.runtime.access = acl.DefaultPolicy()
	case "mixed":
		fixture.state.runtime.access = defaultProjectionPolicy(t, nil, map[string][]acl.Rule{
			"dc=example,dc=com": defaultProjectionRules(t,
				fmt.Sprintf(`{0}to dn.exact="%s" attrs=entry by * search`, fixture.groups[1].DN),
				"{1}to attrs=description,userPassword by * none",
				"{2}to attrs=member by anonymous search by users read by * none",
				"{3}to * by * read"),
		})
	case "filter denied":
		fixture.state.runtime.access = defaultProjectionPolicy(t, defaultProjectionRules(t,
			"{0}to attrs=member,uid by * none", "{1}to * by * read"), nil)
	default:
		t.Fatalf("unknown policy %q", name)
	}
	if !fixture.state.runtime.access.CanBatchValues() {
		t.Fatal("fixture policy must permit value batching")
	}
}

func readOnlySearchRequest(filter string, attributes []string, typesOnly bool) *ldap.SearchRequest {
	request := smallIndexedSDKRequest(filter)
	request.Attributes, request.TypesOnly = attributes, typesOnly
	return request
}

// Check the production branch's other gates for both normalizer types, and
// prove these small Bolt postings actually reuse borrowed descriptors. A plain
// Registry wrapper would lose the index interfaces and silently test a scan.
func (fixture *readOnlySearchFixture) assertEligible(t *testing.T, request *ldap.SearchRequest, owned bool) {
	t.Helper()
	runtime := fixture.state.runtime
	message := smallIndexedMessage(request.Filter)
	wireRequest := message.Request.(ldapwire.SearchRequest)
	wireRequest.Attributes, wireRequest.TypesOnly = request.Attributes, request.TypesOnly
	_, prepared := runtime.searchSelections.get(runtime.schema, request.Attributes)
	// Wildcards deliberately remain on the owned fallback; the other requested
	// selections must exercise the new branch, including TypesOnly and 1.1.
	if prepared == slices.Contains(request.Attributes, "*") ||
		len(request.Controls) != 0 || request.DerefAliases != ldap.NeverDerefAliases ||
		!runtime.access.CanBatchValues() || !smallIndexedRuntimeProjectionSafe(runtime) ||
		!databaseSearchResultCacheSafe(runtime, *fixture.database) ||
		searchRequestsSubschemaReference(runtime.schema, wireRequest, nil) {
		t.Fatal("request does not satisfy the unpaged borrowed branch guards")
	}
	if err := fixture.server.config.Store.View(t.Context(), func(reader storage.Reader) error {
		tx := readerForDatabase(reader, *fixture.database)
		if got := localProjectionReadOnly(runtime, tx); got == owned {
			t.Fatalf("localProjectionReadOnly = %t, owned baseline = %t", got, owned)
		}
		collective, err := runtimeCollectiveAttributePlan(runtime, fixture.database.partition, tx)
		if err != nil {
			return err
		}
		if len(collective.sources) != 0 ||
			newCollectProjectionCache(fixture.server, runtime, reader, fixture.state.boundDN).enabled ||
			newNestGroupProjectionCache(t.Context(), fixture.server, runtime, reader, fixture.state.boundDN,
				nestGroupProjectionRequest{attributes: request.Attributes, filter: wireRequest.Filter}).enabled {
			t.Fatal("fixture unexpectedly enables a projection")
		}
		borrows := !owned && prepared
		iterate := storage.ForEachFilterCandidate
		if borrows {
			iterate = storage.ForEachReadOnlyFilterCandidate
		}
		var addresses []uintptr
		planned, count, err := iterate(tx, wireRequest.Filter, func(entry directory.Entry) error {
			// Record only addresses, never borrowed descriptors or value slices.
			address := reflect.ValueOf(&entry.Attributes[0]).Pointer()
			if len(addresses) > 0 && slices.Contains(addresses, address) != borrows {
				t.Fatalf("descriptor reuse does not match borrowed=%t", borrows)
			}
			want := fixture.groups[len(addresses)]
			if entry.DN != want.DN || len(entry.Values("member")) != len(want.Values("member")) {
				t.Fatal("candidate order or member count differs from the large/small fixture")
			}
			addresses = append(addresses, address)
			return nil
		})
		if err != nil || !planned || count != len(fixture.groups) {
			t.Fatalf("indexed plan = %t/%d/%v, want %d candidates", planned, count, err, len(fixture.groups))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func (fixture *readOnlySearchFixture) search(t *testing.T, request *ldap.SearchRequest, owned bool) (*ldap.SearchResult, error, smallIndexedOutcome) {
	t.Helper()
	fixture.database.dnNormalizer = fixture.normalizer
	if owned {
		fixture.database.dnNormalizer = &readOnlySearchOwnedNormalizer{fixture.normalizer}
	}
	defer func() { fixture.database.dnNormalizer = fixture.normalizer }()
	fixture.assertEligible(t, request, owned)
	fixture.state.runtime.searchResults = newSearchResultCache(32 << 20)
	// "general" calls handleUncachedSearch with an evaluated prelude, bypassing
	// both trySmallIndexedSearch and result-cache hits even for root and <=4 rows.
	result, err, outcome := smallIndexedSDKSearch(t, fixture.server, fixture.state, request, "general")
	if outcome.handled || outcome.handlerError != "" || outcome.memory != 0 {
		t.Fatalf("general handler failure or leaked reservation: %+v", outcome)
	}
	return result, err, outcome
}

func (fixture *readOnlySearchFixture) assertEntries(t *testing.T, result *ldap.SearchResult, request *ldap.SearchRequest, policy string) {
	t.Helper()
	want := make(map[string]map[string][][]byte)
	root := fixture.state.boundDN == smallIndexedRootDN
	for i, entry := range fixture.groups {
		if !root && (policy == "filter denied" || policy == "mixed" && i == 1) {
			continue
		}
		attributes := make(map[string][][]byte)
		for _, attribute := range entry.Attributes {
			if !slices.Contains(request.Attributes, "*") && !slices.Contains(request.Attributes, attribute.Description) {
				continue
			}
			if !root && policy == "mixed" && (attribute.Description == "description" ||
				attribute.Description == "userPassword" || attribute.Description == "member" && fixture.state.boundDN == "") {
				continue
			}
			values := attribute.Values
			if request.TypesOnly {
				values = nil
			}
			attributes[attribute.Description] = values
		}
		want[entry.DN] = attributes
	}
	if result == nil || len(result.Entries) != len(want) || len(result.Referrals) != 0 || len(result.Controls) != 0 {
		t.Fatalf("response = %#v, want %d entries without controls/referrals", result, len(want))
	}
	for _, entry := range result.Entries {
		attributes, found := want[entry.DN]
		if !found || len(entry.Attributes) != len(attributes) {
			t.Fatalf("unexpected DN/attributes for %q: %#v; want %#v", entry.DN, entry.Attributes, attributes)
		}
		for _, attribute := range entry.Attributes {
			values, found := attributes[attribute.Name]
			if !found || !slices.EqualFunc(attribute.ByteValues, values, bytes.Equal) {
				t.Fatalf("%s/%s: got %d values, want %d (present=%t)", entry.DN, attribute.Name,
					len(attribute.ByteValues), len(values), found)
			}
			delete(attributes, attribute.Name)
		}
		delete(want, entry.DN)
	}
}

// Compare the encoded entries themselves, including flags and value ordering,
// without relying on a decoder that could hide an in-place storage mutation.
func (fixture *readOnlySearchFixture) rawEntries(t *testing.T) (map[string][]byte, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "snapshot.db")
	if _, err := fixture.store.Backup(t.Context(), path, false); err != nil {
		return nil, err
	}
	snapshot, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer snapshot.Close()
	entries := make(map[string][]byte)
	if err := snapshot.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("entries")).ForEach(func(key, value []byte) error {
			entries[string(key)] = bytes.Clone(value)
			return nil
		})
	}); err != nil {
		return nil, err
	}
	return entries, nil
}

func TestReadOnlyNonRootSearchOwnedDifferential(t *testing.T) {
	for _, test := range []struct {
		count   int
		members []int
	}{
		{count: 2}, {count: 3}, {count: 4},
		{count: 2, members: []int{1000, 105}},
		{count: 3, members: []int{1000, 105, 1003}},
		{count: 4, members: []int{1000, 105, 1003, 106}},
	} {
		t.Run(fmt.Sprintf("candidates=%d/overflow=%t", test.count, len(test.members) > 0), func(t *testing.T) {
			fixture := newReadOnlySearchFixture(t, test.count, test.members...)
			before, err := fixture.rawEntries(t)
			if err != nil {
				t.Fatal(err)
			}
			for _, policy := range []string{"default", "mixed", "filter denied"} {
				fixture.policy(t, policy)
				for _, subject := range []string{"", "uid=reader," + smallIndexedPeopleDN, smallIndexedRootDN} {
					fixture.state.boundDN = subject
					for _, filter := range []string{"(member=" + readOnlySearchMember + ")", "(UID=BORROWED-GROUPS)"} {
						for _, attributes := range [][]string{{"cn"}, {"member"}, {"cn", "member", "description", "userPassword"}, {"*"}, {"1.1"}} {
							for _, typesOnly := range []bool{false, true} {
								t.Run(fmt.Sprintf("%s/%s/%s/%v/types=%t", policy, subject, filter, attributes, typesOnly), func(t *testing.T) {
									request := readOnlySearchRequest(filter, attributes, typesOnly)
									want, wantErr, owned := fixture.search(t, request, true)
									got, gotErr, borrowed := fixture.search(t, request, false)
									if wantErr != nil || gotErr != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(borrowed, owned) {
										t.Fatalf("owned/borrowed responses differ: errors=%v/%v, codes=%d/%d, entries=%d/%d",
											wantErr, gotErr, owned.code, borrowed.code, owned.entries, borrowed.entries)
									}
									if borrowed.code != int(ldapwire.ResultSuccess) || borrowed.rejections != 0 || borrowed.entries != len(got.Entries) {
										t.Fatalf("unexpected audit/quota result: %+v", borrowed)
									}
									fixture.assertEntries(t, got, request, policy)
								})
							}
						}
					}
				}
			}
			after, err := fixture.rawEntries(t)
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatalf("search changed encoded Bolt entries: %v", err)
			}
		})
	}
}

func TestReadOnlyNonRootSearchRetentionAfterUpdateAndUnmap(t *testing.T) {
	for _, members := range [][]int{nil, {1000, 105, 1003, 106}} {
		for _, policy := range []string{"default", "mixed"} {
			t.Run(fmt.Sprintf("overflow=%t/%s", len(members) > 0, policy), func(t *testing.T) {
				testReadOnlySearchRetention(t, members, policy)
			})
		}
	}
}

func testReadOnlySearchRetention(t *testing.T, members []int, policy string) {
	t.Helper()
	for _, subject := range []string{"", "uid=reader," + smallIndexedPeopleDN, smallIndexedRootDN} {
		for _, attributes := range [][]string{{"cn"}, {"member"}, {"*"}, {"1.1"}} {
			for _, typesOnly := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%v/types=%t", subject, attributes, typesOnly), func(t *testing.T) {
					fixture := newReadOnlySearchFixture(t, 4, members...)
					fixture.policy(t, policy)
					fixture.state.boundDN = subject
					request := readOnlySearchRequest("(member="+readOnlySearchMember+")", attributes, typesOnly)
					want, wantErr, owned := fixture.search(t, request, true)
					if wantErr != nil {
						t.Fatal(wantErr)
					}
					before, err := fixture.rawEntries(t)
					if err != nil {
						t.Fatal(err)
					}
					observed := &smallIndexedObservedStore{Store: fixture.server.config.Store}
					fixture.server.config.Store = observed
					var closed bool
					observed.afterView = func() error {
						if fixture.server.searchMemoryLimiter.active.Load() == 0 {
							return nil
						}
						observed.afterView = nil
						// handleUncachedSearch has retained all selected entries but
						// has not encoded any LDAP responses. Its read tx is closed.
						after, err := fixture.rawEntries(t)
						if err != nil {
							return err
						}
						if !reflect.DeepEqual(after, before) {
							return fmt.Errorf("borrowed projection changed encoded Bolt entries")
						}
						for generation := range 3 {
							if err := observed.Store.Update(t.Context(), func(writer storage.Writer) error {
								tx := writerForDatabase(writer, *fixture.database)
								for _, original := range fixture.groups {
									entry := original.Clone()
									entry.ReplaceValues("cn", stringValues(fmt.Sprintf("replaced-%d", generation)))
									entry.ReplaceValues("member", stringValues("uid=replaced,"+smallIndexedPeopleDN))
									if err := tx.Put(entry, true); err != nil {
										return err
									}
								}
								return nil
							}); err != nil {
								return err
							}
						}
						if err := observed.Store.Close(); err != nil {
							return err
						}
						closed = true
						return nil
					}
					got, gotErr, borrowed := fixture.search(t, request, false)
					if !closed || gotErr != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(borrowed, owned) {
						t.Fatalf("response changed after update/unmap: closed=%t error=%v codes=%d/%d entries=%d/%d",
							closed, gotErr, borrowed.code, owned.code, borrowed.entries, owned.entries)
					}
					fixture.assertEntries(t, got, request, policy)
				})
			}
		}
	}
}

func TestReadOnlyNonRootSearchCandidateLimits(t *testing.T) {
	fixture := newReadOnlySearchFixture(t, 4, 1000, 105, 1003, 106)
	fixture.policy(t, "mixed")
	for _, subject := range []string{"", "uid=reader," + smallIndexedPeopleDN, smallIndexedRootDN} {
		fixture.state.boundDN = subject
		for _, limit := range []int{3, 4} {
			t.Run(fmt.Sprintf("%s/unchecked=%d", subject, limit), func(t *testing.T) {
				fixture.database.searchSizeLimits = []databaseSearchSizeLimit{{
					selector: databaseSearchLimitAny, unchecked: limit, uncheckedSet: true,
				}}
				request := readOnlySearchRequest("(UID=BORROWED-GROUPS)", []string{"cn", "member"}, false)
				want, wantErr, owned := fixture.search(t, request, true)
				got, gotErr, borrowed := fixture.search(t, request, false)
				if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || !reflect.DeepEqual(borrowed, owned) {
					t.Fatal("candidate limit changed response, audit, or reservations")
				}
				if limit == 3 && subject != smallIndexedRootDN {
					// The entry denied by ACL still consumes a raw candidate slot.
					if !ldap.IsErrorWithCode(gotErr, ldap.LDAPResultAdminLimitExceeded) ||
						borrowed.code != int(ldapwire.ResultAdminLimitExceeded) || borrowed.entries != 0 {
						t.Fatalf("unchecked limit ignored denied candidate: error=%v code=%d entries=%d", gotErr, borrowed.code, borrowed.entries)
					}
				} else {
					if gotErr != nil || borrowed.code != int(ldapwire.ResultSuccess) {
						t.Fatalf("exact candidate limit/root exemption failed: %v", gotErr)
					}
					fixture.assertEntries(t, got, request, "mixed")
				}
			})
		}
	}
}

func TestReadOnlyNonRootSearchMemoryAndSizeLimits(t *testing.T) {
	fixture := newReadOnlySearchFixture(t, 4, 1000, 105, 1003, 106)
	fixture.policy(t, "mixed")
	fixture.state.boundDN = "uid=reader," + smallIndexedPeopleDN
	request := readOnlySearchRequest("(member="+readOnlySearchMember+")", []string{"cn", "member"}, false)
	observed := &smallIndexedObservedStore{Store: fixture.server.config.Store}
	fixture.server.config.Store = observed
	var retained int64
	observed.afterView = func() error {
		retained = max(retained, fixture.server.searchMemoryLimiter.active.Load())
		return nil
	}
	result, err, baseline := fixture.search(t, request, true)
	if err != nil || retained <= 0 || baseline.entries != 3 {
		t.Fatalf("cannot establish owned candidate budget: bytes=%d entries=%d error=%v", retained, baseline.entries, err)
	}
	fixture.assertEntries(t, result, request, "mixed")
	observed.afterView = nil
	for _, test := range []struct {
		name          string
		candidateMax  int64
		processMax    int64
		sizeLimit     int
		code          uint16
		entries       int
		diagnostic    string
		wantRejection uint64
	}{
		{name: "exact candidate bytes", candidateMax: retained, processMax: retained * 2, entries: 3},
		{name: "candidate bytes minus one", candidateMax: retained - 1, processMax: retained * 2,
			code: ldap.LDAPResultAdminLimitExceeded, diagnostic: "search candidate budget exceeded"},
		{name: "exact process bytes", candidateMax: retained * 2, processMax: retained, entries: 3},
		{name: "process bytes minus one", candidateMax: retained * 2, processMax: retained - 1,
			code: ldap.LDAPResultAdminLimitExceeded, diagnostic: "process search memory budget exceeded", wantRejection: 1},
		{name: "exact size", candidateMax: retained * 2, processMax: retained * 2, sizeLimit: 3, entries: 3},
		{name: "size minus one", candidateMax: retained * 2, processMax: retained * 2, sizeLimit: 2,
			code: ldap.LDAPResultSizeLimitExceeded, entries: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture.server.config.MaxSearchCandidateBytes = test.candidateMax
			request.SizeLimit = test.sizeLimit
			fixture.server.searchMemoryLimiter = newResourceByteLimiter(test.processMax)
			want, wantErr, owned := fixture.search(t, request, true)
			fixture.server.searchMemoryLimiter = newResourceByteLimiter(test.processMax)
			got, gotErr, borrowed := fixture.search(t, request, false)
			if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || !reflect.DeepEqual(borrowed, owned) {
				t.Fatal("budget boundary changed response, audit, or reservations")
			}
			if borrowed.code != int(test.code) || borrowed.entries != test.entries ||
				borrowed.diagnostic != test.diagnostic || borrowed.rejections != test.wantRejection ||
				(test.code == 0 && gotErr != nil) || (test.code != 0 && !ldap.IsErrorWithCode(gotErr, test.code)) {
				t.Fatalf("unexpected budget result: error=%v code=%d entries=%d diagnostic=%q rejections=%d",
					gotErr, borrowed.code, borrowed.entries, borrowed.diagnostic, borrowed.rejections)
			}
		})
	}
}
