package server

import (
	"bytes"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestCompareDNPrefixHandlerIntegration(t *testing.T) {
	for _, backend := range []string{"bolt", "memory"} {
		t.Run(backend, func(t *testing.T) {
			server, state := newSmallIndexedFixture(t, 0)
			if backend == "memory" {
				memory := storage.NewMemory()
				t.Cleanup(func() { _ = memory.Close() })
				if err := memory.Update(t.Context(), func(writer storage.Writer) error {
					return server.config.Store.View(t.Context(), func(reader storage.Reader) error {
						contexts, err := reader.NamingContexts()
						if err != nil {
							return err
						}
						if err := writer.SetNamingContexts(contexts); err != nil {
							return err
						}
						return reader.ForEachPartition(func(partition string, entry directory.Entry) error {
							return writer.PutIn(partition, entry.WithoutDNIdentity(), false)
						})
					})
				}); err != nil {
					t.Fatal(err)
				}
				var err error
				server, err = New(Config{Store: memory, Schema: server.baseSchema,
					RootDN: smallIndexedRootDN, RootPassword: []byte("secret")})
				if err != nil {
					t.Fatal(err)
				}
				state.runtime = server.runtime.Load()
			}
			state.protocolVersion = 3
			observed := &smallIndexedObservedStore{Store: server.config.Store}
			server.config.Store = observed
			var trace string
			observed.beforeView = func() { trace += "view;" }
			observed.afterView = func() error {
				trace += "return;"
				return nil
			}

			group := defaultProjectionBenchmarkEntry(true) // Existing group1000 fixture.
			members := group.Values("member")
			members[0] = []byte("uid=Alice," + smallIndexedPeopleDN)
			group.ReplaceValues("member", members)
			smallIndexedPut(t, server, state, group, false)
			check := func(label, attribute string, assertion []byte, want ldapwire.ResultCode, controls ...ldapwire.Control) {
				t.Helper()
				cache := state.runtime.compareDNPrefixes
				if cache == nil {
					t.Fatal("runtime did not initialize the prefix cache")
				}
				defer func() { state.runtime.compareDNPrefixes = cache }()
				var oracle []byte
				var oracleTrace string
				// The old handler path is the complete wire oracle; repeat with the
				// same cache across requests and mutations, without inspecting tokens.
				for _, candidate := range []*compareDNPrefixCache{nil, cache, cache} {
					state.runtime.compareDNPrefixes = candidate
					observed.views, observed.updates, trace = 0, 0, ""
					capture := &smallIndexedCapture{onWrite: func() { trace += "wire;" }}
					request := ldapwire.CompareRequest{DN: group.DN, Attribute: attribute, Assertion: assertion}
					message := ldapwire.Message{ID: 17, Request: request, Controls: controls}
					if err := server.handleCompare(t.Context(), capture, state, message, request); err != nil {
						t.Fatalf("%s: %v", label, err)
					}
					reader := bytes.NewReader(capture.Bytes())
					packet, err := ber.ReadPacket(reader)
					if err != nil || reader.Len() != 0 {
						t.Fatalf("%s: BER error=%v, trailing bytes=%d", label, err, reader.Len())
					}
					result, err := parseSyncConsumerLDAPResult(packet, message.ID, ldapwire.ApplicationCompareResponse)
					if err != nil || result.code != uint16(want) {
						t.Fatalf("%s: result=%+v, error=%v, want=%d", label, result, err, want)
					}
					if want == ldapwire.ResultInappropriateMatching && result.diagnosticMessage == "" ||
						want == ldapwire.ResultNoSuchObject && result.matchedDN == "" ||
						want == ldapwire.ResultReferral && len(ldapResultReferrals(packet)) == 0 {
						t.Fatalf("%s: missing diagnostic, matched DN or referrals: %+v", label, result)
					}
					if candidate == nil {
						oracle = bytes.Clone(capture.Bytes())
						oracleTrace = trace
					} else if !bytes.Equal(oracle, capture.Bytes()) || trace != oracleTrace {
						t.Fatalf("%s: wire=%x callbacks=%s, oracle=%x callbacks=%s", label, capture.Bytes(), trace, oracle, oracleTrace)
					}
					if observed.views != 1 || observed.updates != 0 {
						t.Fatalf("%s: views=%d updates=%d callbacks=%s", label, observed.views, observed.updates, trace)
					}
				}
			}
			missing := []byte("uid=absent," + smallIndexedPeopleDN)
			warmedCache := state.runtime.compareDNPrefixes
			if warmedCache == nil {
				t.Fatal("runtime did not initialize the prefix cache")
			}
			// Warm the whole group even when each call extends only one value.
			// Keep this loop on the handler path; run the wire oracle afterward.
			warmRequest := ldapwire.CompareRequest{DN: group.DN, Attribute: "member", Assertion: missing}
			warmMessage := ldapwire.Message{ID: 17, Request: warmRequest}
			for i := range 1001 {
				observed.views, observed.updates, trace = 0, 0, ""
				capture := &smallIndexedCapture{onWrite: func() { trace += "wire;" }}
				if err := server.handleCompare(t.Context(), capture, state, warmMessage, warmRequest); err != nil {
					t.Fatalf("warm call %d: %v", i, err)
				}
				reader := bytes.NewReader(capture.Bytes())
				packet, err := ber.ReadPacket(reader)
				if err != nil || reader.Len() != 0 {
					t.Fatalf("warm call %d: BER error=%v, trailing bytes=%d", i, err, reader.Len())
				}
				result, err := parseSyncConsumerLDAPResult(packet, warmMessage.ID, ldapwire.ApplicationCompareResponse)
				if err != nil || result.code != uint16(ldapwire.ResultCompareFalse) {
					t.Fatalf("warm call %d: result=%+v, error=%v", i, result, err)
				}
				if observed.views != 1 || observed.updates != 0 || trace != "view;return;wire;" {
					t.Fatalf("warm call %d: views=%d updates=%d callbacks=%s", i, observed.views, observed.updates, trace)
				}
			}
			check("first", "member", members[0], ldapwire.ResultCompareTrue)
			check("last", "member", members[len(members)-1], ldapwire.ResultCompareTrue)
			check("missing", "member", missing, ldapwire.ResultCompareFalse)
			changed := group.Clone()
			values := changed.Values("member")
			values[900] = missing
			changed.ReplaceValues("member", values)
			smallIndexedPut(t, server, state, changed, true)
			check("updated old member at 900", "member", members[900], ldapwire.ResultCompareFalse)
			check("updated new member", "member", missing, ldapwire.ResultCompareTrue)
			dn, err := state.runtime.schema.NormalizeDN(group.DN)
			if err != nil {
				t.Fatal(err)
			}
			if err := observed.Update(t.Context(), func(writer storage.Writer) error {
				return writerForDatabase(writer, *databaseForNormalizedDN(state.runtime, dn)).Delete(dn)
			}); err != nil {
				t.Fatal(err)
			}
			check("deleted", "member", missing, ldapwire.ResultNoSuchObject)
			smallIndexedPut(t, server, state, group, false)
			check("recreated old member", "member", missing, ldapwire.ResultCompareFalse)
			check("recreated member at 900", "member", members[900], ldapwire.ResultCompareTrue)

			for _, badIndex := range []int{1, 0} {
				smallIndexedPut(t, server, state, group, true)
				check("warm before malformed value", "member", missing, ldapwire.ResultCompareFalse)
				changed = group.Clone()
				values = changed.Values("member")
				values[badIndex] = []byte("not-a-dn")
				changed.ReplaceValues("member", values)
				smallIndexedPut(t, server, state, changed, true)
				want := ldapwire.ResultCompareTrue
				if badIndex == 0 {
					want = ldapwire.ResultInappropriateMatching
				}
				check("malformed before/after match", "member", members[0], want)
				check("malformed reached on miss", "member", missing, ldapwire.ResultInappropriateMatching)
			}
			filter, err := ldap.CompileFilter("(cn=absent)")
			if err != nil {
				t.Fatal(err)
			}
			assertion := ldapwire.Control{OID: assertionControlOID, Critical: true, HasValue: true, Value: filter.Bytes()}
			state.boundDN = ""
			check("ACL before assertion and malformed member", "member", missing, ldapwire.ResultInsufficientAccessRights, assertion)
			state.boundDN = smallIndexedRootDN
			check("assertion before malformed member", "member", missing, ldapwire.ResultAssertionFailed, assertion)
			changed.ReplaceValues("objectClass", stringValues("referral", "extensibleObject"))
			changed.ReplaceValues("ref", stringValues("ldap://remote.example/dc=remote,dc=example"))
			smallIndexedPut(t, server, state, changed, true)
			check("referral before assertion and member", "member", missing, ldapwire.ResultReferral, assertion)
			manage := ldapwire.Control{OID: manageDsaITControlOID, Critical: true}
			state.runtime.access = defaultProjectionPolicy(t, defaultProjectionRules(t,
				"to attrs=member by * none", "to * by * read"), nil)
			state.boundDN = ""
			check("referral before denied compare", "member", missing, ldapwire.ResultReferral, assertion)
			check("managed referral ACL before assertion", "member", missing, ldapwire.ResultInsufficientAccessRights, manage, assertion)
			state.boundDN = smallIndexedRootDN
			check("managed referral assertion", "member", missing, ldapwire.ResultAssertionFailed, manage, assertion)
			check("managed referral malformed member", "member", missing, ldapwire.ResultInappropriateMatching, manage)

			smallIndexedPut(t, server, state, group, true)
			lower := []byte("uid=alice," + smallIndexedPeopleDN)
			check("warm schema", "member", lower, ldapwire.ResultCompareTrue)
			uid, _ := state.runtime.schema.AttributeType("uid")
			for _, equality := range []string{"caseExactMatch", "caseIgnoreMatch", "caseExactMatch"} {
				uid.Equality = equality
				if err := state.runtime.schema.UpsertAttributeType(uid); err != nil {
					t.Fatal(err)
				}
				want := ldapwire.ResultCompareFalse
				if equality == "caseIgnoreMatch" {
					want = ldapwire.ResultCompareTrue
				}
				check(equality, "member", lower, want)
			}
			if state.runtime.compareDNPrefixes != warmedCache {
				t.Fatal("store mutations or schema changes replaced the warmed cache")
			}
			previous := state.runtime
			if err := observed.View(t.Context(), func(reader storage.Reader) error {
				var err error
				state.runtime, err = server.buildRuntimeState(reader)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if state.runtime.compareDNPrefixes == previous.compareDNPrefixes || state.runtime.schema == previous.schema {
				t.Fatal("rebuilt runtime retained the previous cache or schema")
			}
			server.activateRuntime(state.runtime)
			check("reloaded schema", "member", lower, ldapwire.ResultCompareTrue)

			if err := state.runtime.schema.ParseAndRegisterAttributeType("( 1.2.3.991 NAME 'prefixChild' SUP member )"); err != nil {
				t.Fatal(err)
			}
			for _, fallback := range []struct {
				name, stored, requested string
				values                  [][]byte
			}{
				{"small", "member", "member", members[:10]},
				{"uid", "uid", "uid", stringValues("Alice")},
				{"unique UID", "uniqueMember", "uniqueMember", stringValues(string(members[0]) + "#'0101'B")},
				{"options", "member;lang-en", "member", members},
				{"requested options", "member;lang-en", "member;lang-en", members},
				{"SUP", "prefixChild", "member", members},
			} {
				changed = group.Clone()
				changed.ReplaceValues("member", nil)
				changed.ReplaceValues(fallback.stored, fallback.values)
				smallIndexedPut(t, server, state, changed, true)
				check(fallback.name, fallback.requested, fallback.values[0], ldapwire.ResultCompareTrue)
				check(fallback.name+" missing", fallback.requested, missing, ldapwire.ResultCompareFalse)
			}
		})
	}
}
