package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func bindRouteRequest(dn, password string) (ldapwire.Message, ldapwire.BindRequest) {
	request := ldapwire.BindRequest{Version: 3, Name: dn, Authentication: ldapwire.Authentication{Simple: []byte(password)}}
	return ldapwire.Message{ID: 1, Request: request}, request
}

func TestSimpleBindRouteReuseEligibility(t *testing.T) {
	for _, mode := range []string{
		"local", "memory", "custom-store", "custom-normalizer", "custom-parser", "wrapped-custom-registry",
		"other-schema", "other-candidate", "monitor", "frontend-normalizer", "frontend-overlay",
		"ppolicy", "lastbind", "TOTP", "radius", "relay", "rewrite", "translucent", "remoteauth", "pbind",
		"loaded-overlay", "collect", "hidden", "subordinate", "shadow", "retcode", "old-runtime", "unpublished",
		"SASL", "SASL-session", "v2", "empty-DN", "empty-password", "controls", "empty-controls",
	} {
		t.Run(mode, func(t *testing.T) {
			backend := "bolt"
			if mode == "memory" {
				backend = "memory"
			}
			instance, database, _ := newReadOnlyPasswordBindFixture(t, backend, stringValues("secret"), nil)
			runtime := instance.runtime.Load()
			state := &connectionState{runtime: runtime}
			message, request := bindRouteRequest(aliceDN, "secret")
			calls := 0
			custom := &bindRouteNormalizer{Registry: runtime.schema, onParse: func(string) error { calls++; return nil }}
			switch mode {
			case "custom-store":
				instance.config.Store = &bindDatabaseSnapshotProbeStore{Store: instance.config.Store, beforeView: func(int) error { calls++; return nil }}
			case "custom-normalizer":
				database.dnNormalizer = &bindDatabaseSnapshotNormalizer{Registry: runtime.schema, before: func(string, []byte) { calls++ }}
			case "custom-parser":
				database.dnNormalizer = custom
			case "wrapped-custom-registry":
				database.dnNormalizer = &databaseEqualityIndexNormalizer{registry: &recordingDNParserRegistry{Registry: runtime.schema}}
			case "other-schema":
				database.dnNormalizer = runtime.schema.Clone()
			case "other-candidate":
				runtime.databases = append(runtime.databases, runtimeDatabase{name: "mdb", partition: "other", dnNormalizer: custom})
			case "monitor":
				database.name = "monitor"
			case "frontend-normalizer":
				runtime.databases = append(runtime.databases, runtimeDatabase{name: "frontend", dnNormalizer: custom})
			case "frontend-overlay":
				runtime.databases = append(runtime.databases, runtimeDatabase{name: "frontend", totpPasswords: []totpPasswordRuntimeConfiguration{{}}})
			case "ppolicy":
				database.ppolicy = &passwordPolicyRuntimeConfiguration{}
			case "lastbind":
				database.lastBind = true
			case "TOTP":
				database.totpPasswords = []totpPasswordRuntimeConfiguration{{}}
			case "radius":
				runtime.externalPasswords.radiusEnabled = true
			case "relay":
				database.relay = &relayRuntimeConfiguration{}
			case "rewrite":
				database.rwm = &rwmRuntimeConfiguration{}
			case "translucent":
				database.translucent = &translucentRuntimeConfiguration{}
			case "remoteauth":
				database.remoteAuth = &remoteAuthRuntimeConfiguration{}
			case "pbind":
				database.pbind = &pbindRuntimeConfiguration{}
			case "loaded-overlay":
				database.monitorOverlays = []monitorOverlay{{name: "future-overlay"}}
			case "collect":
				database.collect = &collectRuntimeConfiguration{}
			case "hidden":
				database.hidden = true
			case "subordinate":
				database.subordinate = true
			case "shadow":
				database.shadow = true
			case "retcode":
				runtime.features.retcode = true
			case "old-runtime":
				instance.runtime.Store(new(*runtime))
			case "unpublished":
				runtime.revision = 0
			case "SASL":
				request.Authentication.IsSASL = true
			case "SASL-session":
				state.saslSession = &serverSASLSession{}
			case "v2":
				request.Version = 2
			case "empty-DN":
				request.Name = ""
			case "empty-password":
				request.Authentication.Simple = nil
			case "controls":
				message.Controls = []ldapwire.Control{{OID: "1.2.3.4"}}
			case "empty-controls":
				message.ControlsPresent = true
			}
			if got := instance.canReuseSimpleBindRoute(state, message, request); got != (mode == "local") || calls != 0 {
				t.Fatalf("eligible=%t callbacks=%d", got, calls)
			}
		})
	}
}

func TestSimpleBindRouteReuseIdentityAndStringOracle(t *testing.T) {
	instance, database, alice := newReadOnlyPasswordBindFixture(t, "bolt", stringValues("secret"), nil)
	runtime := instance.runtime.Load()
	if err := runtime.schema.ParseAndRegisterAttributeType("( 1.2.3.4567 NAME ( 'bindRouteExact' 'bindRouteAlias' ) EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"); err != nil {
		t.Fatal(err)
	}
	passwords := map[string]string{alice.Key(): "secret"}
	if err := instance.config.Store.Update(t.Context(), func(writer storage.Writer) error {
		tx := writerForDatabase(writer, *database)
		template, err := tx.Get(alice)
		if err != nil {
			return err
		}
		for _, name := range []string{"Alice", "alice"} {
			entry := template.Clone().WithoutDNIdentity()
			entry.DN = "bindRouteExact=" + name + "+cn=Team,dc=example,dc=com"
			entry.ReplaceValues("cn", stringValues("Team"))
			entry.ReplaceValues("bindRouteExact", stringValues(name))
			entry.ReplaceValues("userPassword", stringValues(name+"-secret"))
			dn, err := parseRuntimeConnectionDN(runtime, entry.DN)
			if err != nil {
				return err
			}
			passwords[dn.Key()] = name + "-secret"
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(passwords) != 3 {
		t.Fatal("caseExact fixtures must have distinct identities")
	}
	for _, raw := range []string{
		aliceDN, "UID=ALICE,DC=example,DC=com", "0.9.2342.19200300.100.1.1=alice,dc=example,dc=com",
		"bindRouteAlias=Alice+cn=Team,dc=example,dc=com", "cn=Team+1.2.3.4567=Alice,dc=example,dc=com",
		"bindRouteExact=alice+cn=Team,dc=example,dc=com", `cn=Smith\, Alice,dc=example,dc=com`,
		"cn=" + string(bytes.Repeat([]byte("x"), 1100)) + ",dc=example,dc=com",
	} {
		t.Run(raw, func(t *testing.T) {
			message, request := bindRouteRequest(raw, "secret")
			if !instance.canReuseSimpleBindRoute(&connectionState{runtime: runtime}, message, request) {
				t.Fatal("fixture must opt in")
			}
			dn, err := parseRuntimeConnectionDN(runtime, raw)
			if err != nil {
				t.Fatal(err)
			}
			selected := databaseForDN(runtime, dn)
			first, err := normalizePasswordPolicyDN(runtime, nil, nil, dn.String())
			if err != nil || databaseForDN(runtime, first) != selected || selected != database {
				t.Fatalf("string routing differs: %v", err)
			}
			second, err := normalizePasswordPolicyDN(runtime, selected, nil, dn.String())
			if err != nil || second.Key() != dn.Key() || second.String() != dn.String() {
				t.Fatalf("normalization is not equivalent: %v", err)
			}
			for _, supplied := range []string{"secret", "Alice-secret", "alice-secret", "wrong"} {
				want, wantErr := instance.authenticatePasswordBind(t.Context(), runtime, dn.String(), []byte(supplied), false)
				got, gotErr := instance.authenticateSimpleBindRoute(t.Context(), runtime, selected, dn, []byte(supplied), false, true)
				if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotErr, wantErr) || got.authenticated != (passwords[dn.Key()] == supplied) {
					t.Fatalf("route=%#v/%v string=%#v/%v", got, gotErr, want, wantErr)
				}
			}
		})
	}
}

type bindRouteObservation struct {
	wire                                      []byte
	boundDN, mechanism, credentialDN, limited string
	credentials                               []byte
	version                                   int
	err                                       error
}

// An equivalent replacement disables only route reuse; handleBind retains the
// original runtime for every check and executes the original string entry point.
func observeBindRoute(t *testing.T, instance *Server, runtime *runtimeState, message ldapwire.Message, request ldapwire.BindRequest, reference bool) bindRouteObservation {
	t.Helper()
	current := instance.runtime.Load()
	if reference {
		instance.runtime.Store(new(*current))
	}
	defer instance.runtime.Store(current)
	state := &connectionState{runtime: runtime, protocolVersion: 3, boundDN: "uid=previous,dc=example,dc=com",
		authMechanism: "SIMPLE", bindCredentialDN: "previous", bindCredentials: []byte("previous"), passwordPolicyRestrictedDN: "previous"}
	capture := &smallIndexedCapture{}
	err := instance.handleBind(t.Context(), capture, state, message, request)
	return bindRouteObservation{bytes.Clone(capture.Bytes()), state.boundDN, state.authMechanism,
		state.bindCredentialDN, state.passwordPolicyRestrictedDN, bytes.Clone(state.bindCredentials), state.protocolVersion, err}
}

func mustBindRoutePacket(t *testing.T, wire []byte) *ber.Packet {
	t.Helper()
	packet, err := ber.DecodePacketErr(wire)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestSimpleBindRouteReuseHandlerParity(t *testing.T) {
	for _, mode := range []string{"success", "wrong", "missing", "root", "root-wrong", "root-outside", "security", "root-security", "restricted", "invalid-DN", "undefined-attribute", "version", "critical-control", "anonymous", "empty-password", "config"} {
		t.Run(mode, func(t *testing.T) {
			instance, database, _ := newReadOnlyPasswordBindFixture(t, "bolt", [][]byte{bindRouteSSHA(t)}, nil)
			runtime := instance.runtime.Load()
			root, err := parseRuntimeConnectionDN(runtime, "cn=admin,dc=example,dc=com")
			if err != nil {
				t.Fatal(err)
			}
			database.rootDN, database.rootPassword, database.rootPasswordSet = &root, []byte("root-secret"), true
			clockCalls := 0
			instance.clock = func() time.Time { clockCalls++; return time.Now() }
			message, request := bindRouteRequest(aliceDN, "secret")
			wantCode := ldapwire.ResultSuccess
			switch mode {
			case "wrong":
				request.Authentication.Simple, wantCode = []byte("wrong"), ldapwire.ResultInvalidCredentials
			case "missing":
				request.Name, wantCode = "uid=missing,dc=example,dc=com", ldapwire.ResultInvalidCredentials
			case "root", "root-wrong", "root-security":
				request.Name, request.Authentication.Simple = root.String(), []byte("root-secret")
				if mode == "root-wrong" {
					request.Authentication.Simple, wantCode = []byte("wrong"), ldapwire.ResultInvalidCredentials
				}
			case "root-outside":
				request.Name, request.Authentication.Simple, wantCode = "cn=admin,dc=outside", []byte("root-secret"), ldapwire.ResultInvalidCredentials
			case "restricted":
				database.restrictions, wantCode = restrictBind, ldapwire.ResultUnwillingToPerform
			case "invalid-DN":
				request.Name, wantCode = "cn=broken,", ldapwire.ResultInvalidDNSyntax
			case "undefined-attribute":
				request.Name, wantCode = "undefinedBindRoute=alice,dc=example,dc=com", ldapwire.ResultInvalidDNSyntax
			case "version":
				request.Version, wantCode = 4, ldapwire.ResultProtocolError
			case "critical-control":
				message.Controls, wantCode = []ldapwire.Control{{OID: "1.2.3.4", Critical: true}}, ldapwire.ResultUnavailableCriticalExtension
			case "anonymous":
				request.Name, request.Authentication.Simple = "", nil
			case "empty-password":
				request.Authentication.Simple, wantCode = nil, ldapwire.ResultUnwillingToPerform
			case "config":
				request.Name, wantCode = "cn=config", ldapwire.ResultInvalidCredentials
			}
			if mode == "security" || mode == "root-security" {
				database.security.simpleBind, wantCode = 1, ldapwire.ResultConfidentialityRequired
			}
			// DN, protocol and control errors must still precede security errors.
			if mode == "invalid-DN" || mode == "undefined-attribute" || mode == "version" || mode == "critical-control" {
				database.security.simpleBind = 1
			}
			message.Request = request
			want := observeBindRoute(t, instance, runtime, message, request, true)
			got := observeBindRoute(t, instance, runtime, message, request, false)
			if !reflect.DeepEqual(got, want) || got.err != nil {
				t.Fatalf("handler differs: route=%+v string=%+v", got, want)
			}
			assertRawLDAPEnvelope(t, mustBindRoutePacket(t, got.wire), message.ID, ldapwire.ApplicationBindResponse, int64(wantCode))
			if (mode == "root" || mode == "root-wrong" || mode == "root-security") && clockCalls != 0 {
				t.Fatal("root authentication reached the ordinary entry/storage path")
			}
		})
	}
}

func TestSimpleBindRouteReuseConfigurationAndReload(t *testing.T) {
	instance, _, _ := newReadOnlyPasswordBindFixture(t, "bolt", stringValues("secret"), nil)
	runtime := instance.runtime.Load()
	runtime.databases = append(runtime.databases, runtimeDatabase{
		name: "config", partition: configurationStoragePartition, suffixes: []directory.DN{configurationSuffix},
		rootDN: new(configurationSuffix), rootPassword: []byte("old-root"), rootPasswordSet: true,
	})
	message, request := bindRouteRequest("cn=config", "old-root")
	dn, err := parseRuntimeConnectionDN(runtime, request.Name)
	if err != nil {
		t.Fatal(err)
	}
	database := databaseForDN(runtime, dn)
	if database == nil || !isConfigDatabase(*database) || databaseUsesRuntimeDNIdentity(*database, runtime.schema) {
		t.Fatal("configuration route must be ineligible for the resolved entry point")
	}
	before := observeBindRoute(t, instance, runtime, message, request, false)
	oracle := observeBindRoute(t, instance, runtime, message, request, true)
	if !reflect.DeepEqual(before, oracle) || before.err != nil || before.boundDN != "cn=config" {
		t.Fatalf("config Bind differs: route=%+v string=%+v", before, oracle)
	}
	next := new(*runtime)
	next.schema = runtime.schema.Clone()
	next.databases = slices.Clone(runtime.databases)
	for index := range next.databases {
		candidate := &next.databases[index]
		if isConfigDatabase(*candidate) {
			candidate.rootPassword = []byte("new-root")
		} else if databaseUsesLocalContentStorage(*candidate) {
			candidate.dnNormalizer = &databaseEqualityIndexNormalizer{registry: next.schema, config: candidate.equalityIndexes}
		}
	}
	instance.runtime.Store(next)
	localMessage, localRequest := bindRouteRequest(aliceDN, "secret")
	if instance.canReuseSimpleBindRoute(&connectionState{runtime: runtime}, localMessage, localRequest) ||
		!instance.canReuseSimpleBindRoute(&connectionState{runtime: next}, localMessage, localRequest) {
		t.Fatal("reuse must follow the published runtime and its schema")
	}
	retained := observeBindRoute(t, instance, runtime, message, request, false)
	if !reflect.DeepEqual(retained, before) {
		t.Fatal("reload changed the retained operation's root semantics")
	}
	for _, password := range []string{"old-root", "new-root"} {
		message, request = bindRouteRequest("cn=config", password)
		got := observeBindRoute(t, instance, next, message, request, false)
		if got.err != nil || (got.boundDN != "") != (password == "new-root") {
			t.Fatalf("replacement root Bind(%q)=%+v", password, got)
		}
	}
}

type bindRouteNormalizer struct {
	*schema.Registry
	onParse func(string) error
}

func (normalizer *bindRouteNormalizer) ParseDNIdentity(raw string) (directory.DN, error) {
	if err := normalizer.onParse(raw); err != nil {
		return directory.DN{}, err
	}
	return normalizer.Registry.NormalizeDN(raw)
}

func TestSimpleBindRouteReuseFallbackCallbackOrder(t *testing.T) {
	for _, failAt := range []int{0, 1, 3, 8} {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			instance, database, _ := newReadOnlyPasswordBindFixture(t, "bolt", stringValues("secret"), nil)
			runtime := instance.runtime.Load()
			var trace []string
			calls := 0
			failure := errors.New("normalizer failure")
			database.dnNormalizer = &bindRouteNormalizer{Registry: runtime.schema, onParse: func(raw string) error {
				calls++
				trace = append(trace, "normalize:"+raw)
				if calls == failAt {
					return failure
				}
				return nil
			}}
			instance.config.Store = &bindRouteTraceStore{Store: instance.config.Store, trace: &trace}
			message, request := bindRouteRequest(aliceDN, "secret")
			want := observeBindRoute(t, instance, runtime, message, request, true)
			wantTrace := slices.Clone(trace)
			trace, calls = nil, 0
			got := observeBindRoute(t, instance, runtime, message, request, false)
			if !reflect.DeepEqual(got, want) || !slices.Equal(trace, wantTrace) || len(trace) == 0 {
				t.Fatalf("callback order differs: %v / %v; route=%+v string=%+v", trace, wantTrace, got, want)
			}
			if failAt == 0 && (!slices.Contains(trace, "acl-context") || !slices.Contains(trace, "get:"+aliceDN)) {
				t.Fatal("fixture must exercise reader and ACL context callbacks")
			}
		})
	}
}

func TestSimpleBindRouteReuseProofPrecedesNormalizerCallback(t *testing.T) {
	instance, database, _ := newReadOnlyPasswordBindFixture(t, "bolt", stringValues("secret"), nil)
	runtime := instance.runtime.Load()
	standard := database.dnNormalizer
	calls := 0
	database.dnNormalizer = &bindRouteNormalizer{Registry: runtime.schema, onParse: func(string) error {
		calls++
		database.dnNormalizer = standard
		return nil
	}}
	state := &connectionState{runtime: runtime}
	message, request := bindRouteRequest(aliceDN, "secret")
	proof := instance.canReuseSimpleBindRoute(state, message, request)
	if proof || calls != 0 {
		t.Fatal("proof must decline custom parsing without invoking it")
	}
	dn, err := parseRuntimeConnectionDN(runtime, request.Name)
	if err != nil || calls == 0 || !instance.canReuseSimpleBindRoute(state, message, request) {
		t.Fatalf("fixture must become superficially eligible after its callback: %v", err)
	}
	got, err := instance.authenticateSimpleBindRoute(t.Context(), runtime, databaseForDN(runtime, dn), dn, request.Authentication.Simple, false, proof)
	if err != nil || !got.authenticated {
		t.Fatalf("fallback authentication=%#v/%v", got, err)
	}
}

type bindRouteTraceStore struct {
	storage.Store
	trace *[]string
}

func (store *bindRouteTraceStore) View(ctx context.Context, fn func(storage.Reader) error) error {
	*store.trace = append(*store.trace, "view:start")
	err := store.Store.View(ctx, func(reader storage.Reader) error {
		return fn(bindRouteTraceReader{Reader: reader, trace: store.trace})
	})
	*store.trace = append(*store.trace, "view:end")
	return err
}

type bindRouteTraceReader struct {
	storage.Reader
	trace *[]string
}

func (reader bindRouteTraceReader) GetIn(partition string, dn directory.DN) (directory.Entry, error) {
	*reader.trace = append(*reader.trace, "get:"+dn.String())
	return reader.Reader.GetIn(partition, dn)
}

func (reader bindRouteTraceReader) AccessContext() any {
	*reader.trace = append(*reader.trace, "acl-context")
	if provider, ok := reader.Reader.(interface{ AccessContext() any }); ok {
		return provider.AccessContext()
	}
	return nil
}

func TestSimpleBindRouteReuseFinalSnapshot(t *testing.T) {
	for _, change := range []string{"password", "delete", "subentry", "alias", "referral"} {
		for _, supplied := range []string{"secret", "replacement"} {
			t.Run(change+"/"+supplied, func(t *testing.T) {
				instance, database, dn := newReadOnlyPasswordBindFixture(t, "bolt", stringValues("secret"), nil)
				runtime := instance.runtime.Load()
				message, request := bindRouteRequest(aliceDN, supplied)
				if !instance.canReuseSimpleBindRoute(&connectionState{runtime: runtime}, message, request) {
					t.Fatal("fixture must opt in before authentication")
				}
				probe := &readOnlyBindProbeStore{Store: instance.config.Store}
				probe.beforeView = func(view int) error {
					if view != 2 {
						return nil
					}
					return probe.Store.Update(t.Context(), func(writer storage.Writer) error {
						tx := writerForDatabase(writer, *database)
						if change == "delete" {
							return tx.Delete(dn)
						}
						entry, err := tx.Get(dn)
						if err != nil {
							return err
						}
						if change == "password" {
							entry.ReplaceValues("userPassword", stringValues("replacement"))
						} else {
							entry.ReplaceValues("objectClass", stringValues(change))
						}
						return tx.Put(entry, true)
					})
				}
				// The existing clock seam runs after both entry points join. Install
				// the probe there so the actual handler takes the eligible route.
				instance.clock = func() time.Time { instance.config.Store = probe; return time.Now() }
				got := observeBindRoute(t, instance, runtime, message, request, false)
				code := ldapwire.ResultInvalidCredentials
				if change == "password" && supplied == "replacement" {
					code = ldapwire.ResultSuccess
				}
				if got.err != nil || probe.views != 2 || probe.updates != 0 ||
					!bytes.Equal(got.wire, ldapwire.EncodeBindResponse(1, ldapwire.Result{Code: code}, nil)) {
					t.Fatalf("snapshot result=%+v views=%d updates=%d", got, probe.views, probe.updates)
				}
			})
		}
	}
}

func TestSimpleBindRouteReuseErrorsAndCancellation(t *testing.T) {
	for _, test := range []struct {
		name                string
		view                int
		after, cancel, fail bool
	}{
		{"preverify-open", 1, false, false, true},
		{"preverify-close", 1, true, false, true},
		{"final-open", 2, false, false, true},
		{"final-close", 2, true, false, true},
		{"cancel-after-preverify", 1, true, true, false},
		{"cancel-after-final", 2, true, true, false},
		{"final-error-before-cancel", 2, true, true, true},
	} {
		for _, reference := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/string=%t", test.name, reference), func(t *testing.T) {
				instance, _, _ := newReadOnlyPasswordBindFixture(t, "bolt", stringValues("secret"), nil)
				runtime := instance.runtime.Load()
				state := &connectionState{runtime: runtime, boundDN: aliceDN, bindCredentials: []byte("old")}
				message, request := bindRouteRequest(aliceDN, "secret")
				if !instance.canReuseSimpleBindRoute(state, message, request) {
					t.Fatal("fixture must opt in before the clock callback")
				}
				if reference {
					instance.runtime.Store(new(*runtime))
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				failure := errors.New("storage failure")
				probe := &readOnlyBindProbeStore{Store: instance.config.Store}
				hook := func(view int) error {
					if view == test.view {
						if test.cancel {
							cancel()
						}
						if test.fail {
							return failure
						}
					}
					return nil
				}
				if test.after {
					probe.afterView = hook
				} else {
					probe.beforeView = hook
				}
				instance.clock = func() time.Time { instance.config.Store = probe; return time.Now() }
				capture := &smallIndexedCapture{}
				err := instance.handleBind(ctx, capture, state, message, request)
				want := error(context.Canceled)
				if test.fail {
					want = failure
				}
				if !errors.Is(err, want) || state.boundDN != "" || len(state.bindCredentials) != 0 || capture.Len() != 0 || probe.updates != 0 {
					t.Fatalf("error=%v state=%q views=%d updates=%d wire=%x", err, state.boundDN, probe.views, probe.updates, capture.Bytes())
				}
			})
		}
	}
}

func TestSimpleBindRouteReuseACLAndPolicyFallback(t *testing.T) {
	for _, policy := range []bool{false, true} {
		instance, database, _ := newReadOnlyPasswordBindFixture(t, "bolt", stringValues("denied", "secret", "tail"), []string{
			`{0}to attrs=userPassword val.exact="denied" by * none`,
			`{1}to attrs=userPassword by anonymous auth by * none`,
		})
		runtime := instance.runtime.Load()
		if policy {
			database.ppolicy = &passwordPolicyRuntimeConfiguration{}
		}
		for _, password := range []string{"denied", "secret", "tail", "wrong"} {
			message, request := bindRouteRequest(aliceDN, password)
			if got := instance.canReuseSimpleBindRoute(&connectionState{runtime: runtime}, message, request); got == policy {
				t.Fatalf("ppolicy=%t eligibility=%t", policy, got)
			}
			want := observeBindRoute(t, instance, runtime, message, request, true)
			got := observeBindRoute(t, instance, runtime, message, request, false)
			code := ldapwire.ResultInvalidCredentials
			if password == "secret" || password == "tail" {
				code = ldapwire.ResultSuccess
			}
			if !reflect.DeepEqual(got, want) || got.err != nil {
				t.Fatalf("ACL/policy differs: route=%+v string=%+v", got, want)
			}
			assertRawLDAPEnvelope(t, mustBindRoutePacket(t, got.wire), message.ID, ldapwire.ApplicationBindResponse, int64(code))
		}
	}
}

func bindRouteSSHA(t testing.TB) []byte {
	t.Helper()
	stored, err := auth.HashPassword([]byte("secret"), auth.OpenLDAPDefaultHashScheme, bytes.NewReader([]byte{1, 2, 3, 4}))
	if err != nil {
		t.Fatal(err)
	}
	return stored
}
