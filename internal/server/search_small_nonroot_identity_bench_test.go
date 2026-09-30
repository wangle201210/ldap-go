package server

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

// This is a caller benchmark: one local Bolt entry, the real base-search
// handlers and response encoder, with no sockets or large directory setup.
func BenchmarkSmallNonRootBaseIdentity(b *testing.B) {
	for _, policy := range []string{"default", "explicit"} {
		for _, spelling := range []string{"same", "alias-case"} {
			for _, mode := range []string{"small", "general", "wrapper"} {
				b.Run(policy+"/"+spelling+"/"+mode, func(b *testing.B) {
					server, state := newSmallIndexedFixture(b, 1)
					state.boundDN, state.protocolVersion = smallNonRootReaderDN, 3
					state.runtime.access = acl.DefaultPolicy()
					if policy == "explicit" {
						state.runtime.access = defaultProjectionPolicy(b, defaultProjectionRules(b,
							`{0}to attrs=userPassword by * none`,
							`{1}to dn.subtree="ou=people,dc=example,dc=com" by users read by * none`,
							`{2}to * by * none`), nil)
					}
					base := "uid=person-00000," + smallIndexedPeopleDN
					if spelling == "alias-case" {
						base = strings.ToUpper(strings.Replace(base, "uid=", "userid=", 1))
					}
					message := smallNonRootIdentityMessage(base)
					request := message.Request.(ldapwire.SearchRequest)
					request.Attributes = []string{"uid", "cn", "sn", "jpegPhoto"}
					message.Request = request
					prelude, database := smallIndexedTestPrelude(server, state, message)
					capture := &smallIndexedCapture{}
					ctx := b.Context()
					// Prove this fixture actually reaches the optimized branch and
					// retains general-handler output before starting the timer.
					if handled, err := server.trySmallNonRootSearch(ctx, capture, state, message, request, prelude.base, database); !handled || err != nil {
						b.Fatalf("base fast path: handled=%t err=%v", handled, err)
					}
					want := bytes.Clone(capture.Bytes())
					capture.Reset()
					if err := server.handleUncachedSearch(ctx, capture, state, message, request, prelude); err != nil || !bytes.Equal(want, capture.Bytes()) {
						b.Fatalf("general baseline: err=%v equal=%t", err, bytes.Equal(want, capture.Bytes()))
					}
					b.ReportAllocs()
					for b.Loop() {
						capture.Reset()
						var err error
						switch mode {
						case "small":
							var handled bool
							handled, err = server.trySmallNonRootSearch(ctx, capture, state, message, request, prelude.base, database)
							if !handled {
								b.Fatal("base search declined the fast path")
							}
						case "general":
							err = server.handleUncachedSearch(ctx, capture, state, message, request, prelude)
						case "wrapper":
							err = server.handleSearch(ctx, capture, state, message, request)
						}
						if err != nil {
							b.Fatal(err)
						}
					}
					if !bytes.Equal(want, capture.Bytes()) || server.searchMemoryLimiter.active.Load() != 0 ||
						len(state.runtime.searchResults.entries) != 0 || len(state.runtime.searchBases.entries) != 0 {
						b.Fatal("benchmark changed the response, retained memory, or cached a nonroot result")
					}
				})
			}
		}
	}
}
