package server

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

// Both cases execute the real handler, including DN parsing, security checks,
// authentication, connection-state replacement and response encoding. The
// string control retains an equivalent old runtime to decline only route reuse;
// it adds no Store/Reader wrapper and performs the same two Bolt Views.
func BenchmarkHandleBindRouteReuse(b *testing.B) {
	for _, distribution := range []string{"hot", "rotate256"} {
		for _, supplied := range []string{"secret", "wrong"} {
			for _, route := range []string{"reuse", "string"} {
				b.Run(distribution+"/"+supplied+"/"+route, func(b *testing.B) {
					instance, database, dn := newReadOnlyPasswordBindFixture(b, "bolt", [][]byte{bindRouteSSHA(b)}, nil)
					runtime := instance.runtime.Load()
					count := 1
					if distribution == "rotate256" {
						count = 256
					}
					requests := make([]ldapwire.BindRequest, count)
					messages := make([]ldapwire.Message, count)
					if err := instance.config.Store.Update(b.Context(), func(writer storage.Writer) error {
						tx := writerForDatabase(writer, *database)
						template, err := tx.Get(dn)
						if err != nil {
							return err
						}
						for index := range count {
							uid := fmt.Sprintf("bind-route-%03d", index)
							entry := template.Clone()
							entry.DN = "uid=" + uid + ",dc=example,dc=com"
							entry.ReplaceValues("uid", stringValues(uid))
							if err := tx.Put(entry.WithoutDNIdentity(), false); err != nil {
								return err
							}
							messages[index], requests[index] = bindRouteRequest(entry.DN, supplied)
						}
						return nil
					}); err != nil {
						b.Fatal(err)
					}
					state := &connectionState{runtime: runtime, protocolVersion: 3}
					if !instance.canReuseSimpleBindRoute(state, messages[0], requests[0]) {
						b.Fatal("fixture must initially qualify for reuse")
					}
					if route == "string" {
						instance.runtime.Store(new(*runtime))
					}
					if instance.canReuseSimpleBindRoute(state, messages[0], requests[0]) != (route == "reuse") {
						b.Fatal("incorrect route selected")
					}
					code := ldapwire.ResultInvalidCredentials
					if supplied == "secret" {
						code = ldapwire.ResultSuccess
					}
					expected := ldapwire.EncodeBindResponse(1, ldapwire.Result{Code: code}, nil)
					capture := &smallIndexedCapture{}
					ctx := b.Context()
					// Warm storage and validate every request outside b.Loop. The
					// rotating set exceeds both bounded DN caches (128 entries).
					for index := range count {
						capture.Reset()
						if err := instance.handleBind(ctx, capture, state, messages[index], requests[index]); err != nil || !bytes.Equal(capture.Bytes(), expected) {
							b.Fatalf("warm handler response: %v / %x", err, capture.Bytes())
						}
					}
					index := 0
					b.ReportAllocs()
					for b.Loop() {
						capture.Reset()
						if err := instance.handleBind(ctx, capture, state, messages[index], requests[index]); err != nil {
							b.Fatal(err)
						}
						index = (index + 1) % count
					}
					if !bytes.Equal(capture.Bytes(), expected) || (state.boundDN != "") != (supplied == "secret") {
						b.Fatal("final handler response or identity differs")
					}
				})
			}
		}
	}
}
