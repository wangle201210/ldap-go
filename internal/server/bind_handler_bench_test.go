package server

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

// Keep this benchmark independent of route-specific helpers so the same source
// measures the real handleBind implementation in both historical and current builds.
func BenchmarkHandleSimpleBind(b *testing.B) {
	for _, distribution := range []string{"hot", "rotate256"} {
		for _, supplied := range []struct {
			name, password string
			code           ldapwire.ResultCode
		}{
			{"correct", "secret", ldapwire.ResultSuccess},
			{"wrong", "wrong", ldapwire.ResultInvalidCredentials},
		} {
			b.Run(distribution+"/"+supplied.name, func(b *testing.B) {
				stored, err := auth.HashPassword([]byte("secret"), auth.OpenLDAPDefaultHashScheme, bytes.NewReader([]byte{1, 2, 3, 4}))
				if err != nil {
					b.Fatal(err)
				}
				instance, database, dn := newReadOnlyPasswordBindFixture(b, "bolt", [][]byte{stored}, nil)
				state := &connectionState{runtime: instance.runtime.Load(), protocolVersion: 3}
				ctx := b.Context()
				count := 1
				if distribution == "rotate256" {
					count = 256
				}
				password := []byte(supplied.password)
				requests := make([]ldapwire.BindRequest, count)
				messages := make([]ldapwire.Message, count)
				if err := instance.config.Store.Update(ctx, func(writer storage.Writer) error {
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
						request := ldapwire.BindRequest{Version: 3, Name: entry.DN, Authentication: ldapwire.Authentication{Simple: password}}
						requests[index] = request
						messages[index] = ldapwire.Message{ID: 1, Request: request}
					}
					return nil
				}); err != nil {
					b.Fatal(err)
				}
				expected := ldapwire.EncodeBindResponse(1, ldapwire.Result{Code: supplied.code}, nil)
				capture := &smallIndexedCapture{}
				validate := func(request ldapwire.BindRequest) {
					b.Helper()
					if !bytes.Equal(capture.Bytes(), expected) {
						b.Fatalf("handler response for %q: got %x, want %x", request.Name, capture.Bytes(), expected)
					}
					var boundDN, mechanism string
					var credentials []byte
					if supplied.code == ldapwire.ResultSuccess {
						boundDN, mechanism, credentials = request.Name, "SIMPLE", password
					}
					if state.boundDN != boundDN || state.bindCredentialDN != boundDN ||
						state.authMechanism != mechanism || !bytes.Equal(state.bindCredentials, credentials) ||
						state.passwordPolicyRestrictedDN != "" || state.protocolVersion != 3 {
						b.Fatalf("handler identity for %q: boundDN=%q credentialDN=%q mechanism=%q credentialsMatch=%t restrictedDN=%q version=%d",
							request.Name, state.boundDN, state.bindCredentialDN, state.authMechanism,
							bytes.Equal(state.bindCredentials, credentials), state.passwordPolicyRestrictedDN, state.protocolVersion)
					}
				}
				// b.Loop excludes setup, all warm-up checks and final validation.
				// The rotating set exceeds both bounded DN caches (128 entries).
				for index := range count {
					capture.Reset()
					if err := instance.handleBind(ctx, capture, state, messages[index], requests[index]); err != nil {
						b.Fatal(err)
					}
					validate(requests[index])
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
				validate(requests[(index+count-1)%count])
			})
		}
	}
}
