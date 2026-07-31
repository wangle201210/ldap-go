package server

import (
	"bytes"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestNormalizeSyncConsumerSyncInfoForGoLDAP(t *testing.T) {
	t.Parallel()

	var identifier ldapwire.SyncUUID
	copy(identifier[:], []byte("0123456789abcdef"))
	tests := []struct {
		name string
		info ldapwire.SyncInfoValue
	}{
		{
			name: "refresh present without cookie",
			info: ldapwire.SyncInfoValue{
				Kind:        ldapwire.SyncInfoRefreshPresent,
				RefreshDone: false,
			},
		},
		{
			name: "present UUID set with omitted defaults",
			info: ldapwire.SyncInfoValue{
				Kind:  ldapwire.SyncInfoIDSet,
				UUIDs: []ldapwire.SyncUUID{identifier},
			},
		},
		{
			name: "delete UUID set without cookie",
			info: ldapwire.SyncInfoValue{
				Kind:           ldapwire.SyncInfoIDSet,
				RefreshDeletes: true,
				UUIDs:          []ldapwire.SyncUUID{identifier},
			},
		},
		{
			name: "present UUID set with cookie",
			info: ldapwire.SyncInfoValue{
				Kind:      ldapwire.SyncInfoIDSet,
				Cookie:    []byte("cookie"),
				HasCookie: true,
				UUIDs:     []ldapwire.SyncUUID{identifier},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			encoded := ldapwire.EncodeIntermediateResponse(
				7,
				syncInfoOID,
				ldapwire.EncodeSyncInfoValue(test.info),
				nil,
			)
			packet, err := ber.DecodePacketErr(encoded)
			if err != nil {
				t.Fatalf("decode source response: %v", err)
			}
			normalized, err := normalizeSyncConsumerResponsePacket(packet)
			if err != nil {
				t.Fatalf("normalize response: %v", err)
			}
			packet, err = ber.DecodePacketErr(normalized)
			if err != nil {
				t.Fatalf("decode normalized response: %v", err)
			}
			control, err := ldap.DecodeControl(packet.Children[1])
			if err != nil {
				t.Fatalf("go-ldap DecodeControl(): %v", err)
			}
			info, ok := control.(*ldap.ControlSyncInfo)
			if !ok {
				t.Fatalf("decoded control = %T", control)
			}
			assertGoLDAPSyncInfo(t, info, test.info, identifier)
		})
	}
}

func assertGoLDAPSyncInfo(
	t *testing.T,
	got *ldap.ControlSyncInfo,
	want ldapwire.SyncInfoValue,
	identifier ldapwire.SyncUUID,
) {
	t.Helper()
	if got.Value != ldap.ControlSyncInfoValue(want.Kind) {
		t.Fatalf("Sync Info kind = %d, want %d", got.Value, want.Kind)
	}
	switch want.Kind {
	case ldapwire.SyncInfoRefreshPresent:
		if got.RefreshPresent == nil ||
			got.RefreshPresent.RefreshDone != want.RefreshDone ||
			!bytes.Equal(got.RefreshPresent.Cookie, want.Cookie) {
			t.Fatalf("refreshPresent = %#v, want %#v", got.RefreshPresent, want)
		}
	case ldapwire.SyncInfoIDSet:
		if got.SyncIdSet == nil ||
			got.SyncIdSet.RefreshDeletes != want.RefreshDeletes ||
			!bytes.Equal(got.SyncIdSet.Cookie, want.Cookie) ||
			len(got.SyncIdSet.SyncUUIDs) != len(want.UUIDs) {
			t.Fatalf("syncIdSet = %#v, want %#v", got.SyncIdSet, want)
		}
		if len(want.UUIDs) > 0 &&
			!bytes.Equal(got.SyncIdSet.SyncUUIDs[0][:], identifier[:]) {
			t.Fatalf("syncIdSet UUID = %s", got.SyncIdSet.SyncUUIDs[0])
		}
	}
}
