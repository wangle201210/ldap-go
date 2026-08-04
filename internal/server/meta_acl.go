package server

import (
	"context"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func (server *Server) filterMetaSearchPackets(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	packets []*ber.Packet,
	typesOnly bool,
) ([]*ber.Packet, error) {
	filtered := make([]*ber.Packet, 0, len(packets))
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		reader = readerForDatabase(reader, database)
		for _, packet := range packets {
			if metaPacketTag(packet) != ldapwire.ApplicationSearchResultEntry {
				filtered = append(filtered, packet)
				continue
			}
			entry, err := decodeTranslucentSearchEntry(packet)
			if err != nil {
				return err
			}
			if !server.allowed(
				state.runtime,
				reader,
				state.boundDN,
				entry,
				"entry",
				nil,
				acl.Read,
			) {
				continue
			}
			entry = server.attributesWithPrivilege(
				state.runtime,
				reader,
				state.boundDN,
				entry,
				acl.Read,
				typesOnly,
			)
			controls, err := decodePBindResponseControls(packet)
			if err != nil {
				return err
			}
			encoded := ldapwire.EncodeSearchResultEntry(0, entry, controls)
			mapped, err := ber.DecodePacketErr(encoded)
			if err != nil {
				return fmt.Errorf("encode ACL-filtered back-meta entry: %w", err)
			}
			filtered = append(filtered, mapped)
		}
		return nil
	})
	return filtered, err
}
