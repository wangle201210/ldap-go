package server

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

// go-ldap v3.4.14 decodes Sync Info optional fields by position instead of
// ASN.1 tag. Normalize those fields before its reader sees the packet.
type syncConsumerResponseConn struct {
	net.Conn

	readMu  sync.Mutex
	pending []byte
}

func (connection *syncConsumerResponseConn) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	connection.readMu.Lock()
	defer connection.readMu.Unlock()

	if len(connection.pending) == 0 {
		packet, err := readSyncConsumerPacket(connection.Conn)
		if err != nil {
			return 0, err
		}
		connection.pending, err = normalizeSyncConsumerResponsePacket(packet)
		if err != nil {
			return 0, err
		}
	}
	count := copy(buffer, connection.pending)
	connection.pending = connection.pending[count:]
	return count, nil
}

func normalizeSyncConsumerResponsePacket(packet *ber.Packet) ([]byte, error) {
	if packet == nil {
		return nil, errors.New("nil LDAP response packet")
	}
	if packet.ClassType != ber.ClassUniversal ||
		packet.TagType != ber.TypeConstructed ||
		packet.Tag != ber.TagSequence ||
		len(packet.Children) < 2 {
		return nil, errors.New("malformed LDAP response envelope")
	}
	operation := packet.Children[1]
	if operation.ClassType != ber.ClassApplication ||
		operation.TagType != ber.TypeConstructed ||
		operation.Tag != ldapwire.ApplicationIntermediateResponse {
		return packet.Bytes(), nil
	}

	responseName := ""
	valueIndex := -1
	for index, child := range operation.Children {
		if child.ClassType != ber.ClassContext ||
			child.TagType != ber.TypePrimitive {
			continue
		}
		switch child.Tag {
		case 0:
			responseName = child.Data.String()
		case 1:
			valueIndex = index
		}
	}
	if responseName != syncInfoOID {
		return packet.Bytes(), nil
	}
	if valueIndex < 0 {
		return nil, errors.New("Sync Info response has no responseValue")
	}

	info, err := ldapwire.DecodeSyncInfoValue(
		operation.Children[valueIndex].Data.Bytes(),
	)
	if err != nil {
		return nil, fmt.Errorf("decode Sync Info response: %w", err)
	}
	normalized, err := encodeSyncConsumerCompatibleInfo(info)
	if err != nil {
		return nil, err
	}
	responseValue := ber.Encode(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		nil,
		"responseValue",
	)
	_, _ = responseValue.Data.Write(normalized)
	operation.Children[valueIndex] = responseValue
	return cloneSyncConsumerBERPacket(packet).Bytes(), nil
}

func encodeSyncConsumerCompatibleInfo(
	info ldapwire.SyncInfoValue,
) ([]byte, error) {
	switch info.Kind {
	case ldapwire.SyncInfoNewCookie:
		return ldapwire.EncodeSyncInfoValue(info), nil
	case ldapwire.SyncInfoRefreshDelete, ldapwire.SyncInfoRefreshPresent:
		tag := ber.Tag(1)
		if info.Kind == ldapwire.SyncInfoRefreshPresent {
			tag = 2
		}
		value := ber.Encode(
			ber.ClassContext,
			ber.TypeConstructed,
			tag,
			nil,
			"syncRefresh",
		)
		value.AppendChild(syncConsumerCompatibilityOctetString(info.Cookie))
		value.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			info.RefreshDone,
			"refreshDone",
		))
		return value.Bytes(), nil
	case ldapwire.SyncInfoIDSet:
		value := ber.Encode(
			ber.ClassContext,
			ber.TypeConstructed,
			3,
			nil,
			"syncIdSet",
		)
		value.AppendChild(syncConsumerCompatibilityOctetString(info.Cookie))
		value.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			info.RefreshDeletes,
			"refreshDeletes",
		))
		identifiers := ber.Encode(
			ber.ClassUniversal,
			ber.TypeConstructed,
			ber.TagSet,
			nil,
			"syncUUIDs",
		)
		for _, identifier := range info.UUIDs {
			identifiers.AppendChild(
				syncConsumerCompatibilityOctetString(identifier[:]),
			)
		}
		value.AppendChild(identifiers)
		return value.Bytes(), nil
	default:
		return nil, fmt.Errorf("unknown Sync Info kind %d", info.Kind)
	}
}

func syncConsumerCompatibilityOctetString(value []byte) *ber.Packet {
	packet := ber.Encode(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		nil,
		"octetString",
	)
	_, _ = packet.Data.Write(bytes.Clone(value))
	return packet
}

func cloneSyncConsumerBERPacket(packet *ber.Packet) *ber.Packet {
	cloned := ber.Encode(
		packet.ClassType,
		packet.TagType,
		packet.Tag,
		nil,
		packet.Description,
	)
	cloned.Value = packet.Value
	if packet.TagType == ber.TypeConstructed {
		for _, child := range packet.Children {
			cloned.AppendChild(cloneSyncConsumerBERPacket(child))
		}
		return cloned
	}
	_, _ = cloned.Data.Write(packet.Data.Bytes())
	return cloned
}
