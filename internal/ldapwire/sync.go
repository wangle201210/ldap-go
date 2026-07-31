package ldapwire

import (
	"bytes"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type SyncMode int64

const (
	SyncRefreshOnly       SyncMode = 1
	SyncRefreshAndPersist SyncMode = 3
)

type SyncState int64

const (
	SyncStatePresent SyncState = iota
	SyncStateAdd
	SyncStateModify
	SyncStateDelete
)

type SyncUUID [16]byte

type SyncRequestValue struct {
	Mode       SyncMode
	Cookie     []byte
	HasCookie  bool
	ReloadHint bool
}

type SyncStateValue struct {
	State     SyncState
	EntryUUID SyncUUID
	Cookie    []byte
	HasCookie bool
}

type SyncDoneValue struct {
	Cookie         []byte
	HasCookie      bool
	RefreshDeletes bool
}

type SyncInfoKind uint8

const (
	SyncInfoNewCookie SyncInfoKind = iota
	SyncInfoRefreshDelete
	SyncInfoRefreshPresent
	SyncInfoIDSet
)

type SyncInfoValue struct {
	Kind           SyncInfoKind
	Cookie         []byte
	HasCookie      bool
	RefreshDone    bool
	RefreshDeletes bool
	UUIDs          []SyncUUID
}

func DecodeSyncRequestValue(value []byte) (SyncRequestValue, error) {
	packet, err := decodeSyncBERValue(value, "sync request")
	if err != nil {
		return SyncRequestValue{}, err
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) < 1 ||
		len(packet.Children) > 3 {
		return SyncRequestValue{}, malformed(
			"sync request value is not a one-to-three-element sequence",
		)
	}

	rawMode, err := syncEnumerated(packet.Children[0], "sync request mode")
	if err != nil {
		return SyncRequestValue{}, err
	}
	request := SyncRequestValue{Mode: SyncMode(rawMode)}
	switch request.Mode {
	case SyncRefreshOnly, SyncRefreshAndPersist:
	default:
		return SyncRequestValue{}, malformed(
			"sync request mode %d is invalid",
			rawMode,
		)
	}

	position := 1
	if position < len(packet.Children) &&
		isPacket(
			packet.Children[position],
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
		) {
		request.Cookie = bytes.Clone(packet.Children[position].Data.Bytes())
		request.HasCookie = true
		position++
	}
	if position < len(packet.Children) &&
		isPacket(
			packet.Children[position],
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
		) {
		request.ReloadHint, err = packetBoolean(packet.Children[position])
		if err != nil {
			return SyncRequestValue{}, malformed("sync request reloadHint is invalid")
		}
		position++
	}
	if position != len(packet.Children) {
		return SyncRequestValue{}, malformed("sync request elements are invalid")
	}
	return request, nil
}

func EncodeSyncRequestValue(request SyncRequestValue) []byte {
	value := ber.NewSequence("syncRequestValue")
	value.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(request.Mode),
		"mode",
	))
	if request.HasCookie || request.Cookie != nil {
		value.AppendChild(octetString(request.Cookie))
	}
	if request.ReloadHint {
		value.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"reloadHint",
		))
	}
	return value.Bytes()
}

func DecodeSyncStateValue(value []byte) (SyncStateValue, error) {
	packet, err := decodeSyncBERValue(value, "sync state")
	if err != nil {
		return SyncStateValue{}, err
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) < 2 ||
		len(packet.Children) > 3 {
		return SyncStateValue{}, malformed(
			"sync state value is not a two-or-three-element sequence",
		)
	}

	rawState, err := syncEnumerated(packet.Children[0], "sync state")
	if err != nil {
		return SyncStateValue{}, err
	}
	state := SyncState(rawState)
	switch state {
	case SyncStatePresent, SyncStateAdd, SyncStateModify, SyncStateDelete:
	default:
		return SyncStateValue{}, malformed("sync state %d is invalid", rawState)
	}

	rawUUID, err := packetBytes(packet.Children[1])
	if err != nil || len(rawUUID) != len(SyncUUID{}) {
		return SyncStateValue{}, malformed(
			"sync state entryUUID is not a 16-byte octet string",
		)
	}
	response := SyncStateValue{State: state}
	copy(response.EntryUUID[:], rawUUID)
	if len(packet.Children) == 3 {
		response.Cookie, err = packetBytes(packet.Children[2])
		if err != nil {
			return SyncStateValue{}, malformed("sync state cookie is invalid")
		}
		response.HasCookie = true
	}
	return response, nil
}

func EncodeSyncStateValue(state SyncStateValue) []byte {
	value := ber.NewSequence("syncStateValue")
	value.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(state.State),
		"state",
	))
	value.AppendChild(octetString(state.EntryUUID[:]))
	if state.HasCookie || state.Cookie != nil {
		value.AppendChild(octetString(state.Cookie))
	}
	return value.Bytes()
}

func DecodeSyncDoneValue(value []byte) (SyncDoneValue, error) {
	packet, err := decodeSyncBERValue(value, "sync done")
	if err != nil {
		return SyncDoneValue{}, err
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) > 2 {
		return SyncDoneValue{}, malformed(
			"sync done value is not a zero-to-two-element sequence",
		)
	}

	var done SyncDoneValue
	position := 0
	if position < len(packet.Children) &&
		isPacket(
			packet.Children[position],
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
		) {
		done.Cookie = bytes.Clone(packet.Children[position].Data.Bytes())
		done.HasCookie = true
		position++
	}
	if position < len(packet.Children) &&
		isPacket(
			packet.Children[position],
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
		) {
		done.RefreshDeletes, err = packetBoolean(packet.Children[position])
		if err != nil {
			return SyncDoneValue{}, malformed(
				"sync done refreshDeletes is invalid",
			)
		}
		position++
	}
	if position != len(packet.Children) {
		return SyncDoneValue{}, malformed("sync done elements are invalid")
	}
	return done, nil
}

func EncodeSyncDoneValue(done SyncDoneValue) []byte {
	value := ber.NewSequence("syncDoneValue")
	if done.HasCookie || done.Cookie != nil {
		value.AppendChild(octetString(done.Cookie))
	}
	if done.RefreshDeletes {
		value.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"refreshDeletes",
		))
	}
	return value.Bytes()
}

func DecodeSyncInfoValue(value []byte) (SyncInfoValue, error) {
	packet, err := decodeSyncBERValue(value, "sync info")
	if err != nil {
		return SyncInfoValue{}, err
	}
	if packet.ClassType != ber.ClassContext {
		return SyncInfoValue{}, malformed("sync info choice has invalid class")
	}

	switch {
	case isPacket(packet, ber.ClassContext, ber.TypePrimitive, 0):
		return SyncInfoValue{
			Kind:      SyncInfoNewCookie,
			Cookie:    bytes.Clone(packet.Data.Bytes()),
			HasCookie: true,
		}, nil
	case isPacket(packet, ber.ClassContext, ber.TypeConstructed, 1):
		return decodeSyncRefreshInfo(packet, SyncInfoRefreshDelete)
	case isPacket(packet, ber.ClassContext, ber.TypeConstructed, 2):
		return decodeSyncRefreshInfo(packet, SyncInfoRefreshPresent)
	case isPacket(packet, ber.ClassContext, ber.TypeConstructed, 3):
		return decodeSyncIDSet(packet)
	default:
		return SyncInfoValue{}, malformed("sync info choice is invalid")
	}
}

func EncodeSyncInfoValue(info SyncInfoValue) []byte {
	switch info.Kind {
	case SyncInfoNewCookie:
		return syncContextOctetString(0, info.Cookie, "newcookie").Bytes()
	case SyncInfoRefreshDelete, SyncInfoRefreshPresent:
		tag := ber.Tag(1)
		description := "refreshDelete"
		if info.Kind == SyncInfoRefreshPresent {
			tag = 2
			description = "refreshPresent"
		}
		value := ber.Encode(
			ber.ClassContext,
			ber.TypeConstructed,
			tag,
			nil,
			description,
		)
		if info.HasCookie || info.Cookie != nil {
			value.AppendChild(octetString(info.Cookie))
		}
		if !info.RefreshDone {
			value.AppendChild(ber.NewLDAPBoolean(
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagBoolean,
				false,
				"refreshDone",
			))
		}
		return value.Bytes()
	case SyncInfoIDSet:
		value := ber.Encode(
			ber.ClassContext,
			ber.TypeConstructed,
			3,
			nil,
			"syncIdSet",
		)
		if info.HasCookie || info.Cookie != nil {
			value.AppendChild(octetString(info.Cookie))
		}
		if info.RefreshDeletes {
			value.AppendChild(ber.NewLDAPBoolean(
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagBoolean,
				true,
				"refreshDeletes",
			))
		}
		uuids := ber.Encode(
			ber.ClassUniversal,
			ber.TypeConstructed,
			ber.TagSet,
			nil,
			"syncUUIDs",
		)
		for _, uuid := range info.UUIDs {
			uuids.AppendChild(octetString(uuid[:]))
		}
		value.AppendChild(uuids)
		return value.Bytes()
	default:
		return nil
	}
}

func decodeSyncRefreshInfo(
	packet *ber.Packet,
	kind SyncInfoKind,
) (SyncInfoValue, error) {
	if len(packet.Children) > 2 {
		return SyncInfoValue{}, malformed(
			"sync refresh info has too many elements",
		)
	}
	info := SyncInfoValue{
		Kind:        kind,
		RefreshDone: true,
	}
	position := 0
	if position < len(packet.Children) &&
		isPacket(
			packet.Children[position],
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
		) {
		info.Cookie = bytes.Clone(packet.Children[position].Data.Bytes())
		info.HasCookie = true
		position++
	}
	if position < len(packet.Children) &&
		isPacket(
			packet.Children[position],
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
		) {
		value, err := packetBoolean(packet.Children[position])
		if err != nil {
			return SyncInfoValue{}, malformed(
				"sync refresh info refreshDone is invalid",
			)
		}
		info.RefreshDone = value
		position++
	}
	if position != len(packet.Children) {
		return SyncInfoValue{}, malformed("sync refresh info elements are invalid")
	}
	return info, nil
}

func decodeSyncIDSet(packet *ber.Packet) (SyncInfoValue, error) {
	if len(packet.Children) < 1 || len(packet.Children) > 3 {
		return SyncInfoValue{}, malformed(
			"syncIdSet is not a one-to-three-element value",
		)
	}
	info := SyncInfoValue{Kind: SyncInfoIDSet}
	position := 0
	if isPacket(
		packet.Children[position],
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
	) {
		info.Cookie = bytes.Clone(packet.Children[position].Data.Bytes())
		info.HasCookie = true
		position++
	}
	if position < len(packet.Children) &&
		isPacket(
			packet.Children[position],
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
		) {
		value, err := packetBoolean(packet.Children[position])
		if err != nil {
			return SyncInfoValue{}, malformed(
				"syncIdSet refreshDeletes is invalid",
			)
		}
		info.RefreshDeletes = value
		position++
	}
	if position >= len(packet.Children) ||
		!isPacket(
			packet.Children[position],
			ber.ClassUniversal,
			ber.TypeConstructed,
			ber.TagSet,
		) {
		return SyncInfoValue{}, malformed("syncIdSet UUIDs are invalid")
	}
	for _, child := range packet.Children[position].Children {
		rawUUID, err := packetBytes(child)
		if err != nil || len(rawUUID) != len(SyncUUID{}) {
			return SyncInfoValue{}, malformed(
				"syncIdSet contains an invalid UUID",
			)
		}
		var uuid SyncUUID
		copy(uuid[:], rawUUID)
		info.UUIDs = append(info.UUIDs, uuid)
	}
	position++
	if position != len(packet.Children) {
		return SyncInfoValue{}, malformed("syncIdSet elements are invalid")
	}
	return info, nil
}

func decodeSyncBERValue(value []byte, name string) (*ber.Packet, error) {
	if len(value) == 0 {
		return nil, malformed("%s value is empty", name)
	}
	reader := bytes.NewReader(value)
	packet, err := ber.ReadPacket(reader)
	if err != nil {
		return nil, malformed("decode %s value: %v", name, err)
	}
	if reader.Len() != 0 {
		return nil, malformed("%s value has trailing data", name)
	}
	return packet, nil
}

func syncEnumerated(packet *ber.Packet, name string) (int64, error) {
	if !isPacket(packet, ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated) ||
		packet.Data.Len() == 0 {
		return 0, malformed("%s is not an enumerated value", name)
	}
	value, err := ber.ParseInt64(packet.Data.Bytes())
	if err != nil {
		return 0, malformed("%s is invalid", name)
	}
	return value, nil
}

func syncContextOctetString(
	tag ber.Tag,
	value []byte,
	description string,
) *ber.Packet {
	packet := ber.Encode(
		ber.ClassContext,
		ber.TypePrimitive,
		tag,
		nil,
		description,
	)
	_, _ = packet.Data.Write(bytes.Clone(value))
	return packet
}
