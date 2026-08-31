package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type derefControlRequest struct {
	specs    []ldapwire.DerefSpec
	critical bool
}

func runtimeSupportsDeref(databases []runtimeDatabase) bool {
	for _, database := range databases {
		if database.deref {
			return true
		}
	}
	return false
}

func frontendSupportsDeref(databases []runtimeDatabase) bool {
	for _, database := range databases {
		if databaseType(database.name) == "frontend" && database.deref {
			return true
		}
	}
	return false
}

func derefEnabledForDatabase(
	databases []runtimeDatabase,
	database runtimeDatabase,
) bool {
	return database.deref || frontendSupportsDeref(databases)
}

func (server *Server) prepareDerefSearchTarget(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	controls *requestControls,
	enabled bool,
) (net.Conn, *ldapwire.Result) {
	if controls.deref == nil {
		return connection, nil
	}
	if !enabled {
		if controls.deref.critical {
			return connection, controlResult(
				ldapwire.ResultUnavailableCriticalExtension,
				"Dereference control is not enabled for this search target",
			)
		}
		controls.deref = nil
		return connection, nil
	}
	return newDerefSearchResponseConnection(
		ctx,
		connection,
		server,
		state,
		controls.deref,
	), nil
}

func prepareDerefControl(
	registry *schema.Registry,
	request *derefControlRequest,
) (*derefControlRequest, *ldapwire.Result) {
	if request == nil {
		return nil, nil
	}

	prepared := &derefControlRequest{
		specs:    make([]ldapwire.DerefSpec, 0, len(request.specs)),
		critical: request.critical,
	}
	for _, spec := range request.specs {
		derefAttribute, found, err := registry.EffectiveAttributeType(spec.DerefAttr)
		if err != nil || !found {
			return nil, controlResult(
				ldapwire.ResultProtocolError,
				"Dereference control: derefAttr decoding error",
			)
		}
		if derefAttribute.Syntax != schema.SyntaxDistinguishedName {
			if request.critical {
				return nil, controlResult(
					ldapwire.ResultProtocolError,
					"Dereference control: derefAttr syntax not distinguishedName",
				)
			}
			return nil, nil
		}

		preparedSpec := ldapwire.DerefSpec{
			DerefAttr: canonicalDerefAttributeDescription(
				registry,
				spec.DerefAttr,
			),
			Attributes: make([]string, 0, len(spec.Attributes)),
		}
		for _, requestedAttribute := range spec.Attributes {
			if _, found, err := registry.EffectiveAttributeType(requestedAttribute); err != nil || !found {
				return nil, controlResult(
					ldapwire.ResultProtocolError,
					"Dereference control: attribute decoding error",
				)
			}
			preparedSpec.Attributes = append(
				preparedSpec.Attributes,
				canonicalDerefAttributeDescription(registry, requestedAttribute),
			)
		}
		prepared.specs = append(prepared.specs, preparedSpec)
	}
	return prepared, nil
}

func canonicalDerefAttributeDescription(
	registry *schema.Registry,
	description string,
) string {
	base, options := splitDerefAttributeDescription(description)
	if attribute, found := registry.AttributeType(base); found {
		base = attribute.Name()
	}
	if len(options) == 0 {
		return base
	}
	return base + ";" + strings.Join(options, ";")
}

func splitDerefAttributeDescription(description string) (string, []string) {
	parts := strings.Split(description, ";")
	base := strings.TrimSpace(parts[0])
	if len(parts) == 1 {
		return base, nil
	}
	options := make([]string, 0, len(parts)-1)
	for _, option := range parts[1:] {
		options = append(options, strings.ToLower(strings.TrimSpace(option)))
	}
	sort.Strings(options)
	return base, options
}

type derefSearchResponseConnection struct {
	net.Conn
	ctx     context.Context
	server  *Server
	state   *connectionState
	request *derefControlRequest
}

func newDerefSearchResponseConnection(
	ctx context.Context,
	connection net.Conn,
	server *Server,
	state *connectionState,
	request *derefControlRequest,
) net.Conn {
	return &derefSearchResponseConnection{
		Conn:    connection,
		ctx:     ctx,
		server:  server,
		state:   state,
		request: request,
	}
}

func (connection *derefSearchResponseConnection) Write(value []byte) (int, error) {
	packet, err := ber.DecodePacketErr(value)
	if err != nil || !isSearchResultEntryPacket(packet) || messageHasDerefControl(packet) {
		return connection.Conn.Write(value)
	}

	entryDN := packet.Children[1].Children[0].Data.String()
	control, err := connection.server.derefResponseControl(
		connection.ctx,
		connection.state,
		entryDN,
		connection.request,
	)
	if err != nil {
		return 0, fmt.Errorf("build dereference response control for %q: %w", entryDN, err)
	}
	if control == nil {
		return connection.Conn.Write(value)
	}

	encoded := encodeSearchEntryWithAdditionalControl(packet, *control)
	if err := ldapwire.Write(connection.Conn, encoded); err != nil {
		return 0, err
	}
	return len(value), nil
}

func (connection *derefSearchResponseConnection) beginFinalResponse() error {
	if finalizer, ok := connection.Conn.(interface {
		beginFinalResponse() error
	}); ok {
		return finalizer.beginFinalResponse()
	}
	return nil
}

func isSearchResultEntryPacket(packet *ber.Packet) bool {
	return packet != nil &&
		packet.ClassType == ber.ClassUniversal &&
		packet.TagType == ber.TypeConstructed &&
		packet.Tag == ber.TagSequence &&
		(len(packet.Children) == 2 || len(packet.Children) == 3) &&
		packet.Children[1].ClassType == ber.ClassApplication &&
		packet.Children[1].TagType == ber.TypeConstructed &&
		uint64(packet.Children[1].Tag) == ldapwire.ApplicationSearchResultEntry &&
		len(packet.Children[1].Children) == 2 &&
		packet.Children[1].Children[0].ClassType == ber.ClassUniversal &&
		packet.Children[1].Children[0].Tag == ber.TagOctetString
}

func messageHasDerefControl(packet *ber.Packet) bool {
	if len(packet.Children) != 3 {
		return false
	}
	for _, control := range packet.Children[2].Children {
		if len(control.Children) > 0 &&
			control.Children[0].Data.String() == ldapwire.DerefControlOID {
			return true
		}
	}
	return false
}

func encodeSearchEntryWithAdditionalControl(
	packet *ber.Packet,
	control ldapwire.Control,
) []byte {
	message := ber.NewSequence("LDAPMessage")
	message.AppendChild(packet.Children[0])
	message.AppendChild(packet.Children[1])

	controls := ber.Encode(
		ber.ClassContext,
		ber.TypeConstructed,
		0,
		nil,
		"controls",
	)
	if len(packet.Children) == 3 {
		for _, existing := range packet.Children[2].Children {
			controls.AppendChild(existing)
		}
	}
	controls.AppendChild(encodeDerefLDAPControl(control))
	message.AppendChild(controls)
	return message.Bytes()
}

func encodeDerefLDAPControl(control ldapwire.Control) *ber.Packet {
	packet := ber.NewSequence("Control")
	packet.AppendChild(derefOctetString([]byte(control.OID)))
	if control.Critical {
		packet.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"criticality",
		))
	}
	if control.HasValue || control.Value != nil {
		packet.AppendChild(derefOctetString(control.Value))
	}
	return packet
}

func derefOctetString(value []byte) *ber.Packet {
	packet := ber.Encode(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		nil,
		"LDAPString",
	)
	_, _ = packet.Data.Write(bytes.Clone(value))
	return packet
}

func (server *Server) derefResponseControl(
	ctx context.Context,
	state *connectionState,
	entryDN string,
	request *derefControlRequest,
) (*ldapwire.Control, error) {
	if request == nil || len(request.specs) == 0 {
		return nil, nil
	}
	sourceDN, err := parseRuntimeDN(entryDN, state.runtime.schema)
	if err != nil {
		return nil, nil
	}
	sourceDatabase := databaseForDN(state.runtime, sourceDN)
	if sourceDatabase == nil ||
		sourceDatabase.partition == "" ||
		!derefEnabledForDatabase(state.runtime.databases, *sourceDatabase) {
		return nil, nil
	}

	var response *ldapwire.Control
	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		databaseReader := readerForDatabase(reader, *sourceDatabase)
		sourceDN, err = storage.NormalizeReaderDN(databaseReader, sourceDN)
		if err != nil {
			return nil
		}
		sourceBase, err := databaseReader.Get(sourceDN)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		sourceResponse := withSubschemaReference(sourceBase)
		sourceResponse, err = withCollectiveAttributes(
			state.runtime.schema,
			databaseReader,
			sourceResponse,
		)
		if err != nil {
			return err
		}

		results, applies, err := server.derefEntryResults(
			state.runtime,
			databaseReader,
			state.boundDN,
			sourceDatabase,
			sourceResponse,
			sourceBase,
			request.specs,
		)
		if err != nil || !applies {
			return err
		}
		value, err := ldapwire.EncodeDerefResponseValue(results)
		if err != nil {
			return err
		}
		response = &ldapwire.Control{
			OID:      ldapwire.DerefControlOID,
			Value:    value,
			HasValue: true,
		}
		return nil
	})
	return response, err
}

func (server *Server) derefEntryResults(
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
	database *runtimeDatabase,
	sourceACL directory.Entry,
	sourceBase directory.Entry,
	specs []ldapwire.DerefSpec,
) ([]ldapwire.DerefResult, bool, error) {
	results := make([]ldapwire.DerefResult, 0)
	applies := false
	for _, spec := range specs {
		sourceAttribute := findDerefEntryAttribute(
			runtime.schema,
			sourceBase,
			spec.DerefAttr,
		)
		if sourceAttribute == nil || !server.allowed(
			runtime,
			reader,
			subjectDN,
			sourceACL,
			sourceAttribute.Description,
			nil,
			acl.Read,
		) {
			continue
		}
		applies = true
		for _, value := range sourceAttribute.Values {
			if !server.allowed(
				runtime,
				reader,
				subjectDN,
				sourceACL,
				sourceAttribute.Description,
				value,
				acl.Read,
			) {
				continue
			}

			targetDN, err := directory.ParseDN(string(value))
			if err != nil {
				continue
			}
			targetDN, err = storage.NormalizeReaderDN(reader, targetDN)
			if err != nil {
				continue
			}
			result := ldapwire.DerefResult{
				DerefAttr:  spec.DerefAttr,
				DerefValue: string(value),
			}
			if derefTargetUsesDatabase(runtime, database, targetDN) {
				target, getErr := reader.Get(targetDN)
				switch {
				case getErr == nil:
					target = withSubschemaReference(target)
					target, getErr = withCollectiveAttributes(
						runtime.schema,
						reader,
						target,
					)
					if getErr != nil {
						return nil, false, getErr
					}
					if server.allowed(
						runtime,
						reader,
						subjectDN,
						target,
						"entry",
						nil,
						acl.Read,
					) {
						result.Attributes = server.derefReadableAttributes(
							runtime,
							reader,
							subjectDN,
							target,
							spec.Attributes,
						)
					}
				case errors.Is(getErr, storage.ErrEntryNotFound):
				default:
					return nil, false, getErr
				}
			}
			results = append(results, result)
		}
	}
	return results, applies, nil
}

func (server *Server) derefReadableAttributes(
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
	target directory.Entry,
	requested []string,
) []ldapwire.DerefAttribute {
	attributes := make([]ldapwire.DerefAttribute, 0, len(requested))
	for _, description := range requested {
		attribute := findDerefEntryAttribute(runtime.schema, target, description)
		if attribute == nil || !server.allowed(
			runtime,
			reader,
			subjectDN,
			target,
			attribute.Description,
			nil,
			acl.Read,
		) {
			continue
		}
		readable := ldapwire.DerefAttribute{Type: description}
		for _, value := range attribute.Values {
			if server.allowed(
				runtime,
				reader,
				subjectDN,
				target,
				attribute.Description,
				value,
				acl.Read,
			) {
				readable.Values = append(readable.Values, bytes.Clone(value))
			}
		}
		if len(readable.Values) > 0 {
			attributes = append(attributes, readable)
		}
	}
	return attributes
}

func findDerefEntryAttribute(
	registry *schema.Registry,
	entry directory.Entry,
	description string,
) *directory.Attribute {
	requestedBase, requestedOptions := splitDerefAttributeDescription(description)
	requestedType, requestedKnown := registry.AttributeType(requestedBase)
	for index := range entry.Attributes {
		candidateBase, candidateOptions := splitDerefAttributeDescription(
			entry.Attributes[index].Description,
		)
		if !equalDerefOptions(candidateOptions, requestedOptions) {
			continue
		}
		candidateType, candidateKnown := registry.AttributeType(candidateBase)
		if requestedKnown && candidateKnown {
			if strings.EqualFold(requestedType.OID, candidateType.OID) {
				return &entry.Attributes[index]
			}
			continue
		}
		if strings.EqualFold(candidateBase, requestedBase) {
			return &entry.Attributes[index]
		}
	}
	return nil
}

func equalDerefOptions(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !strings.EqualFold(left[index], right[index]) {
			return false
		}
	}
	return true
}

func derefTargetWithinDatabase(database runtimeDatabase, target directory.DN) bool {
	for _, suffix := range database.suffixes {
		if databaseDNAtOrBelow(database, target, suffix) {
			return true
		}
	}
	return false
}

func derefTargetUsesDatabase(
	runtime *runtimeState,
	source *runtimeDatabase,
	target directory.DN,
) bool {
	return runtime != nil && source != nil && databaseForDN(runtime, target) == source
}
