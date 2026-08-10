package server

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	SockDefaultMaxRequestBytes  int64 = 16 << 20
	SockDefaultMaxResponseBytes int64 = 16 << 20
	SockDefaultMaxLineBytes           = 1 << 20
	SockDefaultMaxEntryBytes          = 4 << 20
	SockDefaultMaxEntries             = 10_000
	SockDefaultMaxAttributes          = 4_096
	SockDefaultMaxValues              = 65_536

	sockLDIFLineWidth = 76
)

var (
	ErrSockProtocol      = errors.New("OpenLDAP back-sock protocol error")
	ErrSockProtocolLimit = errors.New("OpenLDAP back-sock protocol limit exceeded")
)

// SockProtocolLimits bounds allocations and individual records at the
// untrusted external-process boundary. Zero fields select the defaults.
type SockProtocolLimits struct {
	MaxRequestBytes  int64
	MaxResponseBytes int64
	MaxLineBytes     int
	MaxEntryBytes    int
	MaxEntries       int
	MaxAttributes    int
	MaxValues        int
}

// SockConnectionFields are emitted only when their matching Include field is
// true, mirroring olcDbSocketExtensions. IncludeBindDN can therefore emit an
// empty binddn for an anonymous connection.
type SockConnectionFields struct {
	IncludeBindDN   bool
	BindDN          string
	IncludePeerName bool
	PeerName        string
	IncludeSSF      bool
	SSF             int
	IncludeConnID   bool
	ConnID          uint64
}

// SockRequest is one OpenLDAP back-sock request. Suffixes and connection
// fields are written in the same position and order as OpenLDAP 2.6.13.
type SockRequest struct {
	MessageID  int64
	Suffixes   []string
	Connection SockConnectionFields
	Operation  SockOperation
}

// SockOperation is the closed set implemented by OpenLDAP's sock backend.
type SockOperation interface {
	sockOperation()
}

type SockAddRequest struct {
	Entry directory.Entry
}

func (SockAddRequest) sockOperation() {}

type SockBindRequest struct {
	DN          string
	Method      int
	Credentials []byte
}

func (SockBindRequest) sockOperation() {}

type SockCompareRequest struct {
	DN        string
	Attribute string
	Assertion []byte
}

func (SockCompareRequest) sockOperation() {}

type SockDeleteRequest struct {
	DN string
}

func (SockDeleteRequest) sockOperation() {}

type SockExtendedRequest struct {
	OID      string
	Value    []byte
	HasValue bool
}

func (SockExtendedRequest) sockOperation() {}

type SockModifyRequest struct {
	DN      string
	Changes []ldapwire.Modification
}

func (SockModifyRequest) sockOperation() {}

type SockModifyDNRequest struct {
	DN             string
	NewRDN         string
	DeleteOldRDN   bool
	NewSuperior    string
	HasNewSuperior bool
}

func (SockModifyDNRequest) sockOperation() {}

type SockSearchRequest struct {
	BaseDN       string
	Scope        directory.Scope
	DerefAliases int
	SizeLimit    int
	TimeLimit    int
	Filter       directory.Filter
	TypesOnly    bool
	Attributes   []string
}

func (SockSearchRequest) sockOperation() {}

type SockUnbindRequest struct{}

func (SockUnbindRequest) sockOperation() {}

// SockResponse contains zero or more Search entries followed by the mandatory
// RESULT record. The parser intentionally requires RESULT even though the
// OpenLDAP 2.6.13 implementation accidentally accepts an early EOF as success.
type SockResponse struct {
	Entries []directory.Entry
	Result  ldapwire.Result
}

// EncodeSockRequest renders a complete request, including its terminating
// blank line, using the OpenLDAP 2.6.13 back-sock wire format.
func EncodeSockRequest(request SockRequest, limits SockProtocolLimits) ([]byte, error) {
	limits = limits.withDefaults()
	if err := limits.validate(); err != nil {
		return nil, err
	}
	encoder := sockRequestEncoder{limits: limits}
	if err := encoder.encode(request); err != nil {
		return nil, err
	}
	return bytes.Clone(encoder.output.Bytes()), nil
}

// WriteSockRequest is the streaming-facing counterpart to EncodeSockRequest.
// Validation and bounded encoding complete before any bytes are written, so a
// malformed request cannot leave a partial command on the Unix socket.
func WriteSockRequest(writer io.Writer, request SockRequest, limits SockProtocolLimits) error {
	if writer == nil {
		return sockProtocolError("request writer is nil")
	}
	encoded, err := EncodeSockRequest(request, limits)
	if err != nil {
		return err
	}
	if err := writeAll(writer, encoded); err != nil {
		return fmt.Errorf("write back-sock request: %w", err)
	}
	return nil
}

// ParseSockResponse reads through EOF as required by the back-sock contract,
// which says the external service returns RESULT and then closes its socket.
// It accepts LF and CRLF, unfolds LDIF continuation lines, and rejects trailing
// data after RESULT.
func ParseSockResponse(reader io.Reader, limits SockProtocolLimits) (SockResponse, error) {
	if reader == nil {
		return SockResponse{}, sockProtocolError("response reader is nil")
	}
	limits = limits.withDefaults()
	if err := limits.validate(); err != nil {
		return SockResponse{}, err
	}

	data, err := readSockResponse(reader, limits.MaxResponseBytes)
	if err != nil {
		return SockResponse{}, err
	}
	return parseSockResponse(data, limits)
}

type sockRequestEncoder struct {
	output bytes.Buffer
	limits SockProtocolLimits
}

func (encoder *sockRequestEncoder) encode(request SockRequest) error {
	if request.MessageID <= 0 || request.MessageID > math.MaxInt32 {
		return sockProtocolError("message ID %d is outside 1..%d", request.MessageID, math.MaxInt32)
	}
	if request.Operation == nil {
		return sockProtocolError("request operation is nil")
	}

	command, err := sockCommand(request.Operation)
	if err != nil {
		return err
	}
	if err := encoder.line([]byte(command)); err != nil {
		return err
	}
	if err := encoder.textLine("msgid", strconv.FormatInt(request.MessageID, 10), false); err != nil {
		return err
	}
	if err := encoder.connection(request.Connection); err != nil {
		return err
	}
	for _, suffix := range request.Suffixes {
		if err := encoder.textLine("suffix", suffix, true); err != nil {
			return err
		}
	}

	if err := encoder.operation(request.Operation); err != nil {
		return err
	}
	return encoder.line(nil)
}

func sockCommand(operation SockOperation) (string, error) {
	switch operation.(type) {
	case SockAddRequest, *SockAddRequest:
		return "ADD", nil
	case SockBindRequest, *SockBindRequest:
		return "BIND", nil
	case SockCompareRequest, *SockCompareRequest:
		return "COMPARE", nil
	case SockDeleteRequest, *SockDeleteRequest:
		return "DELETE", nil
	case SockExtendedRequest, *SockExtendedRequest:
		return "EXTENDED", nil
	case SockModifyRequest, *SockModifyRequest:
		return "MODIFY", nil
	case SockModifyDNRequest, *SockModifyDNRequest:
		return "MODRDN", nil
	case SockSearchRequest, *SockSearchRequest:
		return "SEARCH", nil
	case SockUnbindRequest, *SockUnbindRequest:
		return "UNBIND", nil
	default:
		return "", sockProtocolError("unsupported request operation %T", operation)
	}
}

func (encoder *sockRequestEncoder) connection(fields SockConnectionFields) error {
	if fields.IncludeBindDN {
		if err := encoder.textLine("binddn", fields.BindDN, true); err != nil {
			return err
		}
	}
	if fields.IncludePeerName {
		if err := encoder.textLine("peername", fields.PeerName, true); err != nil {
			return err
		}
	}
	if fields.IncludeSSF {
		if fields.SSF < 0 {
			return sockProtocolError("SSF must not be negative")
		}
		if err := encoder.textLine("ssf", strconv.Itoa(fields.SSF), false); err != nil {
			return err
		}
	}
	if fields.IncludeConnID {
		if err := encoder.textLine("connid", strconv.FormatUint(fields.ConnID, 10), false); err != nil {
			return err
		}
	}
	return nil
}

func (encoder *sockRequestEncoder) operation(operation SockOperation) error {
	switch request := operation.(type) {
	case SockAddRequest:
		return encoder.add(request)
	case *SockAddRequest:
		if request == nil {
			return sockProtocolError("ADD request is nil")
		}
		return encoder.add(*request)
	case SockBindRequest:
		return encoder.bind(request)
	case *SockBindRequest:
		if request == nil {
			return sockProtocolError("BIND request is nil")
		}
		return encoder.bind(*request)
	case SockCompareRequest:
		return encoder.compare(request)
	case *SockCompareRequest:
		if request == nil {
			return sockProtocolError("COMPARE request is nil")
		}
		return encoder.compare(*request)
	case SockDeleteRequest:
		return encoder.delete(request)
	case *SockDeleteRequest:
		if request == nil {
			return sockProtocolError("DELETE request is nil")
		}
		return encoder.delete(*request)
	case SockExtendedRequest:
		return encoder.extended(request)
	case *SockExtendedRequest:
		if request == nil {
			return sockProtocolError("EXTENDED request is nil")
		}
		return encoder.extended(*request)
	case SockModifyRequest:
		return encoder.modify(request)
	case *SockModifyRequest:
		if request == nil {
			return sockProtocolError("MODIFY request is nil")
		}
		return encoder.modify(*request)
	case SockModifyDNRequest:
		return encoder.modifyDN(request)
	case *SockModifyDNRequest:
		if request == nil {
			return sockProtocolError("MODRDN request is nil")
		}
		return encoder.modifyDN(*request)
	case SockSearchRequest:
		return encoder.search(request)
	case *SockSearchRequest:
		if request == nil {
			return sockProtocolError("SEARCH request is nil")
		}
		return encoder.search(*request)
	case SockUnbindRequest:
		return nil
	case *SockUnbindRequest:
		if request == nil {
			return sockProtocolError("UNBIND request is nil")
		}
		return nil
	default:
		return sockProtocolError("unsupported request operation %T", operation)
	}
}

func (encoder *sockRequestEncoder) add(request SockAddRequest) error {
	if request.Entry.DN == "" {
		return sockProtocolError("ADD entry DN is empty")
	}
	if err := encoder.ldifValue("dn", []byte(request.Entry.DN), true); err != nil {
		return err
	}
	for _, attribute := range request.Entry.Attributes {
		if err := validateAttributeDescription(attribute.Description); err != nil {
			return fmt.Errorf("ADD attribute: %w", err)
		}
		for _, value := range attribute.Values {
			if err := encoder.ldifValue(attribute.Description, value, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func (encoder *sockRequestEncoder) bind(request SockBindRequest) error {
	if request.Method < 0 {
		return sockProtocolError("BIND method must not be negative")
	}
	if err := encoder.textLine("dn", request.DN, true); err != nil {
		return err
	}
	if err := encoder.textLine("method", strconv.Itoa(request.Method), false); err != nil {
		return err
	}
	if err := encoder.textLine("credlen", strconv.Itoa(len(request.Credentials)), false); err != nil {
		return err
	}
	if containsLineBreakOrNUL(request.Credentials) {
		return sockProtocolError("BIND credentials contain NUL, CR, or LF and cannot be represented by OpenLDAP back-sock")
	}
	return encoder.rawValueLine("cred", request.Credentials)
}

func (encoder *sockRequestEncoder) compare(request SockCompareRequest) error {
	if request.DN == "" {
		return sockProtocolError("COMPARE DN is empty")
	}
	if err := encoder.textLine("dn", request.DN, false); err != nil {
		return err
	}
	if err := validateAttributeDescription(request.Attribute); err != nil {
		return fmt.Errorf("COMPARE attribute: %w", err)
	}
	return encoder.ldifValue(request.Attribute, request.Assertion, false)
}

func (encoder *sockRequestEncoder) delete(request SockDeleteRequest) error {
	if request.DN == "" {
		return sockProtocolError("DELETE DN is empty")
	}
	return encoder.textLine("dn", request.DN, false)
}

func (encoder *sockRequestEncoder) extended(request SockExtendedRequest) error {
	if !validNumericOID(request.OID) {
		return sockProtocolError("EXTENDED OID %q is not a numeric OID", request.OID)
	}
	if !request.HasValue && len(request.Value) != 0 {
		return sockProtocolError("EXTENDED value is present while HasValue is false")
	}
	if err := encoder.textLine("oid", request.OID, false); err != nil {
		return err
	}
	if request.HasValue {
		return encoder.rawValueLine("value", []byte(base64.StdEncoding.EncodeToString(request.Value)))
	}
	return nil
}

func (encoder *sockRequestEncoder) modify(request SockModifyRequest) error {
	if request.DN == "" {
		return sockProtocolError("MODIFY DN is empty")
	}
	if err := encoder.textLine("dn", request.DN, false); err != nil {
		return err
	}
	for _, change := range request.Changes {
		name := change.Attribute.Description
		if err := validateAttributeDescription(name); err != nil {
			return fmt.Errorf("MODIFY attribute: %w", err)
		}
		var action string
		switch change.Operation {
		case ldapwire.ModificationAdd:
			action = "add"
		case ldapwire.ModificationDelete:
			action = "delete"
		case ldapwire.ModificationReplace:
			action = "replace"
		case ldapwire.ModificationIncrement:
			action = "increment"
		default:
			return sockProtocolError("MODIFY operation %d is unsupported", change.Operation)
		}
		if err := encoder.textLine(action, name, false); err != nil {
			return err
		}
		for _, value := range change.Attribute.Values {
			if err := encoder.ldifValue(name, value, false); err != nil {
				return err
			}
		}
		if err := encoder.line([]byte("-")); err != nil {
			return err
		}
	}
	return nil
}

func (encoder *sockRequestEncoder) modifyDN(request SockModifyDNRequest) error {
	if request.DN == "" || request.NewRDN == "" {
		return sockProtocolError("MODRDN DN and new RDN must not be empty")
	}
	if !request.HasNewSuperior && request.NewSuperior != "" {
		return sockProtocolError("MODRDN new superior is set while HasNewSuperior is false")
	}
	if err := encoder.textLine("dn", request.DN, false); err != nil {
		return err
	}
	if err := encoder.textLine("newrdn", request.NewRDN, false); err != nil {
		return err
	}
	deleteOldRDN := "0"
	if request.DeleteOldRDN {
		deleteOldRDN = "1"
	}
	if err := encoder.textLine("deleteoldrdn", deleteOldRDN, false); err != nil {
		return err
	}
	if request.HasNewSuperior {
		return encoder.textLine("newSuperior", request.NewSuperior, true)
	}
	return nil
}

func (encoder *sockRequestEncoder) search(request SockSearchRequest) error {
	if request.Scope < directory.ScopeBase || request.Scope > directory.ScopeChildren {
		return sockProtocolError("SEARCH scope %d is outside 0..%d", request.Scope, directory.ScopeChildren)
	}
	if request.DerefAliases < ldapwire.NeverDerefAliases || request.DerefAliases > ldapwire.DerefAlways {
		return sockProtocolError("SEARCH dereference mode %d is outside 0..3", request.DerefAliases)
	}
	if request.SizeLimit < 0 || request.TimeLimit < 0 {
		return sockProtocolError("SEARCH size and time limits must not be negative")
	}
	filter, err := encodeSockFilter(request.Filter)
	if err != nil {
		return fmt.Errorf("SEARCH filter: %w", err)
	}
	for _, attribute := range request.Attributes {
		if err := validateAttributeSelector(attribute); err != nil {
			return fmt.Errorf("SEARCH attribute: %w", err)
		}
	}
	fields := []struct {
		name  string
		value string
	}{
		{"base", request.BaseDN},
		{"scope", strconv.Itoa(int(request.Scope))},
		{"deref", strconv.Itoa(request.DerefAliases)},
		{"sizelimit", strconv.Itoa(request.SizeLimit)},
		{"timelimit", strconv.Itoa(request.TimeLimit)},
		{"filter", filter},
	}
	for _, field := range fields {
		if err := encoder.textLine(field.name, field.value, field.name == "base"); err != nil {
			return err
		}
	}
	attributesOnly := "0"
	if request.TypesOnly {
		attributesOnly = "1"
	}
	if err := encoder.textLine("attrsonly", attributesOnly, false); err != nil {
		return err
	}
	attributes := "all"
	if len(request.Attributes) != 0 {
		attributes = strings.Join(request.Attributes, " ")
	}
	return encoder.textLine("attrs", attributes, false)
}

func (encoder *sockRequestEncoder) textLine(name, value string, allowEmpty bool) error {
	if (!allowEmpty && value == "") || containsLineBreakOrNUL([]byte(value)) {
		return sockProtocolError("%s contains an empty or unsafe line value", name)
	}
	return encoder.rawValueLine(name, []byte(value))
}

func (encoder *sockRequestEncoder) rawValueLine(name string, value []byte) error {
	line := make([]byte, 0, len(name)+2+len(value))
	line = append(line, name...)
	line = append(line, ':', ' ')
	line = append(line, value...)
	return encoder.line(line)
}

func (encoder *sockRequestEncoder) ldifValue(name string, value []byte, fold bool) error {
	if err := validateAttributeDescription(name); err != nil && !strings.EqualFold(name, "dn") {
		return err
	}
	prefix := name + ": "
	encoded := value
	if len(value) == 0 {
		return encoder.line([]byte(name + ":"))
	}
	if sockLDIFRequiresBase64(name, value) {
		prefix = name + ":: "
		encodedLength := base64.StdEncoding.EncodedLen(len(value))
		if int64(encodedLength) > encoder.limits.MaxRequestBytes {
			return sockLimitError("LDIF value exceeds request limit after base64 encoding")
		}
		encoded = make([]byte, encodedLength)
		base64.StdEncoding.Encode(encoded, value)
	}
	if !fold {
		line := make([]byte, 0, len(prefix)+len(encoded))
		line = append(line, prefix...)
		line = append(line, encoded...)
		return encoder.line(line)
	}
	return encoder.foldedLine([]byte(prefix), encoded)
}

func (encoder *sockRequestEncoder) foldedLine(prefix, value []byte) error {
	if len(prefix) >= sockLDIFLineWidth {
		return sockProtocolError("LDIF attribute prefix is too long to fold")
	}
	first := sockLDIFLineWidth - len(prefix)
	if len(value) <= first {
		line := append(bytes.Clone(prefix), value...)
		return encoder.line(line)
	}
	line := append(bytes.Clone(prefix), value[:first]...)
	if err := encoder.line(line); err != nil {
		return err
	}
	value = value[first:]
	for len(value) != 0 {
		count := sockLDIFLineWidth - 1
		if len(value) < count {
			count = len(value)
		}
		line = make([]byte, 1, count+1)
		line[0] = ' '
		line = append(line, value[:count]...)
		if err := encoder.line(line); err != nil {
			return err
		}
		value = value[count:]
	}
	return nil
}

func (encoder *sockRequestEncoder) line(value []byte) error {
	if len(value) > encoder.limits.MaxLineBytes {
		return sockLimitError("request line is %d bytes; maximum is %d", len(value), encoder.limits.MaxLineBytes)
	}
	additional := int64(len(value) + 1)
	if int64(encoder.output.Len()) > encoder.limits.MaxRequestBytes-additional {
		return sockLimitError("request exceeds %d bytes", encoder.limits.MaxRequestBytes)
	}
	encoder.output.Write(value)
	encoder.output.WriteByte('\n')
	return nil
}

func encodeSockFilter(filter directory.Filter) (string, error) {
	var output strings.Builder
	if err := appendSockFilter(&output, filter, 0); err != nil {
		return "", err
	}
	encoded := output.String()
	if _, err := ldapwire.CompileFilter(encoded); err != nil {
		return "", sockProtocolError("invalid RFC 4515 filter: %v", err)
	}
	return encoded, nil
}

func appendSockFilter(output *strings.Builder, filter directory.Filter, depth int) error {
	if depth > 64 {
		return sockProtocolError("filter nesting exceeds 64")
	}
	output.WriteByte('(')
	switch filter.Kind {
	case directory.FilterAnd, directory.FilterOr:
		if filter.Kind == directory.FilterAnd {
			output.WriteByte('&')
		} else {
			output.WriteByte('|')
		}
		for _, child := range filter.Children {
			if err := appendSockFilter(output, child, depth+1); err != nil {
				return err
			}
		}
	case directory.FilterNot:
		if len(filter.Children) != 1 {
			return sockProtocolError("NOT filter requires exactly one child")
		}
		output.WriteByte('!')
		if err := appendSockFilter(output, filter.Children[0], depth+1); err != nil {
			return err
		}
	case directory.FilterEquality, directory.FilterGreaterOrEqual,
		directory.FilterLessOrEqual, directory.FilterApprox:
		if err := validateAttributeDescription(filter.Attribute); err != nil {
			return err
		}
		output.WriteString(filter.Attribute)
		switch filter.Kind {
		case directory.FilterEquality:
			output.WriteByte('=')
		case directory.FilterGreaterOrEqual:
			output.WriteString(">=")
		case directory.FilterLessOrEqual:
			output.WriteString("<=")
		case directory.FilterApprox:
			output.WriteString("~=")
		}
		output.WriteString(ldap.EscapeFilter(string(filter.Assertion)))
	case directory.FilterPresent:
		if err := validateAttributeDescription(filter.Attribute); err != nil {
			return err
		}
		output.WriteString(filter.Attribute)
		output.WriteString("=*")
	case directory.FilterSubstrings:
		if err := validateAttributeDescription(filter.Attribute); err != nil {
			return err
		}
		if filter.Substring.Initial == nil && len(filter.Substring.Any) == 0 && filter.Substring.Final == nil {
			return sockProtocolError("substring filter has no components")
		}
		output.WriteString(filter.Attribute)
		output.WriteByte('=')
		if filter.Substring.Initial != nil {
			output.WriteString(ldap.EscapeFilter(string(filter.Substring.Initial)))
		}
		output.WriteByte('*')
		for _, part := range filter.Substring.Any {
			output.WriteString(ldap.EscapeFilter(string(part)))
			output.WriteByte('*')
		}
		if filter.Substring.Final != nil {
			output.WriteString(ldap.EscapeFilter(string(filter.Substring.Final)))
		}
	case directory.FilterExtensible:
		if filter.Attribute == "" && filter.MatchingRule == "" {
			return sockProtocolError("extensible filter has neither attribute nor matching rule")
		}
		if filter.Attribute != "" {
			if err := validateAttributeDescription(filter.Attribute); err != nil {
				return err
			}
			output.WriteString(filter.Attribute)
		}
		if filter.DNAttributes {
			output.WriteString(":dn")
		}
		if filter.MatchingRule != "" {
			if err := validateMatchingRule(filter.MatchingRule); err != nil {
				return err
			}
			output.WriteByte(':')
			output.WriteString(filter.MatchingRule)
		}
		output.WriteString(":=")
		output.WriteString(ldap.EscapeFilter(string(filter.Assertion)))
	default:
		return sockProtocolError("unknown filter kind %d", filter.Kind)
	}
	output.WriteByte(')')
	return nil
}

func readSockResponse(reader io.Reader, maximum int64) ([]byte, error) {
	limited := io.LimitReader(reader, maximum+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read back-sock response: %w", err)
	}
	if int64(len(data)) > maximum {
		return nil, sockLimitError("response exceeds %d bytes", maximum)
	}
	if len(data) == 0 {
		return nil, sockProtocolError("response is empty")
	}
	return data, nil
}

type sockResponseBlock struct {
	lines   [][]byte
	bytes   int
	folded  bool
	started bool
}

func parseSockResponse(data []byte, limits SockProtocolLimits) (SockResponse, error) {
	if data[len(data)-1] != '\n' {
		return SockResponse{}, sockProtocolError("response is truncated before a newline")
	}

	physicalLines := bytes.Split(data, []byte{'\n'})
	var response SockResponse
	var block sockResponseBlock
	resultSeen := false
	for index, raw := range physicalLines[:len(physicalLines)-1] {
		if resultSeen {
			return SockResponse{}, sockProtocolError("response has trailing data after RESULT")
		}
		if len(raw) > 0 && raw[len(raw)-1] == '\r' {
			raw = raw[:len(raw)-1]
		}
		if bytes.IndexByte(raw, '\r') >= 0 || bytes.IndexByte(raw, 0) >= 0 {
			return SockResponse{}, sockProtocolError("response line %d contains CR or NUL", index+1)
		}
		if len(raw) > limits.MaxLineBytes {
			return SockResponse{}, sockLimitError("response line %d is %d bytes; maximum is %d", index+1, len(raw), limits.MaxLineBytes)
		}
		if len(raw) != 0 && (raw[0] == '#' || hasASCIIPrefixFold(raw, []byte("DEBUG:"))) {
			continue
		}
		if len(raw) == 0 {
			if !block.started {
				continue
			}
			seen, err := finishSockResponseBlock(&response, block, limits)
			if err != nil {
				return SockResponse{}, err
			}
			resultSeen = seen
			block = sockResponseBlock{}
			continue
		}

		block.started = true
		block.bytes += len(raw) + 1
		if block.bytes > limits.MaxEntryBytes {
			return SockResponse{}, sockLimitError("response record exceeds %d bytes", limits.MaxEntryBytes)
		}
		if raw[0] == ' ' {
			if len(block.lines) == 0 {
				return SockResponse{}, sockProtocolError("response line %d is an orphan LDIF continuation", index+1)
			}
			block.lines[len(block.lines)-1] = append(block.lines[len(block.lines)-1], raw[1:]...)
			block.folded = true
			continue
		}
		block.lines = append(block.lines, bytes.Clone(raw))
	}
	if block.started {
		return SockResponse{}, sockProtocolError("response is truncated before the terminating blank line")
	}
	if !resultSeen {
		return SockResponse{}, sockProtocolError("response has no RESULT record")
	}
	return response, nil
}

func finishSockResponseBlock(response *SockResponse, block sockResponseBlock, limits SockProtocolLimits) (bool, error) {
	if len(block.lines) == 0 {
		return false, sockProtocolError("response record has no content")
	}
	if bytes.EqualFold(block.lines[0], []byte("RESULT")) {
		if block.folded {
			return false, sockProtocolError("RESULT fields must not use LDIF continuation lines")
		}
		result, err := parseSockResult(block.lines)
		if err != nil {
			return false, err
		}
		response.Result = result
		return true, nil
	}
	if len(response.Entries) >= limits.MaxEntries {
		return false, sockLimitError("response has more than %d entries", limits.MaxEntries)
	}
	entry, err := parseSockEntry(block.lines, limits)
	if err != nil {
		return false, err
	}
	response.Entries = append(response.Entries, entry)
	return false, nil
}

func parseSockResult(lines [][]byte) (ldapwire.Result, error) {
	var result ldapwire.Result
	seen := make(map[string]struct{}, 3)
	for _, line := range lines[1:] {
		name, value, err := parseSockResultLine(line)
		if err != nil {
			return ldapwire.Result{}, fmt.Errorf("RESULT: %w", err)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return ldapwire.Result{}, sockProtocolError("RESULT field %q is duplicated", name)
		}
		seen[key] = struct{}{}
		switch key {
		case "code":
			trimmed := strings.TrimSpace(string(value))
			if trimmed == "" {
				return ldapwire.Result{}, sockProtocolError("RESULT code is empty")
			}
			code, err := strconv.ParseInt(trimmed, 10, 32)
			if err != nil || code < 0 {
				return ldapwire.Result{}, sockProtocolError("RESULT code %q is invalid", value)
			}
			result.Code = ldapwire.ResultCode(code)
		case "matched":
			if !utf8.Valid(value) {
				return ldapwire.Result{}, sockProtocolError("RESULT matched DN is not UTF-8")
			}
			result.MatchedDN = string(value)
		case "info":
			if !utf8.Valid(value) {
				return ldapwire.Result{}, sockProtocolError("RESULT info is not UTF-8")
			}
			result.DiagnosticMessage = string(value)
		default:
			return ldapwire.Result{}, sockProtocolError("RESULT field %q is unknown", name)
		}
	}
	return result, nil
}

func parseSockResultLine(line []byte) (string, []byte, error) {
	separator := bytes.IndexByte(line, ':')
	if separator <= 0 {
		return "", nil, sockProtocolError("malformed RESULT line %q", line)
	}
	name := string(line[:separator])
	value := line[separator+1:]
	if len(value) != 0 && (value[0] == ':' || value[0] == '<') {
		return "", nil, sockProtocolError("RESULT field %q must be plain text", name)
	}
	if len(value) != 0 && value[0] == ' ' {
		value = value[1:]
	}
	return name, bytes.Clone(value), nil
}

func parseSockEntry(lines [][]byte, limits SockProtocolLimits) (directory.Entry, error) {
	if len(lines) == 0 {
		return directory.Entry{}, sockProtocolError("LDIF entry is empty")
	}
	name, value, _, err := parseSockLDIFLine(lines[0])
	if err != nil {
		return directory.Entry{}, fmt.Errorf("LDIF entry DN: %w", err)
	}
	if !strings.EqualFold(name, "dn") {
		return directory.Entry{}, sockProtocolError("LDIF entry starts with %q instead of dn", name)
	}
	if !utf8.Valid(value) {
		return directory.Entry{}, sockProtocolError("LDIF entry DN is not UTF-8")
	}
	if containsLineBreakOrNUL(value) {
		return directory.Entry{}, sockProtocolError("LDIF entry DN contains NUL, CR, or LF")
	}
	entry := directory.Entry{DN: string(value)}
	values := 0
	for _, line := range lines[1:] {
		name, value, _, err = parseSockLDIFLine(line)
		if err != nil {
			return directory.Entry{}, fmt.Errorf("LDIF entry %q: %w", entry.DN, err)
		}
		if strings.EqualFold(name, "dn") {
			return directory.Entry{}, sockProtocolError("LDIF entry %q contains a second dn", entry.DN)
		}
		if err := validateAttributeDescription(name); err != nil {
			return directory.Entry{}, fmt.Errorf("LDIF entry %q: %w", entry.DN, err)
		}
		values++
		if values > limits.MaxValues {
			return directory.Entry{}, sockLimitError("LDIF entry %q has more than %d values", entry.DN, limits.MaxValues)
		}
		attributeIndex := -1
		for index := range entry.Attributes {
			if strings.EqualFold(entry.Attributes[index].Description, name) {
				attributeIndex = index
				break
			}
		}
		if attributeIndex < 0 {
			if len(entry.Attributes) >= limits.MaxAttributes {
				return directory.Entry{}, sockLimitError("LDIF entry %q has more than %d attributes", entry.DN, limits.MaxAttributes)
			}
			entry.Attributes = append(entry.Attributes, directory.Attribute{Description: name})
			attributeIndex = len(entry.Attributes) - 1
		}
		entry.Attributes[attributeIndex].Values = append(entry.Attributes[attributeIndex].Values, bytes.Clone(value))
	}
	return entry, nil
}

func parseSockLDIFLine(line []byte) (string, []byte, bool, error) {
	separator := bytes.IndexByte(line, ':')
	if separator <= 0 {
		return "", nil, false, sockProtocolError("malformed LDIF line %q", line)
	}
	name := string(line[:separator])
	value := line[separator+1:]
	base64Encoded := false
	if len(value) != 0 && value[0] == ':' {
		base64Encoded = true
		value = value[1:]
	} else if len(value) != 0 && value[0] == '<' {
		return "", nil, false, sockProtocolError("LDIF URL values are not accepted")
	}
	if len(value) != 0 && value[0] == ' ' {
		value = value[1:]
	}
	if base64Encoded {
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(value)))
		count, err := base64.StdEncoding.Strict().Decode(decoded, value)
		if err != nil {
			return "", nil, false, sockProtocolError("LDIF field %q has invalid base64: %v", name, err)
		}
		value = decoded[:count]
	} else if len(value) != 0 && sockLDIFRequiresBase64(name, value) {
		return "", nil, false, sockProtocolError("LDIF field %q uses an unsafe value without base64", name)
	}
	return name, bytes.Clone(value), base64Encoded, nil
}

func sockLDIFRequiresBase64(name string, value []byte) bool {
	if len(value) == 0 {
		return false
	}
	base := name
	if separator := strings.IndexByte(base, ';'); separator >= 0 {
		base = base[:separator]
	}
	if strings.EqualFold(base, "userPassword") || base == "2.5.4.35" ||
		strings.Contains(strings.ToLower(name), ";binary") {
		return true
	}
	if !sockLDIFGraph(value[0]) || value[0] == ':' || value[0] == '<' || !sockLDIFGraph(value[len(value)-1]) {
		return true
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return true
		}
	}
	return false
}

func sockLDIFGraph(value byte) bool {
	return value > 0x20 && value <= 0x7e
}

func validateAttributeDescription(value string) error {
	if value == "" || containsLineBreakOrNUL([]byte(value)) {
		return sockProtocolError("attribute description %q is empty or unsafe", value)
	}
	parts := strings.Split(value, ";")
	if !validKeyString(parts[0], true) {
		return sockProtocolError("attribute description %q is invalid", value)
	}
	for _, option := range parts[1:] {
		if !validKeyString(option, false) {
			return sockProtocolError("attribute option %q is invalid", option)
		}
	}
	return nil
}

func validateAttributeSelector(value string) error {
	if value == "*" || value == "+" || value == "1.1" {
		return nil
	}
	if len(value) > 1 && (value[0] == '@' || value[0] == '!' || value[0] == '+') {
		if validKeyString(value[1:], true) {
			return nil
		}
		return sockProtocolError("object class attribute selector %q is invalid", value)
	}
	return validateAttributeDescription(value)
}

func validateMatchingRule(value string) error {
	if !validKeyString(value, true) {
		return sockProtocolError("matching rule %q is invalid", value)
	}
	return nil
}

func validKeyString(value string, numericAllowed bool) bool {
	if value == "" {
		return false
	}
	if numericAllowed && value[0] >= '0' && value[0] <= '9' {
		return validNumericOID(value)
	}
	if !isASCIIAlpha(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !isASCIIAlpha(character) && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validNumericOID(value string) bool {
	if value == "" || value[0] == '.' || value[len(value)-1] == '.' {
		return false
	}
	components := strings.Split(value, ".")
	if len(components) < 2 {
		return false
	}
	for _, component := range components {
		if component == "" || (len(component) > 1 && component[0] == '0') {
			return false
		}
		for index := range component {
			if component[index] < '0' || component[index] > '9' {
				return false
			}
		}
	}
	return true
}

func isASCIIAlpha(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func containsLineBreakOrNUL(value []byte) bool {
	return bytes.IndexByte(value, 0) >= 0 || bytes.IndexByte(value, '\r') >= 0 || bytes.IndexByte(value, '\n') >= 0
}

func hasASCIIPrefixFold(value, prefix []byte) bool {
	if len(value) < len(prefix) {
		return false
	}
	return bytes.EqualFold(value[:len(prefix)], prefix)
}

func (limits SockProtocolLimits) withDefaults() SockProtocolLimits {
	if limits.MaxRequestBytes == 0 {
		limits.MaxRequestBytes = SockDefaultMaxRequestBytes
	}
	if limits.MaxResponseBytes == 0 {
		limits.MaxResponseBytes = SockDefaultMaxResponseBytes
	}
	if limits.MaxLineBytes == 0 {
		limits.MaxLineBytes = SockDefaultMaxLineBytes
	}
	if limits.MaxEntryBytes == 0 {
		limits.MaxEntryBytes = SockDefaultMaxEntryBytes
	}
	if limits.MaxEntries == 0 {
		limits.MaxEntries = SockDefaultMaxEntries
	}
	if limits.MaxAttributes == 0 {
		limits.MaxAttributes = SockDefaultMaxAttributes
	}
	if limits.MaxValues == 0 {
		limits.MaxValues = SockDefaultMaxValues
	}
	return limits
}

func (limits SockProtocolLimits) validate() error {
	if limits.MaxRequestBytes <= 0 || limits.MaxResponseBytes <= 0 || limits.MaxLineBytes <= 0 ||
		limits.MaxEntryBytes <= 0 || limits.MaxEntries <= 0 || limits.MaxAttributes <= 0 || limits.MaxValues <= 0 {
		return sockProtocolError("protocol limits must all be positive")
	}
	if int64(limits.MaxLineBytes) > limits.MaxResponseBytes || int64(limits.MaxEntryBytes) > limits.MaxResponseBytes {
		return sockProtocolError("line and entry limits must not exceed the response limit")
	}
	if limits.MaxResponseBytes == math.MaxInt64 {
		return sockProtocolError("response limit is too large")
	}
	return nil
}

func sockProtocolError(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrSockProtocol, fmt.Sprintf(format, arguments...))
}

func sockLimitError(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrSockProtocolLimit, fmt.Sprintf(format, arguments...))
}

func writeAll(writer io.Writer, value []byte) error {
	buffered := bufio.NewWriter(writer)
	if _, err := buffered.Write(value); err != nil {
		return err
	}
	return buffered.Flush()
}
