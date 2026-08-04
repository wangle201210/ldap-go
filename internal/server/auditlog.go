package server

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
)

const auditlogLDIFLineWidth = 78

type auditlogRuntimeConfiguration struct {
	filename string
}

type auditlogPendingRecord struct {
	filename        string
	operation       accesslogOperation
	suffix          string
	authorizationDN string
	realDN          string
	peerName        string
	connectionID    uint64
	requestDN       string
	after           *directory.Entry
	modifications   []ldapwire.Modification
	newRDN          string
	deleteOldRDN    bool
	newSuperior     string
	registry        *schema.Registry
}

func loadAuditlogRuntimeConfiguration(
	entry directory.Entry,
) (auditlogRuntimeConfiguration, error) {
	values := entry.Values("olcAuditlogFile")
	if len(values) > 1 {
		return auditlogRuntimeConfiguration{}, fmt.Errorf(
			"%s olcAuditlogFile must be single-valued",
			entry.DN,
		)
	}
	if len(values) == 0 {
		return auditlogRuntimeConfiguration{}, nil
	}
	filename := string(values[0])
	if filename == "" || strings.IndexByte(filename, 0) >= 0 {
		return auditlogRuntimeConfiguration{}, fmt.Errorf(
			"%s olcAuditlogFile has invalid filename %q",
			entry.DN,
			filename,
		)
	}
	return auditlogRuntimeConfiguration{filename: filename}, nil
}

func (server *Server) finishAuditlogWrite(
	state *connectionState,
	source runtimeDatabase,
	record accesslogWriteRecord,
) {
	configurations := auditlogConfigurations(state.runtime, source)
	if len(configurations) == 0 {
		return
	}

	suffix := "global"
	if len(source.suffixes) > 0 && source.suffixes[0].Depth() > 0 {
		suffix = source.suffixes[0].String()
	}
	realDN := state.operationRealDN
	if realDN == "" {
		realDN = state.boundDN
	}
	pending := auditlogPendingRecord{
		operation:       record.operation,
		suffix:          suffix,
		authorizationDN: auditlogAuthorizationDN(record),
		realDN:          realDN,
		peerName:        auditlogPeerName(state.connection),
		connectionID:    state.connectionID,
		requestDN:       record.requestDN.String(),
		modifications:   auditlogCompleteModifications(state.runtime.schema, record),
		newRDN:          record.newRDN,
		deleteOldRDN:    record.deleteOldRDN,
		registry:        state.runtime.schema,
	}
	if record.after != nil {
		entry := record.after.Clone()
		pending.after = &entry
	}
	if record.newSuperior != nil {
		pending.newSuperior = record.newSuperior.String()
	}

	records := make([]auditlogPendingRecord, 0, len(configurations))
	for _, configuration := range configurations {
		pending.filename = configuration.filename
		records = append(records, pending)
	}
	server.appendAuditlogRecords(records)
}

func auditlogConfigurations(
	runtime *runtimeState,
	source runtimeDatabase,
) []*auditlogRuntimeConfiguration {
	configurations := make([]*auditlogRuntimeConfiguration, 0, 2)
	if source.auditlog != nil && source.auditlog.filename != "" {
		configurations = append(configurations, source.auditlog)
	}
	if runtime == nil || databaseType(source.name) == "frontend" {
		return configurations
	}
	for index := range runtime.databases {
		database := &runtime.databases[index]
		if databaseType(database.name) == "frontend" &&
			database.auditlog != nil && database.auditlog.filename != "" {
			configurations = append(configurations, database.auditlog)
			break
		}
	}
	return configurations
}

func auditlogAuthorizationDN(record accesslogWriteRecord) string {
	if record.operation != accesslogAdd && record.operation != accesslogModify {
		return record.authorizationDN
	}
	if record.operation == accesslogModify {
		for _, modification := range record.modifications {
			if !strings.EqualFold(
				auditlogBaseAttributeDescription(modification.Attribute.Description),
				"modifiersName",
			) || (modification.Operation != ldapwire.ModificationAdd &&
				modification.Operation != ldapwire.ModificationReplace) ||
				len(modification.Attribute.Values) == 0 {
				continue
			}
			return string(modification.Attribute.Values[0])
		}
	}
	if record.after != nil {
		values := record.after.Values("modifiersName")
		if len(values) > 0 {
			return string(values[0])
		}
	}
	return record.authorizationDN
}

func auditlogPeerName(connection net.Conn) string {
	if connection == nil || connection.RemoteAddr() == nil {
		return ""
	}
	address := connection.RemoteAddr()
	switch {
	case strings.HasPrefix(strings.ToLower(address.Network()), "tcp"):
		return "IP=" + address.String()
	case strings.HasPrefix(strings.ToLower(address.Network()), "unix"):
		return "PATH=" + address.String()
	default:
		return address.String()
	}
}

func (server *Server) appendAuditlogRecords(records []auditlogPendingRecord) {
	if len(records) == 0 {
		return
	}
	server.auditlogMu.Lock()
	defer server.auditlogMu.Unlock()

	for _, record := range records {
		if err := appendAuditlogRecord(record); err != nil {
			server.config.Logger.Error(
				"write OpenLDAP auditlog record",
				"filename",
				record.filename,
				"error",
				err,
			)
		}
	}
}

func appendAuditlogRecord(record auditlogPendingRecord) error {
	file, err := os.OpenFile(
		record.filename,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0o666,
	)
	if err != nil {
		return err
	}
	data := renderAuditlogRecord(record, time.Now().Unix())
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func renderAuditlogRecord(record auditlogPendingRecord, timestamp int64) []byte {
	operation := accesslogOperationName(record.operation)
	var output bytes.Buffer
	fmt.Fprintf(
		&output,
		"# %s %d %s %s %s conn=%d\n",
		operation,
		timestamp,
		record.suffix,
		record.authorizationDN,
		record.peerName,
		record.connectionID,
	)
	if record.realDN != "" && !auditlogDNEqual(record.realDN, record.authorizationDN) {
		fmt.Fprintf(&output, "# realdn: %s\n", record.realDN)
	}
	fmt.Fprintf(
		&output,
		"dn: %s\nchangetype: %s\n",
		record.requestDN,
		operation,
	)

	switch record.operation {
	case accesslogAdd:
		if record.after != nil {
			for _, attribute := range record.after.Attributes {
				name := auditlogAttributeName(record.registry, attribute.Description)
				if strings.EqualFold(
					auditlogBaseAttributeDescription(name),
					"subschemaSubentry",
				) {
					continue
				}
				for _, value := range attribute.Values {
					writeAuditlogLDIFValue(&output, name, value)
				}
			}
		}
	case accesslogModify:
		for _, modification := range record.modifications {
			name := auditlogAttributeName(
				record.registry,
				modification.Attribute.Description,
			)
			operationName := auditlogModificationName(modification.Operation)
			if operationName == "" {
				fmt.Fprintf(&output, "# MOD_TYPE_UNKNOWN:%02x\n", modification.Operation)
				continue
			}
			fmt.Fprintf(&output, "%s: %s\n", operationName, name)
			for _, value := range modification.Attribute.Values {
				writeAuditlogLDIFValue(&output, name, value)
			}
			output.WriteString("-\n")
		}
	case accesslogModifyDN:
		deleteOldRDN := "0"
		if record.deleteOldRDN {
			deleteOldRDN = "1"
		}
		fmt.Fprintf(
			&output,
			"newrdn: %s\ndeleteoldrdn: %s\n",
			record.newRDN,
			deleteOldRDN,
		)
		if record.newSuperior != "" {
			fmt.Fprintf(&output, "newsuperior: %s\n", record.newSuperior)
		}
	}
	fmt.Fprintf(&output, "# end %s %d\n\n", operation, timestamp)
	return output.Bytes()
}

func auditlogModificationName(operation ldapwire.ModificationOperation) string {
	switch operation {
	case ldapwire.ModificationAdd:
		return "add"
	case ldapwire.ModificationDelete:
		return "delete"
	case ldapwire.ModificationReplace:
		return "replace"
	case ldapwire.ModificationIncrement:
		return "increment"
	default:
		return ""
	}
}

func auditlogCompleteModifications(
	registry *schema.Registry,
	record accesslogWriteRecord,
) []ldapwire.Modification {
	modifications := cloneLDAPModifications(record.modifications)
	if record.operation != accesslogModify || record.before == nil || record.after == nil {
		return modifications
	}

	touched := make(map[string]struct{}, len(modifications))
	for _, modification := range modifications {
		touched[auditlogAttributeKey(registry, modification.Attribute.Description)] = struct{}{}
	}
	before := auditlogAttributeMap(registry, record.before)
	after := auditlogAttributeMap(registry, record.after)
	keys := make(map[string]struct{}, len(before)+len(after))
	for key := range before {
		keys[key] = struct{}{}
	}
	for key := range after {
		keys[key] = struct{}{}
	}

	appendDifference := func(key string, force bool) {
		if _, exists := touched[key]; exists {
			return
		}
		beforeAttribute, beforeExists := before[key]
		afterAttribute, afterExists := after[key]
		if key == auditlogAttributeKey(registry, "subschemaSubentry") ||
			(key == auditlogAttributeKey(registry, "structuralObjectClass") &&
				!beforeExists && afterExists) {
			return
		}
		if !force && beforeExists && afterExists &&
			accesslogValuesEqual(beforeAttribute.Values, afterAttribute.Values) {
			return
		}
		if !beforeExists && !afterExists {
			return
		}
		description := beforeAttribute.Description
		values := [][]byte(nil)
		if afterExists {
			description = afterAttribute.Description
			values = afterAttribute.Values
		}
		modifications = append(modifications, ldapwire.Modification{
			Operation: ldapwire.ModificationReplace,
			Attribute: directory.Attribute{
				Description: description,
				Values:      cloneAuditlogValues(values),
			},
		})
		touched[key] = struct{}{}
	}

	entryCSNKey := auditlogAttributeKey(registry, "entryCSN")
	beforeCSN, hadBeforeCSN := before[entryCSNKey]
	afterCSN, hasAfterCSN := after[entryCSNKey]
	lastModApplied := hasAfterCSN && (!hadBeforeCSN ||
		!accesslogValuesEqual(beforeCSN.Values, afterCSN.Values))
	for _, description := range []string{
		"entryCSN",
		"modifiersName",
		"modifyTimestamp",
	} {
		appendDifference(auditlogAttributeKey(registry, description), lastModApplied)
	}
	remaining := make([]string, 0, len(keys))
	for key := range keys {
		if _, exists := touched[key]; !exists {
			remaining = append(remaining, key)
		}
	}
	sort.Strings(remaining)
	for _, key := range remaining {
		appendDifference(key, false)
	}
	return modifications
}

func auditlogAttributeMap(
	registry *schema.Registry,
	entry *directory.Entry,
) map[string]directory.Attribute {
	result := make(map[string]directory.Attribute)
	if entry == nil {
		return result
	}
	for _, attribute := range entry.Attributes {
		result[auditlogAttributeKey(registry, attribute.Description)] = attribute
	}
	return result
}

func auditlogAttributeKey(registry *schema.Registry, description string) string {
	base := auditlogBaseAttributeDescription(description)
	if registry != nil {
		if attribute, ok := registry.AttributeType(base); ok {
			base = attribute.OID
		}
	}
	options := ""
	if separator := strings.IndexByte(description, ';'); separator >= 0 {
		options = description[separator:]
	}
	return strings.ToLower(base + options)
}

func cloneAuditlogValues(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index, value := range values {
		cloned[index] = bytes.Clone(value)
	}
	return cloned
}

func auditlogAttributeName(registry *schema.Registry, description string) string {
	base := auditlogBaseAttributeDescription(description)
	name := base
	if registry != nil {
		if attribute, ok := registry.AttributeType(base); ok {
			name = attribute.Name()
		}
	}
	if separator := strings.IndexByte(description, ';'); separator >= 0 {
		name += description[separator:]
	}
	return name
}

func auditlogBaseAttributeDescription(description string) string {
	if separator := strings.IndexByte(description, ';'); separator >= 0 {
		return description[:separator]
	}
	return description
}

func writeAuditlogLDIFValue(output *bytes.Buffer, name string, value []byte) {
	if len(value) == 0 {
		output.WriteString(name)
		output.WriteString(":\n")
		return
	}
	prefix := name + ": "
	encoded := value
	if auditlogValueRequiresBase64(name, value) {
		prefix = name + ":: "
		encoded = []byte(base64.StdEncoding.EncodeToString(value))
	}
	writeAuditlogFoldedLine(output, prefix, encoded)
}

func auditlogValueRequiresBase64(name string, value []byte) bool {
	base := auditlogBaseAttributeDescription(name)
	if strings.EqualFold(base, "userPassword") ||
		base == "2.5.4.35" ||
		strings.Contains(strings.ToLower(name), ";binary") {
		return true
	}
	if !auditlogGraph(value[0]) || value[0] == ':' || value[0] == '<' ||
		!auditlogGraph(value[len(value)-1]) {
		return true
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return true
		}
	}
	return false
}

func auditlogGraph(value byte) bool {
	return value > 0x20 && value <= 0x7e
}

func writeAuditlogFoldedLine(output *bytes.Buffer, prefix string, value []byte) {
	line := append([]byte(prefix), value...)
	if len(line) <= auditlogLDIFLineWidth {
		output.Write(line)
		output.WriteByte('\n')
		return
	}
	output.Write(line[:auditlogLDIFLineWidth])
	line = line[auditlogLDIFLineWidth:]
	for len(line) > 0 {
		output.WriteString("\n ")
		width := auditlogLDIFLineWidth - 1
		if len(line) < width {
			width = len(line)
		}
		output.Write(line[:width])
		line = line[width:]
	}
	output.WriteByte('\n')
}

func auditlogDNEqual(left, right string) bool {
	leftDN, leftErr := directory.ParseDN(left)
	rightDN, rightErr := directory.ParseDN(right)
	if leftErr == nil && rightErr == nil {
		return leftDN.Equal(rightDN)
	}
	return strings.EqualFold(left, right)
}
