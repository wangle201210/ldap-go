package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
)

const (
	maxLDAPWriteInputSize   = 64 << 20
	maxLDAPWriteRecordSize  = 8 << 20
	maxLDAPWriteLineSize    = 1 << 20
	maxLDAPWriteRecords     = 100_000
	recursiveDeletePageSize = 500
)

type ldapWriteOperationKind uint8

const (
	ldapWriteAdd ldapWriteOperationKind = iota + 1
	ldapWriteModify
	ldapWriteDelete
	ldapWriteModifyDN
)

type ldapWriteOperation struct {
	kind           ldapWriteOperationKind
	add            *ldap.AddRequest
	modify         *ldap.ModifyRequest
	delete         *ldap.DelRequest
	modifyDN       *ldap.ModifyDNRequest
	recordControls []ldap.Control
}

func (operation *ldapWriteOperation) dn() string {
	if operation == nil {
		return ""
	}
	switch operation.kind {
	case ldapWriteAdd:
		return operation.add.DN
	case ldapWriteModify:
		return operation.modify.DN
	case ldapWriteDelete:
		return operation.delete.DN
	case ldapWriteModifyDN:
		return operation.modifyDN.DN
	default:
		return ""
	}
}

func (operation *ldapWriteOperation) name() string {
	if operation == nil {
		return "operation"
	}
	switch operation.kind {
	case ldapWriteAdd:
		return "add"
	case ldapWriteModify:
		return "modify"
	case ldapWriteDelete:
		return "delete"
	case ldapWriteModifyDN:
		return "modify DN"
	default:
		return "operation"
	}
}

func (operation *ldapWriteOperation) execute(connection *ldap.Conn) error {
	switch operation.kind {
	case ldapWriteAdd:
		return connection.Add(operation.add)
	case ldapWriteModify:
		return connection.Modify(operation.modify)
	case ldapWriteDelete:
		return connection.Del(operation.delete)
	case ldapWriteModifyDN:
		return connection.ModifyDN(operation.modifyDN)
	default:
		return errors.New("unknown LDAP write operation")
	}
}

func (operation *ldapWriteOperation) setControls(controls []ldap.Control) {
	if operation == nil {
		return
	}
	combined := make([]ldap.Control, 0, len(operation.recordControls)+len(controls))
	combined = append(combined, operation.recordControls...)
	combined = append(combined, controls...)
	switch operation.kind {
	case ldapWriteAdd:
		operation.add.Controls = combined
	case ldapWriteModify:
		operation.modify.Controls = combined
	case ldapWriteDelete:
		operation.delete.Controls = combined
	case ldapWriteModifyDN:
		operation.modifyDN.Controls = combined
	}
}

func (operation *ldapWriteOperation) clearRecordControls() {
	if operation == nil {
		return
	}
	clearLDAPControls(operation.recordControls)
	operation.recordControls = nil
}

type ldapWriteParseState struct {
	sawVersion   bool
	sawOperation bool
}

type ldapWriteFailureFile struct {
	root      *os.Root
	file      *os.File
	temporary string
	target    string
	records   int
	failed    bool
}

func runLDAPModify(
	command string,
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) (runErr error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var client ldapClientOptions
	client.register(flags)
	client.unsupportedFlags = withoutLDAPClientUnsupportedFlag(client.unsupportedFlags, "M")
	client.unsupportedFlags = withoutLDAPClientUnsupportedFlag(client.unsupportedFlags, "v")
	flags.Lookup("M").Usage = "enable ManageDsaIT control"
	flags.Lookup("v").Usage = "write verbose operation diagnostics"
	defer client.clear()

	inputPath := flags.String("f", "", "read LDIF from a file instead of stdin")
	resumeLine := flags.Int("j", 0, "skip records beginning before this physical line")
	continueOnError := flags.Bool("c", false, "continue after failed records")
	failurePath := flags.String("S", "", "write failed records as LDIF")
	addMode := false
	var extensions repeatedStringFlag
	flags.Var(&extensions, "E", "operation control: [!]<oid>[=:<string>|::<base64>|:<file URI>]")
	if command == "ldapmodify" {
		flags.BoolVar(&addMode, "a", false, "treat content records as Add requests")
	}
	criticalManageDsaIT := flags.Bool("MM", false, "critical ManageDsaIT control")

	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	manageDsaIT, err := ldapBooleanFlagValue(flags, "M")
	if err != nil {
		return err
	}
	verbose, err := ldapBooleanFlagValue(flags, "v")
	if err != nil {
		return err
	}
	if flagWasSet(flags, "M") && !manageDsaIT {
		return errors.New("-M=false is not supported")
	}
	if flagWasSet(flags, "MM") && !*criticalManageDsaIT {
		return errors.New("-MM=false is not supported")
	}
	if flagWasSet(flags, "v") && !verbose {
		return errors.New("-v=false is not supported")
	}
	manageDsaITCount := 0
	for _, argument := range args {
		if argument == "-M" {
			manageDsaITCount++
		}
	}
	manageDsaITCritical := *criticalManageDsaIT || manageDsaITCount > 1
	if err := client.validateWrite(flags); err != nil {
		return err
	}
	if err := rejectUnsupportedFlags(command, flags, nil); err != nil {
		return err
	}
	extensionControls, err := parseLDAPControlSpecs(extensions, ldapControlValueLDIF)
	if err != nil {
		return fmt.Errorf("%s -E: %w", command, err)
	}
	defer clearLDAPControls(extensionControls)
	controlGroups := [][]ldap.Control{client.generalControls, extensionControls}
	if manageDsaIT || *criticalManageDsaIT {
		controlGroups = append(controlGroups, []ldap.Control{&ldapRawControl{
			oid:      ldapManageDsaITOID,
			critical: manageDsaITCritical,
		}})
	}
	controls, err := mergeLDAPControls(controlGroups...)
	if err != nil {
		return fmt.Errorf("%s controls: %w", command, err)
	}
	if flagWasSet(flags, "c") && !*continueOnError {
		return errors.New("-c=false is not supported")
	}
	if flagWasSet(flags, "a") && !addMode {
		return errors.New("-a=false is not supported")
	}
	if flagWasSet(flags, "f") && *inputPath == "" {
		return errors.New("-f requires a non-empty path or - for stdin")
	}
	if flagWasSet(flags, "S") && *failurePath == "" {
		return errors.New("-S requires a non-empty output path")
	}
	if *resumeLine < 0 {
		return errors.New("-j requires a non-negative line number")
	}

	failureFile, err := openLDAPWriteFailureFile(*failurePath, *inputPath)
	if err != nil {
		return err
	}
	if failureFile != nil {
		defer func() {
			runErr = errors.Join(runErr, failureFile.Close())
		}()
	}

	var connection *ldap.Conn
	if !client.dryRun {
		if verbose {
			if _, err := fmt.Fprintf(
				stderr,
				"ldap_initialize( %s/??base )\n",
				strings.TrimSuffix(client.uri, "/"),
			); err != nil {
				return err
			}
		}
		connection, err = client.connectAndBind(flags, stdin, stderr)
		if err != nil {
			return err
		}
		defer connection.Close()
	}

	input, err := readLDAPWriteSource(*inputPath, stdin)
	if err != nil {
		return err
	}
	defer clear(input)
	records, err := splitLDAPWriteRecordsWithLines(input)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return errors.New("LDIF input contains no records")
	}

	state := ldapWriteParseState{}
	succeeded := 0
	failed := 0
	processed := 0
	var firstFailure error
	allowContentAdd := command == "ldapadd" || addMode
	for index, record := range records {
		if record.line < *resumeLine {
			continue
		}
		processed++
		operation, parseErr := parseLDAPWriteRecord(
			record.raw,
			allowContentAdd,
			&state,
		)
		if parseErr != nil {
			return fmt.Errorf("record %d: %w", index+1, parseErr)
		}
		if operation == nil {
			continue
		}
		operation.setControls(controls)
		if verbose {
			if err := writeLDAPModifyVerboseOperation(stdout, operation, client.dryRun); err != nil {
				operation.clearRecordControls()
				return err
			}
		}
		if !client.dryRun {
			if executeErr := client.executeWriteWithReferrals(connection, operation); executeErr != nil {
				parseErr = fmt.Errorf(
					"%s %q: %w",
					operation.name(),
					operation.dn(),
					executeErr,
				)
			}
		}
		if parseErr == nil {
			if verbose && !client.dryRun {
				if err := writeLDAPModifyVerboseCompletion(stdout, operation); err != nil {
					operation.clearRecordControls()
					return err
				}
			}
			if verbose {
				if _, err := fmt.Fprintln(stdout); err != nil {
					operation.clearRecordControls()
					return err
				}
			}
			succeeded++
			operation.clearRecordControls()
			continue
		}
		if verbose {
			if _, err := fmt.Fprintln(stdout); err != nil {
				operation.clearRecordControls()
				return errors.Join(parseErr, err)
			}
		}

		failed++
		if firstFailure == nil {
			firstFailure = fmt.Errorf("record %d: %w", index+1, parseErr)
		}
		if failureFile != nil {
			err = failureFile.WriteOperation(operation)
			if err != nil {
				operation.clearRecordControls()
				return errors.Join(firstFailure, err)
			}
		}
		operation.clearRecordControls()
		if !*continueOnError {
			break
		}
	}

	if !verbose {
		action := "applied"
		if client.dryRun {
			action = "validated"
		}
		if _, err := fmt.Fprintf(
			stdout,
			"%s: %s %d record(s), %d failed\n",
			command,
			action,
			succeeded,
			failed,
		); err != nil {
			return errors.Join(firstFailure, err)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d record(s) failed: %w", failed, firstFailure)
	}
	if processed == 0 && *resumeLine > 0 {
		return nil
	}
	if succeeded == 0 {
		return errors.New("LDIF input contains no operations")
	}
	return nil
}

func writeLDAPModifyVerboseOperation(
	writer io.Writer,
	operation *ldapWriteOperation,
	dryRun bool,
) error {
	if operation == nil {
		return errors.New("cannot render a nil LDAP write operation")
	}
	prefix := ""
	if dryRun {
		prefix = "!"
	}
	switch operation.kind {
	case ldapWriteAdd:
		for _, attribute := range operation.add.Attributes {
			if err := writeLDAPModifyVerboseAttribute(
				writer,
				"add",
				attribute.Type,
				attribute.Vals,
			); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintf(writer, "%sadding new entry %q\n", prefix, operation.add.DN)
		return err
	case ldapWriteModify:
		for _, change := range operation.modify.Changes {
			name := "unknown"
			switch change.Operation {
			case ldap.AddAttribute:
				name = "add"
			case ldap.DeleteAttribute:
				name = "delete"
			case ldap.ReplaceAttribute:
				name = "replace"
			case ldap.IncrementAttribute:
				name = "increment"
			}
			if err := writeLDAPModifyVerboseAttribute(
				writer,
				name,
				change.Modification.Type,
				change.Modification.Vals,
			); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintf(writer, "%smodifying entry %q\n", prefix, operation.modify.DN)
		return err
	case ldapWriteDelete:
		_, err := fmt.Fprintf(writer, "%sdeleting entry %q\n", prefix, operation.delete.DN)
		return err
	case ldapWriteModifyDN:
		if _, err := fmt.Fprintf(
			writer,
			"%smodifying rdn of entry %q\n",
			prefix,
			operation.modifyDN.DN,
		); err != nil {
			return err
		}
		keep := ""
		if operation.modifyDN.DeleteOldRDN {
			keep = "do not "
		}
		_, err := fmt.Fprintf(
			writer,
			"\tnew RDN: %q (%skeep existing values)\n",
			operation.modifyDN.NewRDN,
			keep,
		)
		return err
	default:
		return errors.New("cannot render an unknown LDAP write operation")
	}
}

func writeLDAPModifyVerboseAttribute(
	writer io.Writer,
	operation, attribute string,
	values []string,
) error {
	if _, err := fmt.Fprintf(writer, "%s %s:\n", operation, attribute); err != nil {
		return err
	}
	for _, value := range values {
		ascii := true
		for index := 0; index < len(value); index++ {
			if value[index] > 0x7f {
				ascii = false
				break
			}
		}
		if !ascii {
			if _, err := fmt.Fprintf(writer, "\tNOT ASCII (%d bytes)\n", len(value)); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(writer, "\t%s\n", value); err != nil {
			return err
		}
	}
	return nil
}

func writeLDAPModifyVerboseCompletion(
	writer io.Writer,
	operation *ldapWriteOperation,
) error {
	completion := "modify complete"
	switch operation.kind {
	case ldapWriteAdd, ldapWriteModify:
	case ldapWriteDelete:
		completion = "delete complete"
	case ldapWriteModifyDN:
		completion = "rename complete"
	default:
		return errors.New("cannot complete an unknown LDAP write operation")
	}
	_, err := fmt.Fprintln(writer, completion)
	return err
}

func runLDAPDelete(
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	flags := flag.NewFlagSet("ldapdelete", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var client ldapClientOptions
	client.register(flags)
	defer client.clear()
	inputPath := flags.String("f", "", "read one DN per line from a file")
	recursive := flags.Bool("r", false, "recursively delete each DN")
	var extensions repeatedStringFlag
	flags.Var(&extensions, "E", "operation control: [!]<oid>[=:<string>|::<base64>|:<file URI>]")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := client.validateWrite(flags); err != nil {
		return err
	}
	extensionControls, err := parseLDAPControlSpecs(extensions, ldapControlValueLDIF)
	if err != nil {
		return fmt.Errorf("ldapdelete -E: %w", err)
	}
	defer clearLDAPControls(extensionControls)
	controls, err := mergeLDAPControls(client.generalControls, extensionControls)
	if err != nil {
		return fmt.Errorf("ldapdelete controls: %w", err)
	}
	if err := rejectUnsupportedFlags("ldapdelete", flags, nil); err != nil {
		return err
	}
	if flagWasSet(flags, "r") && !*recursive {
		return errors.New("-r=false is not supported")
	}
	if flagWasSet(flags, "f") && *inputPath == "" {
		return errors.New("-f requires a non-empty path or - for stdin")
	}
	if flagWasSet(flags, "f") && flags.NArg() != 0 {
		return errors.New("ldapdelete DN arguments and -f are mutually exclusive")
	}

	var connection *ldap.Conn
	if !client.dryRun {
		var err error
		connection, err = client.connectAndBind(flags, stdin, stderr)
		if err != nil {
			return err
		}
		defer connection.Close()
	}

	dns := append([]string(nil), flags.Args()...)
	if len(dns) == 0 {
		input, err := readLDAPWriteSource(*inputPath, stdin)
		if err != nil {
			return err
		}
		defer clear(input)
		dns, err = parseLDAPWriteLineInput(input)
		if err != nil {
			return err
		}
	}
	if len(dns) == 0 {
		return errors.New("ldapdelete requires at least one DN")
	}
	for _, dn := range dns {
		if err := validateLDAPWriteDN(dn); err != nil {
			return fmt.Errorf("invalid delete DN: %w", err)
		}
	}

	deleted := 0
	for _, dn := range dns {
		if client.dryRun {
			deleted++
			continue
		}
		if *recursive {
			count, err := recursivelyDeleteLDAPDN(&client, connection, dn, controls)
			if err != nil {
				return fmt.Errorf("recursively delete %q: %w", dn, err)
			}
			deleted += count
			continue
		}
		operation := &ldapWriteOperation{
			kind:   ldapWriteDelete,
			delete: ldap.NewDelRequest(dn, controls),
		}
		if err := client.executeWriteWithReferrals(connection, operation); err != nil {
			return fmt.Errorf("delete %q: %w", dn, err)
		}
		deleted++
	}
	action := "deleted"
	if client.dryRun {
		action = "validated"
	}
	_, err = fmt.Fprintf(stdout, "ldapdelete: %s %d entry(s)\n", action, deleted)
	return err
}

func runLDAPModRDN(
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	flags := flag.NewFlagSet("ldapmodrdn", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var client ldapClientOptions
	client.register(flags)
	defer client.clear()
	inputPath := flags.String("f", "", "read old DN/new RDN line pairs from a file")
	newSuperior := flags.String("s", "", "move entries below this new superior DN")
	deleteOldRDN := flags.Bool("r", false, "delete old RDN attribute values")
	var extensions repeatedStringFlag
	flags.Var(&extensions, "E", "operation control: [!]<oid>[=:<string>|::<base64>|:<file URI>]")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := client.validateWrite(flags); err != nil {
		return err
	}
	extensionControls, err := parseLDAPControlSpecs(extensions, ldapControlValueLDIF)
	if err != nil {
		return fmt.Errorf("ldapmodrdn -E: %w", err)
	}
	defer clearLDAPControls(extensionControls)
	controls, err := mergeLDAPControls(client.generalControls, extensionControls)
	if err != nil {
		return fmt.Errorf("ldapmodrdn controls: %w", err)
	}
	if err := rejectUnsupportedFlags("ldapmodrdn", flags, nil); err != nil {
		return err
	}
	if flagWasSet(flags, "r") && !*deleteOldRDN {
		return errors.New("-r=false is not supported")
	}
	if flagWasSet(flags, "s") && *newSuperior == "" {
		return errors.New("-s requires a non-empty new superior DN")
	}
	if flagWasSet(flags, "f") && *inputPath == "" {
		return errors.New("-f requires a non-empty path or - for stdin")
	}
	if flagWasSet(flags, "f") && flags.NArg() != 0 {
		return errors.New("ldapmodrdn arguments and -f are mutually exclusive")
	}
	if flags.NArg() != 0 && flags.NArg() != 2 {
		return errors.New("ldapmodrdn requires oldDN newRDN or line-pair input")
	}

	var connection *ldap.Conn
	if !client.dryRun {
		var err error
		connection, err = client.connectAndBind(flags, stdin, stderr)
		if err != nil {
			return err
		}
		defer connection.Close()
	}

	var pairs []string
	if flags.NArg() == 2 {
		pairs = append(pairs, flags.Arg(0), flags.Arg(1))
	} else {
		input, err := readLDAPWriteSource(*inputPath, stdin)
		if err != nil {
			return err
		}
		defer clear(input)
		pairs, err = parseLDAPWriteLineInput(input)
		if err != nil {
			return err
		}
	}
	if len(pairs) == 0 || len(pairs)%2 != 0 {
		return errors.New("ldapmodrdn line input must contain old DN/new RDN pairs")
	}
	if *newSuperior != "" {
		if err := validateLDAPWriteDN(*newSuperior); err != nil {
			return fmt.Errorf("invalid new superior DN: %w", err)
		}
	}

	operations := make([]*ldapWriteOperation, 0, len(pairs)/2)
	for index := 0; index < len(pairs); index += 2 {
		request := ldap.NewModifyDNRequest(
			pairs[index],
			pairs[index+1],
			*deleteOldRDN,
			*newSuperior,
		)
		operation := &ldapWriteOperation{
			kind:     ldapWriteModifyDN,
			modifyDN: request,
		}
		operation.setControls(controls)
		if err := validateLDAPWriteOperation(operation); err != nil {
			return fmt.Errorf("pair %d: %w", index/2+1, err)
		}
		operations = append(operations, operation)
	}

	if !client.dryRun {
		for _, operation := range operations {
			if err := client.executeWriteWithReferrals(connection, operation); err != nil {
				return fmt.Errorf("modify DN %q: %w", operation.dn(), err)
			}
		}
	}
	action := "modified"
	if client.dryRun {
		action = "validated"
	}
	_, err = fmt.Fprintf(stdout, "ldapmodrdn: %s %d entry(s)\n", action, len(operations))
	return err
}

func parseLDAPWriteRecord(
	raw []byte,
	allowContentAdd bool,
	state *ldapWriteParseState,
) (*ldapWriteOperation, error) {
	logicalLines, err := logicalLDAPWriteLines(raw)
	if err != nil {
		return nil, errors.New("invalid folded LDIF record")
	}
	if len(logicalLines) == 0 {
		return nil, nil
	}

	firstName, firstValue, firstMode, err := parseLDAPWriteLine(logicalLines[0])
	if err != nil {
		return nil, errors.New("invalid LDIF record header")
	}
	if strings.EqualFold(firstName, "version") {
		if state.sawVersion || state.sawOperation || firstMode != ldapWriteValuePlain || string(firstValue) != "1" {
			return nil, errors.New("invalid or misplaced LDIF version header")
		}
		state.sawVersion = true
		logicalLines = logicalLines[1:]
		if len(logicalLines) == 0 {
			return nil, nil
		}
		firstName, _, _, err = parseLDAPWriteLine(logicalLines[0])
		if err != nil {
			return nil, errors.New("invalid LDIF record header")
		}
	}
	state.sawOperation = true
	if !strings.EqualFold(firstName, "dn") {
		return nil, errors.New("LDIF record must begin with dn")
	}

	externalBytesRemaining := maxLDAPWriteRecordSize - len(raw)
	for index, line := range logicalLines {
		if line == "-" {
			continue
		}
		name, value, mode, err := parseLDAPWriteLine(line)
		if err != nil {
			return nil, errors.New("invalid LDIF value line")
		}
		if mode == ldapWriteValueURL && !strings.EqualFold(name, "control") {
			loaded, err := readLDAPWriteFileURL(string(value), externalBytesRemaining)
			if err != nil {
				return nil, fmt.Errorf("external value for %q: %w", name, err)
			}
			externalBytesRemaining -= len(loaded)
			logicalLines[index] = name + ":: " + base64.StdEncoding.EncodeToString(loaded)
			clear(loaded)
		}
	}

	recordControls := make([]ldap.Control, 0, 2)
	controlEnd := 1
	for controlEnd < len(logicalLines) {
		name, value, _, err := parseLDAPWriteLine(logicalLines[controlEnd])
		if err != nil || !strings.EqualFold(name, "control") {
			break
		}
		control, externalBytes, err := parseLDAPWriteRecordControl(value, externalBytesRemaining)
		if err != nil {
			clearLDAPControls(recordControls)
			return nil, err
		}
		externalBytesRemaining -= externalBytes
		recordControls = append(recordControls, control)
		controlEnd++
	}
	for index := controlEnd; index < len(logicalLines); index++ {
		if logicalLines[index] == "-" {
			continue
		}
		name, _, _, err := parseLDAPWriteLine(logicalLines[index])
		if err == nil && strings.EqualFold(name, "control") {
			clearLDAPControls(recordControls)
			return nil, errors.New("LDIF request controls must follow dn before changetype")
		}
	}
	if controlEnd > 1 {
		logicalLines = append(logicalLines[:1], logicalLines[controlEnd:]...)
	}
	attachControls := func(operation *ldapWriteOperation, err error) (*ldapWriteOperation, error) {
		if err != nil || operation == nil {
			clearLDAPControls(recordControls)
			return operation, err
		}
		operation.recordControls = recordControls
		return operation, nil
	}

	changeType := ""
	if len(logicalLines) > 1 {
		name, value, _, lineErr := parseLDAPWriteLine(logicalLines[1])
		if lineErr == nil && strings.EqualFold(name, "changetype") {
			changeType = strings.ToLower(string(value))
		}
	}
	if changeType == "moddn" || changeType == "modrdn" {
		operation, err := parseLDAPModifyDNRecord(logicalLines)
		if err != nil {
			return attachControls(nil, err)
		}
		return attachControls(operation, validateLDAPWriteOperation(operation))
	}
	if changeType == "modify" {
		operation, err := parseLDAPModifyRecord(logicalLines, true)
		if err != nil {
			return attachControls(nil, err)
		}
		return attachControls(operation, validateLDAPWriteOperation(operation))
	}
	if changeType == "" && !allowContentAdd {
		operation, err := parseLDAPModifyRecord(logicalLines, false)
		if err != nil {
			return attachControls(nil, err)
		}
		return attachControls(operation, validateLDAPWriteOperation(operation))
	}

	document := &ldif.LDIF{Controls: true}
	var parsed *ldif.Entry
	resolvedRaw := []byte(strings.Join(logicalLines, "\n") + "\n")
	for entry, parseErr := range ldif.UnmarshalEntries(bytes.NewReader(resolvedRaw), document) {
		if parseErr != nil {
			return attachControls(nil, errors.New("invalid LDIF syntax"))
		}
		if entry == nil {
			continue
		}
		if parsed != nil {
			return attachControls(nil, errors.New("record contains multiple LDIF operations"))
		}
		parsed = entry
	}
	if parsed == nil {
		return attachControls(nil, nil)
	}
	operation, err := ldapWriteOperationFromLDIF(parsed, allowContentAdd)
	if err != nil {
		return attachControls(nil, err)
	}
	if operation.kind == ldapWriteAdd {
		orderLDAPAddRequestAttributes(operation.add, logicalLines)
	}
	return attachControls(operation, validateLDAPWriteOperation(operation))
}

func orderLDAPAddRequestAttributes(request *ldap.AddRequest, lines []string) {
	if request == nil || len(request.Attributes) < 2 {
		return
	}
	ordered := make([]ldap.Attribute, 0, len(request.Attributes))
	used := make([]bool, len(request.Attributes))
	for index := 1; index < len(lines); index++ {
		if lines[index] == "-" {
			continue
		}
		name, _, _, err := parseLDAPWriteLine(lines[index])
		if err != nil || strings.EqualFold(name, "changetype") {
			continue
		}
		for attributeIndex := range request.Attributes {
			if used[attributeIndex] ||
				!strings.EqualFold(request.Attributes[attributeIndex].Type, name) {
				continue
			}
			ordered = append(ordered, request.Attributes[attributeIndex])
			used[attributeIndex] = true
			break
		}
	}
	remaining := make([]ldap.Attribute, 0, len(request.Attributes)-len(ordered))
	for index, attribute := range request.Attributes {
		if !used[index] {
			remaining = append(remaining, attribute)
		}
	}
	sort.SliceStable(remaining, func(first, second int) bool {
		return strings.ToLower(remaining[first].Type) < strings.ToLower(remaining[second].Type)
	})
	request.Attributes = append(ordered, remaining...)
}

func parseLDAPWriteRecordControl(value []byte, externalBytesRemaining int) (*ldapRawControl, int, error) {
	text := strings.TrimSpace(string(value))
	if text == "" {
		return nil, 0, errors.New("LDIF control requires an OID")
	}
	oidEnd := strings.IndexAny(text, " \t")
	oid := text
	remainder := ""
	if oidEnd >= 0 {
		oid = text[:oidEnd]
		remainder = strings.TrimSpace(text[oidEnd:])
	}
	if !validLDAPOperationOID(oid) {
		return nil, 0, fmt.Errorf("invalid LDIF control OID %q", oid)
	}
	critical := false
	for _, keyword := range []struct {
		name  string
		value bool
	}{{"true", true}, {"false", false}} {
		if len(remainder) >= len(keyword.name) &&
			strings.EqualFold(remainder[:len(keyword.name)], keyword.name) &&
			(len(remainder) == len(keyword.name) || remainder[len(keyword.name)] == ' ' ||
				remainder[len(keyword.name)] == '\t' || remainder[len(keyword.name)] == ':') {
			critical = keyword.value
			remainder = strings.TrimSpace(remainder[len(keyword.name):])
			break
		}
	}
	control := &ldapRawControl{oid: oid, critical: critical}
	if remainder == "" {
		return control, 0, nil
	}
	control.hasValue = true
	switch {
	case strings.HasPrefix(remainder, "::"):
		decoded, err := decodeLDAPControlBase64(strings.TrimSpace(remainder[2:]), oid)
		if err != nil {
			return nil, 0, err
		}
		control.value = decoded
	case strings.HasPrefix(remainder, ":<"):
		loaded, err := readLDAPWriteFileURL(
			strings.TrimSpace(remainder[2:]),
			externalBytesRemaining,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("LDIF control %s: %w", oid, err)
		}
		control.value = loaded
		return control, len(loaded), nil
	case strings.HasPrefix(remainder, ":"):
		control.value = []byte(strings.TrimLeft(remainder[1:], " \t"))
		if len(control.value) > maxLDAPControlValueSize {
			control.clear()
			return nil, 0, fmt.Errorf("LDAP control %s value exceeds %d bytes", oid, maxLDAPControlValueSize)
		}
	default:
		return nil, 0, fmt.Errorf("LDIF control %s value must begin with :, ::, or :<", oid)
	}
	return control, 0, nil
}

func readLDAPWriteFileURL(reference string, bytesRemaining int) ([]byte, error) {
	if bytesRemaining < 0 {
		return nil, fmt.Errorf("expanded LDIF record exceeds %d bytes", maxLDAPWriteRecordSize)
	}
	parsed, err := url.Parse(strings.TrimSpace(reference))
	if err != nil {
		return nil, fmt.Errorf("parse file URL: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "file") || parsed.Opaque != "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Host != "" && !strings.EqualFold(parsed.Host, "localhost")) {
		return nil, errors.New("external LDIF value must use a local file:// absolute URL")
	}
	path := filepath.FromSlash(parsed.Path)
	if path == "" || !filepath.IsAbs(path) || strings.IndexByte(path, 0) >= 0 {
		return nil, errors.New("external LDIF file path must be absolute")
	}
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect external LDIF value: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("external LDIF value must be a non-symlink regular file")
	}
	if info.Size() > int64(bytesRemaining) {
		return nil, fmt.Errorf("expanded LDIF record exceeds %d bytes", maxLDAPWriteRecordSize)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open external LDIF value: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("external LDIF value changed while opening it")
	}
	value, err := io.ReadAll(io.LimitReader(file, int64(bytesRemaining)+1))
	if err != nil {
		return nil, fmt.Errorf("read external LDIF value: %w", err)
	}
	if len(value) > bytesRemaining {
		clear(value)
		return nil, fmt.Errorf("expanded LDIF record exceeds %d bytes", maxLDAPWriteRecordSize)
	}
	return value, nil
}

func parseLDAPModifyRecord(lines []string, explicitChangeType bool) (*ldapWriteOperation, error) {
	minimumLines := 2
	changeStart := 1
	if explicitChangeType {
		minimumLines = 3
		changeStart = 2
	}
	if len(lines) < minimumLines {
		return nil, errors.New("modify record requires at least one change")
	}
	dnName, dnValue, _, err := parseLDAPWriteLine(lines[0])
	if err != nil || !strings.EqualFold(dnName, "dn") {
		return nil, errors.New("invalid modify DN")
	}
	if explicitChangeType {
		changeName, changeValue, changeMode, err := parseLDAPWriteLine(lines[1])
		if err != nil || !strings.EqualFold(changeName, "changetype") ||
			changeMode == ldapWriteValueURL || !strings.EqualFold(string(changeValue), "modify") {
			return nil, errors.New("modify record requires changetype: modify")
		}
	}

	request := ldap.NewModifyRequest(string(dnValue), nil)
	for index := changeStart; index < len(lines); {
		operationName, attributeValue, mode, err := parseLDAPWriteLine(lines[index])
		if err != nil || mode == ldapWriteValueURL {
			return nil, fmt.Errorf("invalid modify change at line %d", index+1)
		}
		operationName = strings.ToLower(operationName)
		attribute := string(attributeValue)
		if !validLDIFAttributeDescription(attribute) {
			return nil, fmt.Errorf("invalid modify attribute %q", attribute)
		}
		switch operationName {
		case "add", "delete", "replace", "increment":
		default:
			return nil, fmt.Errorf("unsupported modify change %q", operationName)
		}

		index++
		values := make([]string, 0, 1)
		for index < len(lines) && lines[index] != "-" {
			valueName, value, valueMode, err := parseLDAPWriteLine(lines[index])
			if err != nil || valueMode == ldapWriteValueURL ||
				!strings.EqualFold(valueName, attribute) {
				return nil, fmt.Errorf(
					"modify %s for %q contains an invalid value line",
					operationName,
					attribute,
				)
			}
			values = append(values, string(value))
			index++
		}
		if index < len(lines) {
			if lines[index] != "-" {
				return nil, fmt.Errorf("modify %s for %q must end with -", operationName, attribute)
			}
			index++
		}

		switch operationName {
		case "add":
			request.Add(attribute, values)
		case "delete":
			request.Delete(attribute, values)
		case "replace":
			request.Replace(attribute, values)
		case "increment":
			if len(values) != 1 {
				return nil, fmt.Errorf("increment change for %q requires exactly one value", attribute)
			}
			request.Increment(attribute, values[0])
		}
	}
	return &ldapWriteOperation{kind: ldapWriteModify, modify: request}, nil
}

func ldapWriteOperationFromLDIF(
	record *ldif.Entry,
	allowContentAdd bool,
) (*ldapWriteOperation, error) {
	switch {
	case record.Entry != nil:
		if !allowContentAdd {
			return nil, errors.New("content records require ldapadd or changetype: add")
		}
		request := ldap.NewAddRequest(record.Entry.DN, nil)
		for _, attribute := range record.Entry.Attributes {
			values := attribute.ByteValues
			if len(values) == 0 && len(attribute.Values) > 0 {
				values = make([][]byte, len(attribute.Values))
				for index := range attribute.Values {
					values[index] = []byte(attribute.Values[index])
				}
			}
			encoded := make([]string, len(values))
			for index := range values {
				encoded[index] = string(values[index])
			}
			request.Attribute(attribute.Name, encoded)
		}
		return &ldapWriteOperation{kind: ldapWriteAdd, add: request}, nil
	case record.Add != nil:
		return &ldapWriteOperation{kind: ldapWriteAdd, add: record.Add}, nil
	case record.Modify != nil:
		return &ldapWriteOperation{kind: ldapWriteModify, modify: record.Modify}, nil
	case record.Del != nil:
		return &ldapWriteOperation{kind: ldapWriteDelete, delete: record.Del}, nil
	default:
		return nil, errors.New("LDIF record has no supported operation")
	}
}

func parseLDAPModifyDNRecord(lines []string) (*ldapWriteOperation, error) {
	if len(lines) < 4 || len(lines) > 5 {
		return nil, errors.New("moddn record requires newrdn, deleteoldrdn, and optional newsuperior")
	}
	_, dnValue, _, err := parseLDAPWriteLine(lines[0])
	if err != nil {
		return nil, errors.New("invalid moddn DN")
	}
	expected := []string{"newrdn", "deleteoldrdn"}
	values := make(map[string][]byte, 3)
	for index, expectedName := range expected {
		name, value, mode, err := parseLDAPWriteLine(lines[index+2])
		if err != nil || !strings.EqualFold(name, expectedName) || mode == ldapWriteValueURL {
			return nil, fmt.Errorf("moddn record requires %s in order", expectedName)
		}
		values[expectedName] = value
	}
	if len(lines) == 5 {
		name, value, mode, err := parseLDAPWriteLine(lines[4])
		if err != nil || !strings.EqualFold(name, "newsuperior") || mode == ldapWriteValueURL {
			return nil, errors.New("moddn newsuperior must follow deleteoldrdn")
		}
		values["newsuperior"] = value
	}
	deleteOld := false
	switch string(values["deleteoldrdn"]) {
	case "0":
	case "1":
		deleteOld = true
	default:
		return nil, errors.New("moddn deleteoldrdn must be 0 or 1")
	}
	request := ldap.NewModifyDNRequest(
		string(dnValue),
		string(values["newrdn"]),
		deleteOld,
		string(values["newsuperior"]),
	)
	return &ldapWriteOperation{kind: ldapWriteModifyDN, modifyDN: request}, nil
}

func validateLDAPWriteOperation(operation *ldapWriteOperation) error {
	if operation == nil {
		return errors.New("LDAP write operation is required")
	}
	if err := validateLDAPWriteDN(operation.dn()); err != nil {
		return err
	}
	switch operation.kind {
	case ldapWriteAdd:
		if operation.add == nil || len(operation.add.Attributes) == 0 {
			return errors.New("add operation requires at least one attribute")
		}
		for _, attribute := range operation.add.Attributes {
			if !validLDIFAttributeDescription(attribute.Type) || len(attribute.Vals) == 0 {
				return fmt.Errorf("invalid or empty add attribute %q", attribute.Type)
			}
		}
	case ldapWriteModify:
		if operation.modify == nil || len(operation.modify.Changes) == 0 {
			return errors.New("modify operation requires at least one change")
		}
		for _, change := range operation.modify.Changes {
			if !validLDIFAttributeDescription(change.Modification.Type) {
				return fmt.Errorf("invalid modify attribute %q", change.Modification.Type)
			}
			switch change.Operation {
			case ldap.AddAttribute:
				if len(change.Modification.Vals) == 0 {
					return fmt.Errorf("add change for %q requires a value", change.Modification.Type)
				}
			case ldap.DeleteAttribute, ldap.ReplaceAttribute:
			case ldap.IncrementAttribute:
				if len(change.Modification.Vals) != 1 {
					return fmt.Errorf("increment change for %q requires exactly one value", change.Modification.Type)
				}
			default:
				return fmt.Errorf("unsupported modify operation %d", change.Operation)
			}
		}
	case ldapWriteDelete:
		if operation.delete == nil {
			return errors.New("delete request is required")
		}
	case ldapWriteModifyDN:
		if operation.modifyDN == nil {
			return errors.New("modify DN request is required")
		}
		if err := validateLDAPWriteRDN(operation.modifyDN.NewRDN); err != nil {
			return err
		}
		if operation.modifyDN.NewSuperior != "" {
			if err := validateLDAPWriteDN(operation.modifyDN.NewSuperior); err != nil {
				return fmt.Errorf("invalid new superior: %w", err)
			}
		}
	default:
		return errors.New("unknown LDAP write operation")
	}
	return nil
}

func validateLDAPWriteDN(value string) error {
	parsed, err := ldap.ParseDN(value)
	if err != nil || parsed == nil || len(parsed.RDNs) == 0 {
		if err == nil {
			err = errors.New("DN must not be empty")
		}
		return fmt.Errorf("invalid DN %q: %w", value, err)
	}
	return nil
}

func validateLDAPWriteRDN(value string) error {
	parsed, err := ldap.ParseDN(value)
	if err != nil || parsed == nil || len(parsed.RDNs) != 1 {
		if err == nil {
			err = errors.New("new RDN must contain exactly one RDN")
		}
		return fmt.Errorf("invalid new RDN %q: %w", value, err)
	}
	return nil
}

type ldapWriteValueMode uint8

const (
	ldapWriteValuePlain ldapWriteValueMode = iota
	ldapWriteValueBase64
	ldapWriteValueURL
)

func parseLDAPWriteLine(line string) (string, []byte, ldapWriteValueMode, error) {
	colon := strings.IndexByte(line, ':')
	if colon <= 0 {
		return "", nil, 0, errors.New("LDIF line has no attribute separator")
	}
	name := line[:colon]
	if !validLDIFAttributeDescription(name) {
		return "", nil, 0, errors.New("invalid LDIF attribute description")
	}
	remainder := line[colon+1:]
	if remainder == "" {
		return name, []byte{}, ldapWriteValuePlain, nil
	}
	switch remainder[0] {
	case ':':
		encoded := strings.TrimLeft(remainder[1:], " ")
		value, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", nil, 0, errors.New("invalid base64 LDIF value")
		}
		return name, value, ldapWriteValueBase64, nil
	case '<':
		return name, []byte(strings.TrimLeft(remainder[1:], " ")), ldapWriteValueURL, nil
	default:
		return name, []byte(strings.TrimLeft(remainder, " ")), ldapWriteValuePlain, nil
	}
}

func logicalLDAPWriteLines(raw []byte) ([]string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64<<10), maxLDAPWriteLineSize)
	lines := make([]string, 0, 16)
	current := ""
	comment := false
	flush := func() {
		if current != "" {
			lines = append(lines, current)
			current = ""
		}
	}
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		switch line[0] {
		case '#':
			comment = true
			continue
		case ' ':
			if comment {
				continue
			}
			if current == "" {
				return nil, errors.New("orphan LDIF continuation line")
			}
			current += line[1:]
		default:
			comment = false
			flush()
			current = line
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	flush()
	return lines, nil
}

func splitLDAPWriteRecords(input []byte) ([][]byte, error) {
	records, err := splitLDAPWriteRecordsWithLines(input)
	if err != nil {
		return nil, err
	}
	values := make([][]byte, len(records))
	for index := range records {
		values[index] = records[index].raw
	}
	return values, nil
}

type ldapWriteRawRecord struct {
	line int
	raw  []byte
}

func splitLDAPWriteRecordsWithLines(input []byte) ([]ldapWriteRawRecord, error) {
	if len(input) > maxLDAPWriteInputSize {
		return nil, fmt.Errorf("LDIF input exceeds %d bytes", maxLDAPWriteInputSize)
	}
	reader := bufio.NewReader(bytes.NewReader(input))
	records := make([]ldapWriteRawRecord, 0, 16)
	var current bytes.Buffer
	lineNumber := 0
	startLine := 1
	flush := func() error {
		if current.Len() == 0 {
			return nil
		}
		if len(records) >= maxLDAPWriteRecords {
			return fmt.Errorf("LDIF input exceeds %d records", maxLDAPWriteRecords)
		}
		records = append(records, ldapWriteRawRecord{
			line: startLine,
			raw:  bytes.Clone(current.Bytes()),
		})
		current.Reset()
		return nil
	}
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			lineNumber++
			physical := bytes.TrimSuffix(line, []byte{'\n'})
			physical = bytes.TrimSuffix(physical, []byte{'\r'})
			if len(physical) > maxLDAPWriteLineSize {
				return nil, fmt.Errorf("LDIF physical line exceeds %d bytes", maxLDAPWriteLineSize)
			}
			if len(physical) == 0 {
				if flushErr := flush(); flushErr != nil {
					return nil, flushErr
				}
				startLine = lineNumber + 1
			} else {
				if current.Len() == 0 {
					startLine = lineNumber
				}
				if current.Len()+len(physical)+1 > maxLDAPWriteRecordSize {
					return nil, fmt.Errorf("LDIF record exceeds %d bytes", maxLDAPWriteRecordSize)
				}
				current.Write(physical)
				current.WriteByte('\n')
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("read LDIF input: %w", err)
			}
			break
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return records, nil
}

func readLDAPWriteSource(path string, stdin io.Reader) ([]byte, error) {
	if path == "" || path == "-" {
		return readBoundedLDAPWriteInput(stdin, "stdin")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect LDIF input file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("LDIF input path must be a non-symlink regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open LDIF input file: %w", err)
	}
	defer file.Close()
	return readBoundedLDAPWriteInput(file, "LDIF input")
}

func readBoundedLDAPWriteInput(reader io.Reader, source string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxLDAPWriteInputSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", source, err)
	}
	if len(data) > maxLDAPWriteInputSize {
		clear(data)
		return nil, fmt.Errorf("%s exceeds %d bytes", source, maxLDAPWriteInputSize)
	}
	return data, nil
}

func parseLDAPWriteLineInput(input []byte) ([]string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64<<10), maxLDAPWriteLineSize)
	values := make([]string, 0, 16)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.IndexByte(line, 0) >= 0 {
			return nil, errors.New("line input contains a NUL byte")
		}
		if len(values) >= maxLDAPWriteRecords*2 {
			return nil, errors.New("line input contains too many values")
		}
		values = append(values, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read line input: %w", err)
	}
	return values, nil
}

func recursivelyDeleteLDAPDN(
	client *ldapClientOptions,
	connection *ldap.Conn,
	baseDN string,
	controls []ldap.Control,
) (int, error) {
	result, err := client.searchWithReferrals(connection, ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		controls,
	), recursiveDeletePageSize)
	if err != nil {
		return 0, fmt.Errorf("enumerate subtree: %w", err)
	}
	type candidate struct {
		dn    string
		depth int
	}
	candidates := make([]candidate, 0, len(result.Entries)+1)
	seen := make(map[string]struct{}, len(result.Entries)+1)
	appendDN := func(raw string) error {
		parsed, err := ldap.ParseDN(raw)
		if err != nil || len(parsed.RDNs) == 0 {
			return fmt.Errorf("server returned invalid DN %q", raw)
		}
		key := strings.ToLower(parsed.String())
		if _, found := seen[key]; found {
			return nil
		}
		seen[key] = struct{}{}
		candidates = append(candidates, candidate{dn: raw, depth: len(parsed.RDNs)})
		return nil
	}
	for _, entry := range result.Entries {
		if err := appendDN(entry.DN); err != nil {
			return 0, err
		}
	}
	if err := appendDN(baseDN); err != nil {
		return 0, err
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].depth != candidates[j].depth {
			return candidates[i].depth > candidates[j].depth
		}
		return candidates[i].dn > candidates[j].dn
	})
	for index, entry := range candidates {
		operation := &ldapWriteOperation{
			kind:   ldapWriteDelete,
			delete: ldap.NewDelRequest(entry.dn, controls),
		}
		if err := client.executeWriteWithReferrals(connection, operation); err != nil {
			return index, fmt.Errorf("delete %q: %w", entry.dn, err)
		}
	}
	return len(candidates), nil
}

func openLDAPWriteFailureFile(path, inputPath string) (*ldapWriteFailureFile, error) {
	if path == "" {
		return nil, nil
	}
	if path == "-" {
		return nil, errors.New("-S requires a file path, not stdout")
	}
	if inputPath != "" && inputPath != "-" {
		same, err := ldapWritePathsReferToSameFile(path, inputPath)
		if err != nil {
			return nil, err
		}
		if same {
			return nil, errors.New("-S failure output and -f input must be different files")
		}
	}
	if err := rejectLDAPWriteSymlinkParents(path); err != nil {
		return nil, err
	}

	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve -S failure output path: %w", err)
	}
	parentPath := filepath.Dir(absolute)
	target := filepath.Base(absolute)
	if target == "." || target == string(filepath.Separator) {
		return nil, errors.New("-S failure output must name a file")
	}
	parentBefore, err := os.Lstat(parentPath)
	if err != nil {
		return nil, fmt.Errorf("inspect -S parent directory: %w", err)
	}
	root, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, fmt.Errorf("open -S parent directory: %w", err)
	}
	closeRootOnError := func(err error) (*ldapWriteFailureFile, error) {
		return nil, errors.Join(err, root.Close())
	}
	openedParent, err := root.Stat(".")
	if err != nil {
		return closeRootOnError(fmt.Errorf("inspect opened -S parent directory: %w", err))
	}
	parentAfter, err := os.Lstat(parentPath)
	if err != nil || !os.SameFile(parentBefore, openedParent) || !os.SameFile(parentBefore, parentAfter) {
		return closeRootOnError(errors.New("-S parent directory changed while opening it"))
	}

	info, err := root.Lstat(target)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return closeRootOnError(errors.New("-S failure output must be a non-symlink regular file"))
		}
		if info.Mode().Perm()&0o077 != 0 {
			return closeRootOnError(errors.New("existing -S failure output permissions must not allow group or other access"))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return closeRootOnError(fmt.Errorf("inspect -S failure output: %w", err))
	}

	file, temporary, err := createLDAPWriteFailureTemp(root)
	if err != nil {
		return closeRootOnError(err)
	}
	return &ldapWriteFailureFile{
		root:      root,
		file:      file,
		temporary: temporary,
		target:    target,
	}, nil
}

func createLDAPWriteFailureTemp(root *os.Root) (*os.File, string, error) {
	random := make([]byte, 16)
	defer clear(random)
	for attempt := 0; attempt < 10; attempt++ {
		if _, err := rand.Read(random); err != nil {
			return nil, "", fmt.Errorf("generate -S temporary filename: %w", err)
		}
		name := ".ldap-go-failed-" + hex.EncodeToString(random)
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create -S temporary output: %w", err)
		}
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			_ = root.Remove(name)
			return nil, "", fmt.Errorf("secure -S temporary output: %w", err)
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			_ = file.Close()
			_ = root.Remove(name)
			return nil, "", errors.New("opened -S temporary output is not a regular file")
		}
		return file, name, nil
	}
	return nil, "", errors.New("could not allocate a unique -S temporary output")
}

func rejectLDAPWriteSymlinkParents(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve -S failure output path: %w", err)
	}
	info, err := os.Lstat(filepath.Dir(absolute))
	if err != nil {
		return fmt.Errorf("inspect -S parent directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("-S failure output parent directory must not be a symbolic link")
	}
	if !info.IsDir() {
		return errors.New("-S failure output parent must be a directory")
	}
	return nil
}

func ldapWritePathsReferToSameFile(first, second string) (bool, error) {
	if samePath(first, second) {
		return true, nil
	}
	firstInfo, firstErr := os.Stat(first)
	secondInfo, secondErr := os.Stat(second)
	if firstErr == nil && secondErr == nil {
		return os.SameFile(firstInfo, secondInfo), nil
	}
	if firstErr != nil && !errors.Is(firstErr, os.ErrNotExist) {
		return false, fmt.Errorf("inspect -S failure output: %w", firstErr)
	}
	if secondErr != nil {
		return false, fmt.Errorf("inspect -f input: %w", secondErr)
	}
	return false, nil
}

func (failure *ldapWriteFailureFile) WriteOperation(operation *ldapWriteOperation) error {
	if failure == nil || failure.file == nil {
		return nil
	}
	if err := writeLDAPWriteOperationLDIF(failure.file, operation); err != nil {
		failure.failed = true
		return err
	}
	failure.records++
	return nil
}

func (failure *ldapWriteFailureFile) Close() error {
	if failure == nil || failure.root == nil {
		return nil
	}
	var syncErr, closeErr error
	if failure.file != nil {
		syncErr = failure.file.Sync()
		closeErr = failure.file.Close()
	}
	failure.file = nil
	if failure.failed || failure.records == 0 || syncErr != nil || closeErr != nil {
		removeErr := failure.root.Remove(failure.temporary)
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		rootErr := failure.root.Close()
		failure.root = nil
		return errors.Join(syncErr, closeErr, removeErr, rootErr)
	}
	if err := failure.root.Rename(failure.temporary, failure.target); err != nil {
		removeErr := failure.root.Remove(failure.temporary)
		rootErr := failure.root.Close()
		failure.root = nil
		return errors.Join(fmt.Errorf("publish -S failure output: %w", err), removeErr, rootErr)
	}
	failure.temporary = ""
	rootErr := failure.root.Close()
	failure.root = nil
	return rootErr
}

func writeLDAPWriteOperationLDIF(
	writer io.Writer,
	operation *ldapWriteOperation,
) error {
	if err := writeLDIFAttribute(writer, "dn", []byte(operation.dn())); err != nil {
		return err
	}
	for _, generic := range operation.recordControls {
		control, ok := generic.(*ldapRawControl)
		if !ok || control == nil || !validLDAPOperationOID(control.oid) {
			return errors.New("cannot render invalid LDIF request control")
		}
		line := fmt.Sprintf("control: %s %t", control.oid, control.critical)
		if control.hasValue {
			line += ":: " + base64.StdEncoding.EncodeToString(control.value)
		}
		if err := writeFoldedLDIFLine(writer, []byte(line)); err != nil {
			return err
		}
	}
	switch operation.kind {
	case ldapWriteAdd:
		if err := writeLDIFAttribute(writer, "changetype", []byte("add")); err != nil {
			return err
		}
		for _, attribute := range operation.add.Attributes {
			for _, value := range attribute.Vals {
				if err := writeLDIFAttribute(writer, attribute.Type, []byte(value)); err != nil {
					return err
				}
			}
		}
	case ldapWriteModify:
		if err := writeLDIFAttribute(writer, "changetype", []byte("modify")); err != nil {
			return err
		}
		for _, change := range operation.modify.Changes {
			name := ""
			switch change.Operation {
			case ldap.AddAttribute:
				name = "add"
			case ldap.DeleteAttribute:
				name = "delete"
			case ldap.ReplaceAttribute:
				name = "replace"
			case ldap.IncrementAttribute:
				name = "increment"
			default:
				return fmt.Errorf("cannot render modify operation %d", change.Operation)
			}
			if err := writeLDIFAttribute(writer, name, []byte(change.Modification.Type)); err != nil {
				return err
			}
			for _, value := range change.Modification.Vals {
				if err := writeLDIFAttribute(writer, change.Modification.Type, []byte(value)); err != nil {
					return err
				}
			}
			if err := writeFoldedLDIFLine(writer, []byte("-")); err != nil {
				return err
			}
		}
	case ldapWriteDelete:
		if err := writeLDIFAttribute(writer, "changetype", []byte("delete")); err != nil {
			return err
		}
	case ldapWriteModifyDN:
		if err := writeLDIFAttribute(writer, "changetype", []byte("moddn")); err != nil {
			return err
		}
		if err := writeLDIFAttribute(writer, "newrdn", []byte(operation.modifyDN.NewRDN)); err != nil {
			return err
		}
		deleteOld := "0"
		if operation.modifyDN.DeleteOldRDN {
			deleteOld = "1"
		}
		if err := writeLDIFAttribute(writer, "deleteoldrdn", []byte(deleteOld)); err != nil {
			return err
		}
		if operation.modifyDN.NewSuperior != "" {
			if err := writeLDIFAttribute(writer, "newsuperior", []byte(operation.modifyDN.NewSuperior)); err != nil {
				return err
			}
		}
	default:
		return errors.New("cannot render unknown LDAP operation")
	}
	_, err := io.WriteString(writer, "\n")
	return err
}
