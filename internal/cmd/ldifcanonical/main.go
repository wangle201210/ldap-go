package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
)

func main() {
	flags := flag.NewFlagSet("ldifcanonical", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	inputPath := flags.String("in", "-", "LDIF input path, or - for stdin")
	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected arguments: %s\n", strings.Join(flags.Args(), " "))
		os.Exit(2)
	}

	input := io.Reader(os.Stdin)
	var file *os.File
	if *inputPath != "-" {
		var err error
		file, err = os.Open(*inputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open LDIF: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		input = file
	}
	if err := canonicalizeLDIF(input, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "canonicalize LDIF: %v\n", err)
		os.Exit(1)
	}
}

func canonicalizeLDIF(input io.Reader, output io.Writer) error {
	if input == nil || output == nil {
		return errors.New("input and output are required")
	}
	buffered := bufio.NewWriterSize(output, 256<<10)
	document := &ldif.LDIF{}
	for record, err := range ldif.UnmarshalEntries(input, document) {
		if err != nil {
			return err
		}
		if record == nil || record.Entry == nil ||
			record.Add != nil || record.Del != nil || record.Modify != nil {
			return errors.New("change records are not supported")
		}
		line, err := canonicalEntry(record.Entry)
		if err != nil {
			return err
		}
		if _, err := buffered.WriteString(line); err != nil {
			return err
		}
		if err := buffered.WriteByte('\n'); err != nil {
			return err
		}
	}
	return buffered.Flush()
}

func canonicalEntry(entry *ldap.Entry) (string, error) {
	if entry == nil {
		return "", errors.New("entry is required")
	}
	parsedDN, err := ldap.ParseDN(entry.DN)
	if err != nil {
		return "", fmt.Errorf("parse DN %q: %w", entry.DN, err)
	}
	attributes := make(map[string][][]byte, len(entry.Attributes))
	for _, attribute := range entry.Attributes {
		if attribute == nil {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(attribute.Name))
		if name == "" {
			return "", fmt.Errorf("entry %q contains an empty attribute name", entry.DN)
		}
		for _, value := range attribute.ByteValues {
			attributes[name] = append(attributes[name], bytes.Clone(value))
		}
	}
	names := make([]string, 0, len(attributes))
	for name := range attributes {
		names = append(names, name)
	}
	sort.Strings(names)

	var result strings.Builder
	result.Grow(len(entry.DN)*2 + len(names)*16)
	writeHex(&result, []byte(parsedDN.String()))
	for _, name := range names {
		values := attributes[name]
		sort.Slice(values, func(left, right int) bool {
			return bytes.Compare(values[left], values[right]) < 0
		})
		for _, value := range values {
			result.WriteByte('\t')
			writeHex(&result, []byte(name))
			result.WriteByte('=')
			writeHex(&result, value)
		}
	}
	return result.String(), nil
}

func writeHex(destination *strings.Builder, value []byte) {
	const digits = "0123456789abcdef"
	for _, character := range value {
		destination.WriteByte(digits[character>>4])
		destination.WriteByte(digits[character&0x0f])
	}
}
