package main

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

type ldapLDIFWidthWriter struct {
	io.Writer
	width uint64
}

func (options *ldapClientOptions) ldifWriter(writer io.Writer) io.Writer {
	if options.ldifWrap == 0 {
		return writer
	}
	return &ldapLDIFWidthWriter{Writer: writer, width: options.ldifWrap}
}

func parseLDAPLDIFWrap(value string, present bool) (uint64, error) {
	if !present {
		return 0, nil
	}
	if strings.EqualFold(value, "no") {
		return math.MaxUint64, nil
	}
	trimmed := strings.TrimLeft(value, " \t\r\n\v\f")
	width, err := strconv.ParseUint(strings.TrimPrefix(trimmed, "+"), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("unable to parse ldif_wrap=%q", value)
	}
	return width, nil
}

// OpenLDAP folds the value after emitting the entire attribute prefix. Explicit
// text/base64/URL and comment output use > wrap; ordinary values use >= wrap.
func writeLDAPLDIFConfiguredLine(writer io.Writer, line []byte, preencoded bool) error {
	configured, ok := writer.(*ldapLDIFWidthWriter)
	if !ok {
		return writeFoldedLDIFLineWithWidth(writer, line, ldapSearchLDIFLineWidth)
	}
	prefix := len(line)
	if bytes.HasPrefix(line, []byte("# ")) {
		prefix, preencoded = 2, true
	} else if colon := bytes.IndexByte(line, ':'); colon >= 0 {
		prefix = colon + 1
		if prefix < len(line) && (line[prefix] == ':' || line[prefix] == '<') {
			prefix++
		}
		if prefix < len(line) && line[prefix] == ' ' {
			prefix++
		}
	}
	return configured.writeLine(line, prefix, preencoded)
}

func (writer *ldapLDIFWidthWriter) writeLine(line []byte, prefix int, preencoded bool) error {
	write := func(value []byte) error {
		n, err := writer.Write(value)
		if err == nil && n != len(value) {
			return io.ErrShortWrite
		}
		return err
	}
	if err := write(line[:prefix]); err != nil {
		return err
	}
	width := writer.width
	if preencoded && width != math.MaxUint64 {
		width++
	}
	column := uint64(prefix)
	for value := line[prefix:]; len(value) != 0; {
		if column >= width {
			if err := write([]byte{'\n', ' '}); err != nil {
				return err
			}
			column = 1
		}
		length := min(uint64(len(value)), max(width-column, 1))
		if err := write(value[:length]); err != nil {
			return err
		}
		value = value[length:]
		column += length
	}
	return write([]byte{'\n'})
}
