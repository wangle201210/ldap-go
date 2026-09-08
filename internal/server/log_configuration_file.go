package server

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type openLDAPLogFile struct {
	mu            sync.Mutex
	configuration openLDAPLogFileConfiguration
	file          *os.File
	size          int64
	created       time.Time
	clock         func() time.Time
	hostname      string
	processID     int
	closed        bool
	references    int
	directory     *os.Root
	name          string
}

func openConfiguredLDAPLogFile(
	configuration openLDAPLogFileConfiguration,
	clock func() time.Time,
) (*openLDAPLogFile, error) {
	if configuration.path == "" {
		return nil, nil
	}
	if clock == nil {
		clock = time.Now
	}
	directory, err := os.OpenRoot(filepath.Dir(configuration.path))
	if err != nil {
		return nil, err
	}
	name := filepath.Base(configuration.path)
	file, information, err := openLDAPLogPath(directory, name, false)
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "localhost"
	}
	created, err := openLDAPLogChangeTime(file, information)
	if err != nil {
		_ = file.Close()
		_ = directory.Close()
		return nil, err
	}
	if information.Size() == 0 {
		created = clock().Truncate(time.Second)
	}
	return &openLDAPLogFile{
		configuration: configuration,
		file:          file,
		size:          information.Size(),
		created:       created,
		clock:         clock,
		hostname:      hostname,
		processID:     os.Getpid(),
		references:    1,
		directory:     directory,
		name:          name,
	}, nil
}

func openLDAPLogPath(root *os.Root, name string, exclusive bool) (*os.File, os.FileInfo, error) {
	before, err := root.Lstat(name)
	if err == nil && !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("logfile %q is not a regular file", name)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND | openLDAPLogOpenFlags
	if before == nil || exclusive {
		flags |= os.O_EXCL
	}
	file, err := root.OpenFile(name, flags, 0o640)
	if err != nil {
		return nil, nil, err
	}
	information, err := file.Stat()
	if err == nil && (!information.Mode().IsRegular() ||
		(before != nil && !os.SameFile(before, information))) {
		err = fmt.Errorf("logfile %q is not the expected regular file", name)
	}
	if err == nil {
		err = validateOpenLDAPLogHandle(file, information)
	}
	if err == nil {
		after, statErr := root.Lstat(name)
		if statErr != nil {
			err = statErr
		} else if !after.Mode().IsRegular() || !os.SameFile(after, information) {
			err = fmt.Errorf("logfile %q changed while opening", name)
		}
	}
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, information, nil
}

func (file *openLDAPLogFile) close() error {
	if file == nil {
		return nil
	}
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed {
		return nil
	}
	file.references--
	if file.references > 0 {
		return nil
	}
	file.closed = true
	return errors.Join(file.file.Close(), file.directory.Close())
}

func (file *openLDAPLogFile) write(
	record slog.Record,
	attributes []byte,
	groups []string,
) error {
	return file.writeMessage(formatOpenLDAPLogMessage(record, attributes, groups))
}

func (file *openLDAPLogFile) writeMessage(message []byte) error {
	if file == nil {
		return errors.New("OpenLDAP logfile is not configured")
	}
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed {
		return os.ErrClosed
	}
	now := file.clock()
	encoded := append(file.formatPrefix(now), message...)
	var rotationError error
	if file.shouldRotate(now, int64(len(encoded))) {
		rotationError = file.rotate(now)
	}
	written, err := file.file.Write(encoded)
	if written > 0 {
		file.size += int64(written)
	}
	if err != nil {
		return err
	}
	if written != len(encoded) {
		return fmt.Errorf("short OpenLDAP logfile write: wrote %d of %d bytes", written, len(encoded))
	}
	return rotationError
}

func (file *openLDAPLogFile) shouldRotate(now time.Time, next int64) bool {
	rotation := file.configuration.rotation
	return rotation.maximum != 0 &&
		((rotation.bytes != 0 && file.size+next > rotation.bytes) ||
			(rotation.age != 0 && now.Sub(file.created) >= rotation.age))
}

func (file *openLDAPLogFile) rotate(now time.Time) error {
	root, path := file.directory, file.name
	// Never rotate a pathname that no longer names our open regular file.
	current, err := root.Lstat(path)
	opened, statErr := file.file.Stat()
	if err != nil || statErr != nil || !current.Mode().IsRegular() || !os.SameFile(current, opened) {
		return fmt.Errorf("OpenLDAP logfile changed before rotation: %w", errors.Join(err, statErr, os.ErrInvalid))
	}
	if err := validateOpenLDAPLogHandle(file.file, opened); err != nil {
		return err
	}
	for index := 1; index <= file.configuration.rotation.maximum; index++ {
		information, err := root.Lstat(fmt.Sprintf("%s.%02d", path, index))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !information.Mode().IsRegular() {
			return fmt.Errorf("OpenLDAP rotation target is not a regular file")
		}
	}
	// Reserve a unique staging name; never overwrite an existing .tmp file.
	temporary := ".ldap-go-log-" + rand.Text()
	staged, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	_ = staged.Close()
	if err := root.Rename(path, temporary); err != nil {
		_ = root.Remove(temporary)
		return fmt.Errorf("rename OpenLDAP logfile for rotation: %w", err)
	}
	next, information, err := openLDAPLogPath(root, path, true)
	if err != nil {
		// Restore only if no other process has occupied the original name.
		if _, missing := root.Lstat(path); errors.Is(missing, os.ErrNotExist) {
			_ = root.Rename(temporary, path)
		}
		return fmt.Errorf("reopen OpenLDAP logfile after rotation: %w", err)
	}
	previous := file.file
	file.file = next
	file.size = information.Size()
	file.created = now
	_ = previous.Close()

	for index := file.configuration.rotation.maximum; index > 1; index-- {
		if err := root.Rename(
			fmt.Sprintf("%s.%02d", path, index-1),
			fmt.Sprintf("%s.%02d", path, index),
		); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("shift OpenLDAP logfile rotation: %w", err)
		}
	}
	if err := root.Rename(temporary, path+".01"); err != nil {
		return fmt.Errorf("finish OpenLDAP logfile rotation: %w", err)
	}
	return nil
}

func (file *openLDAPLogFile) formatPrefix(now time.Time) []byte {
	buffer := make([]byte, 0, 256)
	switch file.configuration.format {
	case openLDAPLogFileFormatSyslogUTC:
		buffer = file.appendSyslogPrefix(buffer, now.UTC())
	case openLDAPLogFileFormatSyslogLocaltime:
		buffer = file.appendSyslogPrefix(buffer, now.In(time.Local))
	case openLDAPLogFileFormatRFC3339UTC:
		buffer = append(buffer, now.UTC().Format("2006-01-02T15:04:05.000000000Z")...)
		buffer = file.appendProcessPrefix(buffer)
	default:
		buffer = strconv.AppendInt(buffer, now.Unix(), 16)
		buffer = append(buffer, '.')
		buffer = fmt.Appendf(buffer, "%08x 0x0 ", now.Nanosecond())
	}
	return buffer
}

// Resolve user LogValuers before taking destination or file locks. A LogValuer
// may itself log, or trigger a configuration change.
func formatOpenLDAPLogMessage(record slog.Record, attributes []byte, groups []string) []byte {
	buffer := make([]byte, 0, 256)
	if strings.ContainsAny(record.Message, "\r\n") {
		buffer = strconv.AppendQuote(buffer, record.Message)
	} else {
		buffer = append(buffer, record.Message...)
	}
	buffer = append(buffer, attributes...)
	record.Attrs(func(attribute slog.Attr) bool {
		buffer = appendOpenLDAPLogAttribute(buffer, groups, attribute)
		return true
	})
	buffer = append(buffer, '\n')
	return buffer
}

func (file *openLDAPLogFile) appendSyslogPrefix(buffer []byte, value time.Time) []byte {
	buffer = append(buffer, value.Format("Jan 02 15:04:05")...)
	return file.appendProcessPrefix(buffer)
}

func (file *openLDAPLogFile) appendProcessPrefix(buffer []byte) []byte {
	buffer = append(buffer, ' ')
	buffer = append(buffer, file.hostname...)
	buffer = append(buffer, " slapd["...)
	buffer = strconv.AppendInt(buffer, int64(file.processID), 10)
	return append(buffer, "]: "...)
}

func appendOpenLDAPLogAttribute(
	buffer []byte,
	groups []string,
	attribute slog.Attr,
) []byte {
	attribute.Value = attribute.Value.Resolve()
	if attribute.Equal(slog.Attr{}) {
		return buffer
	}
	if attribute.Value.Kind() == slog.KindGroup {
		if attribute.Key != "" {
			groups = append(append([]string(nil), groups...), attribute.Key)
		}
		return appendOpenLDAPLogAttributes(
			buffer,
			groups,
			attribute.Value.Group(),
		)
	}
	buffer = append(buffer, ' ')
	key := attribute.Key
	if len(groups) > 0 {
		key = strings.Join(groups, ".") + "." + key
	}
	if strings.ContainsAny(key, " \t\r\n=\"") {
		buffer = strconv.AppendQuote(buffer, key)
	} else {
		buffer = append(buffer, key...)
	}
	buffer = append(buffer, '=')
	value := attribute.Value.String()
	if strings.ContainsAny(value, " \t\r\n=\"") || value == "" {
		return strconv.AppendQuote(buffer, value)
	}
	return append(buffer, value...)
}

func appendOpenLDAPLogAttributes(
	buffer []byte,
	groups []string,
	attributes []slog.Attr,
) []byte {
	for _, attribute := range attributes {
		buffer = appendOpenLDAPLogAttribute(buffer, groups, attribute)
	}
	return buffer
}
