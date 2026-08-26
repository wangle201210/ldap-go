package audit

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

const (
	recordVersion   = 1
	minimumKeySize  = 32
	maximumLineSize = 1 << 20
)

// Event contains operation metadata and explicitly bounded session-tracking
// metadata. Directory assertions, attribute values, and credentials remain
// absent so callers cannot accidentally persist them.
type Event struct {
	Timestamp               time.Time         `json:"timestamp"`
	ConnectionID            uint64            `json:"connection_id"`
	MessageID               int64             `json:"message_id"`
	RelatedMessageID        int64             `json:"related_message_id,omitempty"`
	Operation               string            `json:"operation"`
	TargetDN                string            `json:"target_dn,omitempty"`
	ExtendedOperation       string            `json:"extended_operation,omitempty"`
	AuthenticationDN        string            `json:"authentication_dn,omitempty"`
	AuthorizationDN         string            `json:"authorization_dn,omitempty"`
	AuthenticationMechanism string            `json:"authentication_mechanism,omitempty"`
	RemoteAddress           string            `json:"remote_address,omitempty"`
	Secure                  bool              `json:"secure"`
	SecurityStrengthFactor  uint32            `json:"security_strength_factor,omitempty"`
	RequestControls         []string          `json:"request_controls,omitempty"`
	SessionTracking         []SessionTracking `json:"session_tracking,omitempty"`
	ResultCode              *int              `json:"result_code,omitempty"`
	Outcome                 string            `json:"outcome"`
	DurationMicros          int64             `json:"duration_micros"`
}

type SessionTracking struct {
	SourceIP          string `json:"source_ip,omitempty"`
	SourceName        string `json:"source_name,omitempty"`
	FormatOID         string `json:"format_oid"`
	FormatName        string `json:"format_name,omitempty"`
	Identifier        string `json:"identifier,omitempty"`
	IdentifierPresent bool   `json:"identifier_present,omitempty"`
	Trusted           bool   `json:"trusted"`
}

type Sink interface {
	Record(Event) error
}

type chainedRecord struct {
	Version   int    `json:"version"`
	Sequence  uint64 `json:"sequence"`
	Previous  string `json:"previous,omitempty"`
	Event     Event  `json:"event"`
	Integrity string `json:"integrity"`
}

type chainPayload struct {
	Version  int    `json:"version"`
	Sequence uint64 `json:"sequence"`
	Previous string `json:"previous,omitempty"`
	Event    Event  `json:"event"`
}

type syncWriter interface {
	Sync() error
}

type ChainWriter struct {
	mu       sync.Mutex
	writer   io.Writer
	syncer   syncWriter
	key      []byte
	sequence uint64
	previous string
	closed   bool
}

func NewChainWriter(writer io.Writer, key []byte) (*ChainWriter, error) {
	return newChainWriter(writer, key, Verification{})
}

func newChainWriter(
	writer io.Writer,
	key []byte,
	state Verification,
) (*ChainWriter, error) {
	if writer == nil {
		return nil, errors.New("audit writer is required")
	}
	if len(key) < minimumKeySize {
		return nil, fmt.Errorf("audit integrity key must contain at least %d bytes", minimumKeySize)
	}
	result := &ChainWriter{
		writer:   writer,
		key:      bytes.Clone(key),
		sequence: state.Records,
		previous: state.LastIntegrity,
	}
	if syncer, ok := writer.(syncWriter); ok {
		result.syncer = syncer
	}
	return result, nil
}

func (writer *ChainWriter) Record(event Event) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed {
		return errors.New("audit writer is closed")
	}
	if event.Operation == "" {
		return errors.New("audit operation is required")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	} else {
		event.Timestamp = event.Timestamp.UTC()
	}

	payload := chainPayload{
		Version:  recordVersion,
		Sequence: writer.sequence + 1,
		Previous: writer.previous,
		Event:    event,
	}
	integrity, err := signPayload(payload, writer.key)
	if err != nil {
		return err
	}
	record := chainedRecord{
		Version:   payload.Version,
		Sequence:  payload.Sequence,
		Previous:  payload.Previous,
		Event:     payload.Event,
		Integrity: integrity,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode audit record: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := writeFull(writer.writer, encoded); err != nil {
		return fmt.Errorf("write audit record: %w", err)
	}
	writer.sequence = payload.Sequence
	writer.previous = integrity
	if writer.syncer != nil {
		if err := writer.syncer.Sync(); err != nil {
			return fmt.Errorf("sync audit record: %w", err)
		}
	}
	return nil
}

func writeFull(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func signPayload(payload chainPayload, key []byte) (string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode audit integrity payload: %w", err)
	}
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write(encoded)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

type Verification struct {
	Records       uint64
	LastIntegrity string
}

func VerifyFile(path string, key []byte) (Verification, error) {
	if path == "" {
		return Verification{}, errors.New("audit log path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return Verification{}, fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Verification{}, fmt.Errorf("stat audit log: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Verification{}, errors.New("audit log must be a regular file")
	}
	if info.Size() > 0 {
		if _, err := file.Seek(-1, io.SeekEnd); err != nil {
			return Verification{}, fmt.Errorf("inspect audit log ending: %w", err)
		}
		ending := []byte{0}
		if _, err := io.ReadFull(file, ending); err != nil {
			return Verification{}, fmt.Errorf("read audit log ending: %w", err)
		}
		if ending[0] != '\n' {
			return Verification{}, errors.New("audit log ends with a truncated record")
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return Verification{}, fmt.Errorf("rewind audit log: %w", err)
	}
	return Verify(file, key)
}

func Verify(reader io.Reader, key []byte) (Verification, error) {
	if reader == nil {
		return Verification{}, errors.New("audit reader is required")
	}
	if len(key) < minimumKeySize {
		return Verification{}, fmt.Errorf(
			"audit integrity key must contain at least %d bytes",
			minimumKeySize,
		)
	}

	var state Verification
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), maximumLineSize)
	for scanner.Scan() {
		lineNumber := state.Records + 1
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			return Verification{}, fmt.Errorf("audit record %d is empty", lineNumber)
		}
		var record chainedRecord
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil {
			return Verification{}, fmt.Errorf("decode audit record %d: %w", lineNumber, err)
		}
		if decoder.Decode(&struct{}{}) != io.EOF {
			return Verification{}, fmt.Errorf("audit record %d has trailing JSON data", lineNumber)
		}
		if record.Version != recordVersion {
			return Verification{}, fmt.Errorf(
				"audit record %d has unsupported version %d",
				lineNumber,
				record.Version,
			)
		}
		if record.Sequence != lineNumber {
			return Verification{}, fmt.Errorf(
				"audit record %d has sequence %d",
				lineNumber,
				record.Sequence,
			)
		}
		if record.Previous != state.LastIntegrity {
			return Verification{}, fmt.Errorf("audit record %d breaks the integrity chain", lineNumber)
		}
		payload := chainPayload{
			Version:  record.Version,
			Sequence: record.Sequence,
			Previous: record.Previous,
			Event:    record.Event,
		}
		expected, err := signPayload(payload, key)
		if err != nil {
			return Verification{}, err
		}
		actual, err := hex.DecodeString(record.Integrity)
		if err != nil {
			return Verification{}, fmt.Errorf("audit record %d has invalid integrity data", lineNumber)
		}
		expectedBytes, _ := hex.DecodeString(expected)
		if !hmac.Equal(actual, expectedBytes) {
			return Verification{}, fmt.Errorf("audit record %d failed integrity verification", lineNumber)
		}
		state.Records = record.Sequence
		state.LastIntegrity = record.Integrity
	}
	if err := scanner.Err(); err != nil {
		return Verification{}, fmt.Errorf("read audit log: %w", err)
	}
	return state, nil
}

type FileSink struct {
	writer *ChainWriter
	file   *os.File
}

func OpenFile(path string, key []byte) (*FileSink, error) {
	if path == "" {
		return nil, errors.New("audit log path is required")
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	closeWithError := func(openErr error) (*FileSink, error) {
		_ = file.Close()
		return nil, openErr
	}
	if err := file.Chmod(0o600); err != nil {
		return closeWithError(fmt.Errorf("secure audit log permissions: %w", err))
	}
	info, err := file.Stat()
	if err != nil {
		return closeWithError(fmt.Errorf("stat audit log: %w", err))
	}
	if !info.Mode().IsRegular() {
		return closeWithError(errors.New("audit log must be a regular file"))
	}
	if info.Size() > 0 {
		if _, err := file.Seek(-1, io.SeekEnd); err != nil {
			return closeWithError(fmt.Errorf("inspect audit log ending: %w", err))
		}
		ending := []byte{0}
		if _, err := io.ReadFull(file, ending); err != nil {
			return closeWithError(fmt.Errorf("read audit log ending: %w", err))
		}
		if ending[0] != '\n' {
			return closeWithError(errors.New("audit log ends with a truncated record"))
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return closeWithError(fmt.Errorf("rewind audit log: %w", err))
	}
	state, err := Verify(file, key)
	if err != nil {
		return closeWithError(err)
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return closeWithError(fmt.Errorf("seek to audit log end: %w", err))
	}
	writer, err := newChainWriter(file, key, state)
	if err != nil {
		return closeWithError(err)
	}
	return &FileSink{writer: writer, file: file}, nil
}

func (sink *FileSink) Record(event Event) error {
	return sink.writer.Record(event)
}

func (sink *FileSink) Close() error {
	sink.writer.mu.Lock()
	defer sink.writer.mu.Unlock()
	if sink.writer.closed {
		return nil
	}
	sink.writer.closed = true
	clear(sink.writer.key)
	syncErr := sink.file.Sync()
	closeErr := sink.file.Close()
	return errors.Join(syncErr, closeErr)
}
