package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestChainWriterVerifyAndDetectTampering(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x42}, minimumKeySize)
	var log bytes.Buffer
	writer, err := NewChainWriter(&log, key)
	if err != nil {
		t.Fatalf("NewChainWriter(): %v", err)
	}
	success := 0
	for _, event := range []Event{
		{
			Timestamp:      time.Date(2026, 8, 2, 10, 0, 0, 0, time.FixedZone("test", 8*60*60)),
			ConnectionID:   7,
			MessageID:      1,
			Operation:      "bind",
			TargetDN:       "uid=alice,dc=example,dc=com",
			ResultCode:     &success,
			Outcome:        "success",
			DurationMicros: 25,
		},
		{
			ConnectionID:   7,
			MessageID:      2,
			Operation:      "search",
			TargetDN:       "dc=example,dc=com",
			ResultCode:     &success,
			Outcome:        "success",
			DurationMicros: 40,
			SessionTracking: []SessionTracking{{
				SourceIP: "192.0.2.10", FormatOID: "1.2.3",
				Identifier: "session-1", IdentifierPresent: true,
			}},
		},
	} {
		if err := writer.Record(event); err != nil {
			t.Fatalf("Record(): %v", err)
		}
	}

	verified, err := Verify(bytes.NewReader(log.Bytes()), key)
	if err != nil {
		t.Fatalf("Verify(): %v", err)
	}
	if verified.Records != 2 || len(verified.LastIntegrity) != sha256HexSize {
		t.Fatalf("verification = %#v", verified)
	}

	lines := bytes.Split(bytes.TrimSpace(log.Bytes()), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("audit lines = %d", len(lines))
	}
	var second chainedRecord
	if err := json.Unmarshal(lines[1], &second); err != nil {
		t.Fatalf("decode second record: %v", err)
	}
	var first chainedRecord
	if err := json.Unmarshal(lines[0], &first); err != nil {
		t.Fatalf("decode first record: %v", err)
	}
	if second.Previous != first.Integrity {
		t.Fatalf("second previous = %q, want %q", second.Previous, first.Integrity)
	}
	if len(second.Event.SessionTracking) != 1 ||
		second.Event.SessionTracking[0].Identifier != "session-1" ||
		second.Event.SessionTracking[0].Trusted {
		t.Fatalf("session tracking audit JSON = %#v", second.Event.SessionTracking)
	}

	tampered := bytes.Replace(
		bytes.Clone(log.Bytes()),
		[]byte("uid=alice"),
		[]byte("uid=mallory"),
		1,
	)
	if _, err := Verify(bytes.NewReader(tampered), key); err == nil ||
		!strings.Contains(err.Error(), "integrity") {
		t.Fatalf("Verify(tampered) error = %v", err)
	}
	wrongKey := bytes.Repeat([]byte{0x24}, minimumKeySize)
	if _, err := Verify(bytes.NewReader(log.Bytes()), wrongKey); err == nil {
		t.Fatal("Verify() accepted a different integrity key")
	}
}

const sha256HexSize = 64

func TestFileSinkResumesVerifiedChain(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	key := bytes.Repeat([]byte("k"), minimumKeySize)
	first, err := OpenFile(path, key)
	if err != nil {
		t.Fatalf("OpenFile(first): %v", err)
	}
	if err := first.Record(Event{Operation: "bind", Outcome: "failure"}); err != nil {
		t.Fatalf("Record(first): %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close(first): %v", err)
	}

	second, err := OpenFile(path, key)
	if err != nil {
		t.Fatalf("OpenFile(second): %v", err)
	}
	if err := second.Record(Event{Operation: "search", Outcome: "success"}); err != nil {
		t.Fatalf("Record(second): %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("Close(second): %v", err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	verified, verifyErr := Verify(file, key)
	closeErr := file.Close()
	if verifyErr != nil || closeErr != nil {
		t.Fatalf("Verify(file) = %#v, %v, close = %v", verified, verifyErr, closeErr)
	}
	if verified.Records != 2 {
		t.Fatalf("records = %d, want 2", verified.Records)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(): %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("audit permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestFileSinkRejectsTruncatedLog(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	key := bytes.Repeat([]byte("t"), minimumKeySize)
	if err := os.WriteFile(path, []byte(`{"version":1`), 0o600); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	if _, err := OpenFile(path, key); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("OpenFile(truncated) error = %v", err)
	}
}

func TestChainWriterSerializesConcurrentEvents(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte("c"), minimumKeySize)
	var log bytes.Buffer
	writer, err := NewChainWriter(&log, key)
	if err != nil {
		t.Fatalf("NewChainWriter(): %v", err)
	}
	const events = 64
	var wait sync.WaitGroup
	for index := 0; index < events; index++ {
		wait.Add(1)
		go func(messageID int64) {
			defer wait.Done()
			if err := writer.Record(Event{
				MessageID: messageID,
				Operation: "search",
				Outcome:   "success",
			}); err != nil {
				t.Errorf("Record(%d): %v", messageID, err)
			}
		}(int64(index + 1))
	}
	wait.Wait()
	verified, err := Verify(bytes.NewReader(log.Bytes()), key)
	if err != nil {
		t.Fatalf("Verify(): %v", err)
	}
	if verified.Records != events {
		t.Fatalf("records = %d, want %d", verified.Records, events)
	}
}

func TestChainWriterRejectsWeakKeyAndMissingOperation(t *testing.T) {
	t.Parallel()

	if _, err := NewChainWriter(&bytes.Buffer{}, []byte("short")); err == nil {
		t.Fatal("NewChainWriter() accepted a short key")
	}
	writer, err := NewChainWriter(
		&bytes.Buffer{},
		bytes.Repeat([]byte("s"), minimumKeySize),
	)
	if err != nil {
		t.Fatalf("NewChainWriter(): %v", err)
	}
	if err := writer.Record(Event{}); err == nil {
		t.Fatal("Record() accepted an event without an operation")
	}
}
