package storage

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func boltMetadataKeyPartitions() []struct {
	name      string
	partition string
} {
	allBytes := make([]byte, 256)
	for index := range allBytes {
		allBytes[index] = byte(index)
	}
	return []struct {
		name      string
		partition string
	}{
		{"Empty", ""},
		{"OneByte", "a"},
		{"TwoBytes", "ab"},
		{"ThreeBytes", "abc"},
		{"Database", "olcDatabase={1}mdb,cn=config"},
		{"Binary", "\x00\xff\xfe\x80\x00:;/+=\r\n"},
		{"AllBytes", string(allBytes)},
		{"Unicode", "\u76ee\u5f55/\u5206\u533a/\U0001f512/e\u0301"},
		{"Long", strings.Repeat(string(allBytes), 256)},
	}
}

func TestBoltSchemaAwareDNMigrationMetadataKey(t *testing.T) {
	for _, test := range boltMetadataKeyPartitions() {
		t.Run(test.name, func(t *testing.T) {
			want := genericMetadataKey(schemaAwareDNMigrationMetadataKey(test.partition))
			got := boltSchemaAwareDNMigrationMetadataKey(test.partition)
			if !bytes.Equal(got, want) {
				t.Fatal("metadata key differs from reference")
			}
			other := boltSchemaAwareDNMigrationMetadataKey(test.partition)
			clear(got)
			if !bytes.Equal(other, want) ||
				!bytes.Equal(boltSchemaAwareDNMigrationMetadataKey(test.partition), want) {
				t.Fatal("metadata key shares mutable storage")
			}
		})
	}
	for size := 0; size <= 1024; size++ {
		partition := make([]byte, size)
		for index := range partition {
			partition[index] = byte(index*131 + size)
		}
		got := boltSchemaAwareDNMigrationMetadataKey(string(partition))
		want := genericMetadataKey(schemaAwareDNMigrationMetadataKey(string(partition)))
		if !bytes.Equal(got, want) {
			t.Fatalf("metadata key differs from reference at length %d", size)
		}
	}
}

var boltMetadataKeySink []byte

func TestBoltSchemaAwareDNMigrationMetadataKeyAllocations(t *testing.T) {
	defer func() { boltMetadataKeySink = nil }()
	for _, test := range boltMetadataKeyPartitions() {
		t.Run(test.name, func(t *testing.T) {
			allocations := testing.AllocsPerRun(10, func() {
				boltMetadataKeySink = boltSchemaAwareDNMigrationMetadataKey(test.partition)
			})
			if allocations != 1 {
				t.Fatalf("got %g allocations, want 1", allocations)
			}
		})
	}
}

func FuzzBoltSchemaAwareDNMigrationMetadataKey(f *testing.F) {
	for _, test := range boltMetadataKeyPartitions() {
		f.Add(test.partition)
	}
	for value := 0; value < 256; value++ {
		f.Add(string([]byte{byte(value)}))
	}
	f.Fuzz(func(t *testing.T, partition string) {
		got := boltSchemaAwareDNMigrationMetadataKey(partition)
		want := genericMetadataKey(schemaAwareDNMigrationMetadataKey(partition))
		if !bytes.Equal(got, want) {
			t.Fatalf("metadata key differs from reference for %d partition bytes", len(partition))
		}
	})
}

func BenchmarkBoltSchemaAwareDNMigrationMetadataKey(b *testing.B) {
	defer func() { boltMetadataKeySink = nil }()
	for _, test := range boltMetadataKeyPartitions() {
		for _, implementation := range []struct {
			name string
			key  func(string) []byte
		}{
			{"Direct", boltSchemaAwareDNMigrationMetadataKey},
			{"Reference", func(partition string) []byte {
				return genericMetadataKey(schemaAwareDNMigrationMetadataKey(partition))
			}},
		} {
			b.Run(fmt.Sprintf("%s/%s", test.name, implementation.name), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(test.partition)))
				for b.Loop() {
					boltMetadataKeySink = implementation.key(test.partition)
				}
			})
		}
	}
}
