package storage

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/wangle201210/ldap-go/internal/directory"
)

var (
	ErrEntryNotFound    = errors.New("entry not found")
	ErrEntryExists      = errors.New("entry already exists")
	ErrEntryAmbiguous   = errors.New("entry exists in multiple storage partitions")
	ErrMetadataNotFound = errors.New("metadata not found")
)

type Reader interface {
	Get(dn directory.DN) (directory.Entry, error)
	GetIn(partition string, dn directory.DN) (directory.Entry, error)
	ForEach(func(directory.Entry) error) error
	ForEachIn(partition string, fn func(directory.Entry) error) error
	ForEachPartition(fn func(string, directory.Entry) error) error
	NamingContexts() ([]string, error)
	Metadata(key string) ([]byte, error)
}

type Writer interface {
	Reader
	Put(entry directory.Entry, replace bool) error
	PutIn(partition string, entry directory.Entry, replace bool) error
	Delete(dn directory.DN) error
	DeleteIn(partition string, dn directory.DN) error
	Clear() error
	SetNamingContexts(contexts []string) error
	SetMetadata(key string, value []byte) error
	DeleteMetadata(key string) error
}

type Store interface {
	View(ctx context.Context, fn func(Reader) error) error
	Update(ctx context.Context, fn func(Writer) error) error
	Close() error
}

type schemaAwareDNBindingValidator interface {
	validateSchemaAwareDNBindingsIn(
		partition string,
		normalizer directory.DNAttributeNormalizer,
	) error
}

func validateSchemaAwareDNBindingsIn(
	reader Reader,
	partition string,
	normalizer directory.DNAttributeNormalizer,
) error {
	validator, ok := reader.(schemaAwareDNBindingValidator)
	if !ok {
		return nil
	}
	return validator.validateSchemaAwareDNBindingsIn(partition, normalizer)
}

// PutInWithDN stores an entry under an explicitly normalized DN identity. It
// keeps the broad Writer contract backward compatible while allowing importers
// that have loaded cn=config schema to opt into v2 keys.
func PutInWithDN(
	writer Writer,
	partition string,
	entry directory.Entry,
	dn directory.DN,
	replace bool,
) error {
	entryDN, err := directory.ParseDN(entry.DN)
	if err != nil {
		return err
	}
	if !entryDN.EqualExact(dn) {
		return fmt.Errorf(
			"entry DN %q does not match normalized DN %q",
			entry.DN,
			dn.String(),
		)
	}
	identity := dn.Key()
	release, err := trustDNIdentityWrite(partition, entry, identity)
	if err != nil {
		return err
	}
	defer release()
	return writer.PutIn(partition, entry.WithDNIdentity(dn), replace)
}

const schemaAwareDNKeyPrefix = "dn:v2:"

var trustedDNIdentityWrites = struct {
	sync.Mutex
	counts map[[sha256.Size]byte]int
}{counts: make(map[[sha256.Size]byte]int)}

func isSchemaAwareDNKey(key string) bool {
	return strings.HasPrefix(key, schemaAwareDNKeyPrefix)
}

func trustDNIdentityWrite(
	partition string,
	entry directory.Entry,
	identity string,
) (func(), error) {
	key, err := dnIdentityWriteKey(partition, entry, identity)
	if err != nil {
		return nil, err
	}
	trustedDNIdentityWrites.Lock()
	trustedDNIdentityWrites.counts[key]++
	trustedDNIdentityWrites.Unlock()
	return func() {
		trustedDNIdentityWrites.Lock()
		if trustedDNIdentityWrites.counts[key] <= 1 {
			delete(trustedDNIdentityWrites.counts, key)
		} else {
			trustedDNIdentityWrites.counts[key]--
		}
		trustedDNIdentityWrites.Unlock()
	}, nil
}

func requireTrustedDNIdentityWrite(
	partition string,
	entry directory.Entry,
	identity string,
) error {
	key, err := dnIdentityWriteKey(partition, entry, identity)
	if err != nil {
		return err
	}
	trustedDNIdentityWrites.Lock()
	trusted := trustedDNIdentityWrites.counts[key] > 0
	trustedDNIdentityWrites.Unlock()
	if !trusted {
		return errors.New("schema-aware DN identity must be written through PutInWithDN")
	}
	return nil
}

func dnIdentityWriteKey(
	partition string,
	entry directory.Entry,
	identity string,
) ([sha256.Size]byte, error) {
	encodedEntry, err := json.Marshal(entry.WithoutDNIdentity())
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("encode entry %q identity proof: %w", entry.DN, err)
	}
	hash := sha256.New()
	var length [8]byte
	for _, value := range [][]byte{[]byte(partition), encodedEntry, []byte(identity)} {
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(value)
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func validateDirectIdentityLookup(
	physicalKey string,
	requested directory.DN,
) error {
	if !isSchemaAwareDNKey(physicalKey) {
		return nil
	}
	if physicalKey != requested.Key() {
		return fmt.Errorf(
			"schema-aware physical key %q does not match requested DN identity %q",
			physicalKey,
			requested.Key(),
		)
	}
	return nil
}

func validateStoredEntryIdentity(
	physicalKey string,
	entry directory.Entry,
	storedIdentity string,
	storedSource string,
) error {
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return fmt.Errorf("invalid entry DN %q: %w", entry.DN, err)
	}
	if isSchemaAwareDNKey(physicalKey) {
		if storedIdentity == "" {
			return fmt.Errorf(
				"schema-aware physical key %q has no DN identity binding",
				physicalKey,
			)
		}
		if storedIdentity != physicalKey {
			return fmt.Errorf(
				"schema-aware physical key %q does not match stored DN identity %q",
				physicalKey,
				storedIdentity,
			)
		}
		if storedSource == "" {
			return fmt.Errorf(
				"schema-aware physical key %q has no source DN binding",
				physicalKey,
			)
		}
		sourceDN, err := directory.ParseDN(storedSource)
		if err != nil {
			return fmt.Errorf("invalid stored source DN %q: %w", storedSource, err)
		}
		if !sourceDN.EqualExact(dn) {
			return fmt.Errorf(
				"stored source DN %q does not match entry DN %q",
				storedSource,
				entry.DN,
			)
		}
		if err := dn.ValidateIdentityKey(physicalKey); err != nil {
			return fmt.Errorf("invalid schema-aware physical key %q: %w", physicalKey, err)
		}
		return nil
	}
	if storedIdentity != "" || storedSource != "" {
		return fmt.Errorf(
			"legacy physical key %q unexpectedly carries DN identity binding",
			physicalKey,
		)
	}
	if err := dn.ValidateIdentityKey(physicalKey); err != nil {
		return fmt.Errorf(
			"physical key %q does not match normalized DN %q: %w",
			physicalKey,
			entry.DN,
			err,
		)
	}
	return nil
}

func InferNamingContexts(reader Reader) ([]string, error) {
	return inferNamingContexts(func(fn func(directory.Entry, directory.DN) error) error {
		return reader.ForEach(func(entry directory.Entry) error {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			return fn(entry, dn)
		})
	})
}

func InferNamingContextsIn(reader Reader, partition string) ([]string, error) {
	return inferNamingContexts(func(fn func(directory.Entry, directory.DN) error) error {
		return reader.ForEachIn(partition, func(entry directory.Entry) error {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			return fn(entry, dn)
		})
	})
}

func InferNamingContextsWithNormalizer(
	reader Reader,
	normalizer directory.DNAttributeNormalizer,
) ([]string, error) {
	configurationSuffix, err := directory.ParseDN("cn=config")
	if err != nil {
		return nil, err
	}
	return inferNamingContexts(func(fn func(directory.Entry, directory.DN) error) error {
		return reader.ForEachPartition(func(partition string, entry directory.Entry) error {
			legacy, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			dn := legacy
			if partition != OpenLDAPConfigPartition &&
				!configurationSuffix.Equal(legacy) &&
				!configurationSuffix.AncestorOf(legacy) {
				dn, err = directory.ParseDNWithNormalizer(entry.DN, normalizer)
			}
			if err != nil {
				return err
			}
			return fn(entry, dn)
		})
	})
}

func inferNamingContexts(
	forEach func(func(directory.Entry, directory.DN) error) error,
) ([]string, error) {
	type namedDN struct {
		dn  directory.DN
		raw string
	}

	entries := make(map[string]namedDN)
	if err := forEach(func(entry directory.Entry, dn directory.DN) error {
		if dn.Depth() == 0 {
			return nil
		}
		entries[dn.Key()] = namedDN{dn: dn, raw: entry.DN}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("scan directory entries: %w", err)
	}

	contexts := make([]namedDN, 0)
	for _, entry := range entries {
		parent, hasParent := entry.dn.Parent()
		if !hasParent || parent.Depth() == 0 {
			contexts = append(contexts, entry)
			continue
		}
		if _, exists := entries[parent.Key()]; !exists {
			contexts = append(contexts, entry)
		}
	}
	sort.Slice(contexts, func(i, j int) bool {
		return contexts[i].dn.Key() < contexts[j].dn.Key()
	})

	result := make([]string, len(contexts))
	for i := range contexts {
		result[i] = contexts[i].raw
	}
	return result, nil
}

func partitionedEntryKey(partition, dnKey string) string {
	return partition + "\x00" + dnKey
}

func splitPartitionedEntryKey(key string) (partition, dnKey string) {
	index := strings.IndexByte(key, 0)
	if index < 0 {
		return "", key
	}
	return key[:index], key[index+1:]
}

func entryMatchesDisplayDN(entry directory.Entry, requested directory.DN) bool {
	entryDN, err := directory.ParseDN(entry.DN)
	return err == nil && entryDN.EqualExact(requested)
}
