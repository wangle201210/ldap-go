package storage

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
)

var (
	ErrEntryNotFound  = errors.New("entry not found")
	ErrEntryExists    = errors.New("entry already exists")
	ErrEntryAmbiguous = errors.New("entry exists in multiple storage partitions")
)

type Reader interface {
	Get(dn directory.DN) (directory.Entry, error)
	GetIn(partition string, dn directory.DN) (directory.Entry, error)
	ForEach(func(directory.Entry) error) error
	ForEachIn(partition string, fn func(directory.Entry) error) error
	ForEachPartition(fn func(string, directory.Entry) error) error
	NamingContexts() ([]string, error)
}

type Writer interface {
	Reader
	Put(entry directory.Entry, replace bool) error
	PutIn(partition string, entry directory.Entry, replace bool) error
	Delete(dn directory.DN) error
	DeleteIn(partition string, dn directory.DN) error
	Clear() error
	SetNamingContexts(contexts []string) error
}

type Store interface {
	View(ctx context.Context, fn func(Reader) error) error
	Update(ctx context.Context, fn func(Writer) error) error
	Close() error
}

func InferNamingContexts(reader Reader) ([]string, error) {
	return inferNamingContexts(reader.ForEach)
}

func InferNamingContextsIn(reader Reader, partition string) ([]string, error) {
	return inferNamingContexts(func(fn func(directory.Entry) error) error {
		return reader.ForEachIn(partition, fn)
	})
}

func inferNamingContexts(
	forEach func(func(directory.Entry) error) error,
) ([]string, error) {
	type namedDN struct {
		dn  directory.DN
		raw string
	}

	entries := make(map[string]namedDN)
	if err := forEach(func(entry directory.Entry) error {
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
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
