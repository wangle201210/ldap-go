package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	bolt "go.etcd.io/bbolt"
)

var (
	entriesBucket = []byte("entries")
	metaBucket    = []byte("metadata")
	contextsKey   = []byte("naming-contexts")
)

type Bolt struct {
	db *bolt.DB
}

func OpenBolt(path string) (*Bolt, error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	store := &Bolt{db: db}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(entriesBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(metaBucket)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize database: %w", err)
	}
	return store, nil
}

func (store *Bolt) View(ctx context.Context, fn func(Reader) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.db.View(func(tx *bolt.Tx) error {
		return fn(&boltTx{ctx: ctx, tx: tx, entries: tx.Bucket(entriesBucket), meta: tx.Bucket(metaBucket)})
	})
}

func (store *Bolt) Update(ctx context.Context, fn func(Writer) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.db.Update(func(tx *bolt.Tx) error {
		writer := &boltTx{ctx: ctx, tx: tx, entries: tx.Bucket(entriesBucket), meta: tx.Bucket(metaBucket)}
		if err := fn(writer); err != nil {
			return err
		}
		return ctx.Err()
	})
}

func (store *Bolt) Close() error {
	return store.db.Close()
}

type boltTx struct {
	ctx     context.Context
	tx      *bolt.Tx
	entries *bolt.Bucket
	meta    *bolt.Bucket
}

func (tx *boltTx) Get(dn directory.DN) (directory.Entry, error) {
	if err := tx.ctx.Err(); err != nil {
		return directory.Entry{}, err
	}
	value := tx.entries.Get([]byte(dn.Key()))
	if value == nil {
		return directory.Entry{}, ErrEntryNotFound
	}
	return decodeEntry(value)
}

func (tx *boltTx) ForEach(fn func(directory.Entry) error) error {
	return tx.entries.ForEach(func(_, value []byte) error {
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		entry, err := decodeEntry(value)
		if err != nil {
			return err
		}
		return fn(entry)
	})
}

func (tx *boltTx) NamingContexts() ([]string, error) {
	if err := tx.ctx.Err(); err != nil {
		return nil, err
	}
	value := tx.meta.Get(contextsKey)
	if value == nil {
		return nil, nil
	}
	var contexts []string
	if err := json.Unmarshal(value, &contexts); err != nil {
		return nil, fmt.Errorf("decode naming contexts: %w", err)
	}
	return contexts, nil
}

func (tx *boltTx) Put(entry directory.Entry, replace bool) error {
	if !tx.tx.Writable() {
		return errorsReadOnly()
	}
	if err := tx.ctx.Err(); err != nil {
		return err
	}
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return err
	}
	key := []byte(dn.Key())
	if tx.entries.Get(key) != nil && !replace {
		return ErrEntryExists
	}
	value, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode entry %q: %w", entry.DN, err)
	}
	return tx.entries.Put(key, value)
}

func (tx *boltTx) Delete(dn directory.DN) error {
	if !tx.tx.Writable() {
		return errorsReadOnly()
	}
	key := []byte(dn.Key())
	if tx.entries.Get(key) == nil {
		return ErrEntryNotFound
	}
	return tx.entries.Delete(key)
}

func (tx *boltTx) Clear() error {
	if !tx.tx.Writable() {
		return errorsReadOnly()
	}
	if err := tx.tx.DeleteBucket(entriesBucket); err != nil {
		return err
	}
	bucket, err := tx.tx.CreateBucket(entriesBucket)
	if err != nil {
		return err
	}
	tx.entries = bucket
	return tx.meta.Delete(contextsKey)
}

func (tx *boltTx) SetNamingContexts(contexts []string) error {
	if !tx.tx.Writable() {
		return errorsReadOnly()
	}
	value, err := json.Marshal(contexts)
	if err != nil {
		return fmt.Errorf("encode naming contexts: %w", err)
	}
	return tx.meta.Put(contextsKey, value)
}

func decodeEntry(value []byte) (directory.Entry, error) {
	var entry directory.Entry
	if err := json.Unmarshal(value, &entry); err != nil {
		return directory.Entry{}, fmt.Errorf("decode entry: %w", err)
	}
	return entry, nil
}

func errorsReadOnly() error {
	return errors.New("read-only transaction")
}
