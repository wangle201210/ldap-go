package storage

import (
	"context"
	"errors"

	"github.com/wangle201210/ldap-go/internal/directory"
)

var (
	ErrEntryNotFound = errors.New("entry not found")
	ErrEntryExists   = errors.New("entry already exists")
)

type Reader interface {
	Get(dn directory.DN) (directory.Entry, error)
	ForEach(func(directory.Entry) error) error
	NamingContexts() ([]string, error)
}

type Writer interface {
	Reader
	Put(entry directory.Entry, replace bool) error
	Delete(dn directory.DN) error
	Clear() error
	SetNamingContexts(contexts []string) error
}

type Store interface {
	View(ctx context.Context, fn func(Reader) error) error
	Update(ctx context.Context, fn func(Writer) error) error
	Close() error
}
