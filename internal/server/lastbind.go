package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type lastBindResponseConnection struct {
	net.Conn
	ctx    context.Context
	server *Server
	state  *connectionState
	once   sync.Once
}

func (connection *lastBindResponseConnection) Write(value []byte) (int, error) {
	connection.once.Do(func() {
		if connection.server != nil && connection.state != nil &&
			connection.state.boundDN != "" {
			connection.server.recordLastBindOverlay(connection.ctx, connection.state)
		}
	})
	return connection.Conn.Write(value)
}

func (server *Server) recordLastBindOverlay(
	ctx context.Context,
	state *connectionState,
) {
	if state == nil || state.runtime == nil || state.boundDN == "" {
		return
	}
	dn, err := parseRuntimeConnectionDN(state.runtime, state.boundDN)
	if err != nil {
		return
	}
	database := databaseForDN(state.runtime, dn)
	if database == nil || !database.lastBindOverlay {
		return
	}
	if database.shadow && database.lastBindForwardUpdates {
		err = server.forwardLastBindOverlay(ctx, state.runtime, *database, dn)
	} else {
		err = server.writeLastBindOverlay(ctx, *database, dn)
	}
	if err != nil {
		server.config.Logger.Debug(
			"lastbind authTimestamp update failed",
			"dn", dn.String(),
			"error", err,
		)
	}
}

func (server *Server) writeLastBindOverlay(
	ctx context.Context,
	database runtimeDatabase,
	dn directory.DN,
) error {
	now := server.clock().UTC()
	return server.config.Store.Update(ctx, func(writer storage.Writer) error {
		tx := writerForDatabase(writer, database)
		normalized, err := storage.NormalizeReaderDN(tx, dn)
		if err != nil {
			return err
		}
		entry, err := tx.Get(normalized)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !applyLastBindTimestamp(&entry, now, database.lastBindPrecision) {
			return nil
		}
		return tx.Put(entry, true)
	})
}

func (server *Server) forwardLastBindOverlay(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	dn directory.DN,
) error {
	var before, after directory.Entry
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, database)
		normalized, err := storage.NormalizeReaderDN(tx, dn)
		if err != nil {
			return err
		}
		before, err = tx.Get(normalized)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		after = before.Clone()
		applyLastBindTimestamp(&after, server.clock().UTC(), database.lastBindPrecision)
		return nil
	})
	if err != nil || after.DN == "" || before.Equal(after) {
		return err
	}
	return server.forwardPasswordPolicyBindState(ctx, runtime, database, before, after)
}

func applyLastBindTimestamp(entry *directory.Entry, now time.Time, precision int) bool {
	if entry == nil {
		return false
	}
	if value, present := singlePasswordPolicyTime(*entry, "authTimestamp"); present {
		previous, valid := parsePasswordPolicyTime(value)
		if valid && now.Sub(previous) < time.Duration(precision)*time.Second {
			return false
		}
	}
	entry.ReplaceValues(
		"authTimestamp",
		[][]byte{[]byte(formatPasswordPolicyTime(now))},
	)
	return true
}
