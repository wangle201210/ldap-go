package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/wangle201210/ldap-go/internal/storage"
)

type ReverseLookupResolver interface {
	LookupAddr(context.Context, string) ([]string, error)
}

func loadReverseLookup(reader storage.Reader) (bool, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("load olcReverseLookup: %w", err)
	}
	enabled, _, err := singleBoolean(entry, "olcReverseLookup")
	return enabled, err
}

func (server *Server) connectionDomainName(ctx context.Context, address net.Addr) string {
	runtime := server.runtime.Load()
	if runtime == nil || !runtime.reverseLookup || address == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil || net.ParseIP(host) == nil {
		return ""
	}
	resolver := server.config.ReverseLookupResolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	names, err := resolver.LookupAddr(ctx, host)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(names[0], "."))
}
