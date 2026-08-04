package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type translucentRuntimeConfiguration struct {
	configDNKey string
	disabled    bool
	strict      bool
	noGlue      bool
	local       translucentAttributeSet
	remote      translucentAttributeSet
	bindLocal   bool
	pwmodLocal  bool
	backend     ldapBackendRuntimeConfiguration
}

func loadTranslucentRuntimeConfiguration(
	reader storage.Reader,
	overlay directory.Entry,
) (translucentRuntimeConfiguration, error) {
	overlayDN, err := directory.ParseDN(overlay.DN)
	if err != nil {
		return translucentRuntimeConfiguration{}, fmt.Errorf(
			"parse translucent overlay DN %q: %w",
			overlay.DN,
			err,
		)
	}
	if !translucentEntryHasObjectClass(overlay, "olcTranslucentConfig") {
		return translucentRuntimeConfiguration{}, fmt.Errorf(
			"%s translucent overlay requires objectClass olcTranslucentConfig",
			overlay.DN,
		)
	}
	disabled, _, err := singleBoolean(overlay, "olcDisabled")
	if err != nil {
		return translucentRuntimeConfiguration{}, err
	}
	strict, _, err := singleBoolean(overlay, "olcTranslucentStrict")
	if err != nil {
		return translucentRuntimeConfiguration{}, err
	}
	noGlue, _, err := singleBoolean(overlay, "olcTranslucentNoGlue")
	if err != nil {
		return translucentRuntimeConfiguration{}, err
	}
	bindLocal, _, err := singleBoolean(overlay, "olcTranslucentBindLocal")
	if err != nil {
		return translucentRuntimeConfiguration{}, err
	}
	pwmodLocal, _, err := singleBoolean(overlay, "olcTranslucentPwModLocal")
	if err != nil {
		return translucentRuntimeConfiguration{}, err
	}
	local, err := parseTranslucentAttributeSet(overlay, "olcTranslucentLocal")
	if err != nil {
		return translucentRuntimeConfiguration{}, err
	}
	remote, err := parseTranslucentAttributeSet(overlay, "olcTranslucentRemote")
	if err != nil {
		return translucentRuntimeConfiguration{}, err
	}

	var children []directory.Entry
	if err := reader.ForEach(func(entry directory.Entry) error {
		entryDN, err := directory.ParseDN(entry.DN)
		if err != nil {
			return fmt.Errorf("parse entry DN %q: %w", entry.DN, err)
		}
		parent, ok := entryDN.Parent()
		if !ok || !parent.Equal(overlayDN) {
			return nil
		}
		if len(entry.Values("olcDatabase")) == 0 &&
			!translucentEntryHasObjectClass(entry, "olcTranslucentDatabase") {
			return nil
		}
		children = append(children, entry)
		return nil
	}); err != nil {
		return translucentRuntimeConfiguration{}, err
	}
	if len(children) != 1 {
		return translucentRuntimeConfiguration{}, fmt.Errorf(
			"%s translucent overlay requires exactly one ldap child database, found %d",
			overlay.DN,
			len(children),
		)
	}

	child := children[0]
	if !translucentEntryHasObjectClass(child, "olcTranslucentDatabase") {
		return translucentRuntimeConfiguration{}, fmt.Errorf(
			"%s translucent child requires objectClass olcTranslucentDatabase",
			child.DN,
		)
	}
	databaseValues := child.Values("olcDatabase")
	if len(databaseValues) != 1 {
		return translucentRuntimeConfiguration{}, fmt.Errorf(
			"%s olcDatabase must be single-valued",
			child.DN,
		)
	}
	if databaseType(string(databaseValues[0])) != "ldap" {
		return translucentRuntimeConfiguration{}, fmt.Errorf(
			"%s translucent child database must use the ldap backend",
			child.DN,
		)
	}
	backend, err := loadLDAPBackendRuntimeConfiguration(child)
	if err != nil {
		return translucentRuntimeConfiguration{}, fmt.Errorf(
			"%s translucent ldap backend: %w",
			child.DN,
			err,
		)
	}
	return translucentRuntimeConfiguration{
		configDNKey: overlayDN.Key(),
		disabled:    disabled,
		strict:      strict,
		noGlue:      noGlue,
		local:       local,
		remote:      remote,
		bindLocal:   bindLocal,
		pwmodLocal:  pwmodLocal,
		backend:     *backend,
	}, nil
}

func translucentEntryHasObjectClass(entry directory.Entry, expected string) bool {
	for _, value := range entry.Values("objectClass") {
		if strings.EqualFold(string(value), expected) {
			return true
		}
	}
	return false
}

func activeTranslucentConfiguration(
	database *runtimeDatabase,
) *translucentRuntimeConfiguration {
	if database == nil || database.translucent == nil ||
		database.translucent.disabled {
		return nil
	}
	return database.translucent
}

type translucentSearchRouteResult struct {
	entries    []directory.Entry
	base       *directory.Entry
	references [][]string
	result     ldapwire.Result
}

func (server *Server) prepareTranslucentSearchRoutes(
	ctx context.Context,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.SearchRequest,
	routes []databaseSearchRoute,
	manageDsaIT bool,
) ([]*translucentSearchRouteResult, *ldapwire.Result, error) {
	prepared := make([]*translucentSearchRouteResult, len(routes))
	if manageDsaIT {
		return prepared, nil, nil
	}
	for index, route := range routes {
		database := &state.runtime.databases[route.databaseIndex]
		if activeTranslucentConfiguration(database) == nil {
			continue
		}
		entries, references, result, failure, err :=
			server.translucentSearchCandidates(
				ctx,
				state,
				*database,
				message.ID,
				request,
				route,
			)
		if failure != nil {
			return prepared, failure, nil
		}
		if err != nil {
			return nil, nil, err
		}
		prepared[index] = &translucentSearchRouteResult{
			entries:    entries,
			references: references,
			result:     result,
		}
		switch result.Code {
		case ldapwire.ResultSuccess,
			ldapwire.ResultSizeLimitExceeded,
			ldapwire.ResultTimeLimitExceeded,
			ldapwire.ResultAdminLimitExceeded:
		default:
			value := result
			return prepared, &value, nil
		}

		for entryIndex := range entries {
			entryDN, parseErr := directory.ParseDN(entries[entryIndex].DN)
			if parseErr != nil {
				return nil, nil, fmt.Errorf(
					"parse translucent remote entry DN %q: %w",
					entries[entryIndex].DN,
					parseErr,
				)
			}
			if entryDN.Equal(route.base) {
				value := entries[entryIndex].Clone()
				prepared[index].base = &value
				break
			}
		}
		if prepared[index].base != nil {
			continue
		}

		base, baseFailure, err := server.translucentRemoteBase(
			ctx,
			state,
			*database,
			message.ID,
			route.base,
			request.DerefAliases,
			request.TimeLimit,
		)
		if err != nil {
			return nil, nil, err
		}
		if baseFailure != nil {
			return prepared, baseFailure, nil
		}
		if base == nil {
			failure := ldapwire.Result{Code: ldapwire.ResultNoSuchObject}
			return prepared, &failure, nil
		}
		prepared[index].base = base
	}
	return prepared, nil, nil
}

func (server *Server) translucentRemoteBase(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	messageID int64,
	base directory.DN,
	derefAliases int,
	timeLimit int,
) (*directory.Entry, *ldapwire.Result, error) {
	request := ldapwire.SearchRequest{
		BaseDN:       base.String(),
		Scope:        directory.ScopeBase,
		DerefAliases: derefAliases,
		TimeLimit:    timeLimit,
		Filter: directory.Filter{
			Kind:      directory.FilterPresent,
			Attribute: "objectClass",
		},
		Attributes: []string{"*", "+"},
	}
	attempt, failure := server.executeTranslucentOperation(
		ctx,
		state,
		database,
		ldapwire.Message{ID: messageID, Request: request},
	)
	if failure != nil {
		return nil, failure, nil
	}
	result, err := translucentSearchAttemptResult(attempt)
	if err != nil {
		return nil, nil, err
	}
	if result.Code != ldapwire.ResultSuccess {
		return nil, &result, nil
	}
	entries, _, err := decodeTranslucentSearchPackets(attempt.packets)
	if err != nil {
		return nil, nil, err
	}
	if len(entries) == 0 {
		return nil, nil, nil
	}
	entry := entries[0].Clone()
	return &entry, nil, nil
}

func (server *Server) executeTranslucentOperation(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	message ldapwire.Message,
) (chainAttempt, *ldapwire.Result) {
	configuration := activeTranslucentConfiguration(&database)
	if configuration == nil {
		result := ldapwire.ResultError(
			ldapwire.ResultUnavailable,
			"remote DB not available",
		)
		return chainAttempt{}, &result
	}
	proxy := database
	proxy.ldapBackend = &configuration.backend
	attempt, _, failure := server.executeLDAPBackendOperation(
		ctx,
		state,
		proxy,
		message,
	)
	return attempt, failure
}

func translucentSearchAttemptResult(attempt chainAttempt) (ldapwire.Result, error) {
	if attempt.hasResult {
		return attempt.result, nil
	}
	if attempt.transportErr != nil {
		return ldapwire.ResultError(
			ldapwire.ResultUnavailable,
			"remote DB not available: "+attempt.transportErr.Error(),
		), nil
	}
	return ldapwire.Result{}, errors.New("translucent remote search returned no result")
}

func decodeTranslucentSearchPackets(
	packets []*ber.Packet,
) ([]directory.Entry, [][]string, error) {
	var entries []directory.Entry
	var references [][]string
	for _, packet := range packets {
		if len(packet.Children) < 2 {
			return nil, nil, errors.New("malformed translucent LDAP response")
		}
		switch uint64(packet.Children[1].Tag) {
		case ldapwire.ApplicationSearchResultEntry:
			entry, err := decodeTranslucentSearchEntry(packet)
			if err != nil {
				return nil, nil, err
			}
			entries = append(entries, entry)
		case ldapwire.ApplicationSearchResultReference:
			values, err := chainSearchReferences(packet)
			if err != nil {
				return nil, nil, err
			}
			references = append(references, values)
		}
	}
	sort.SliceStable(entries, func(left, right int) bool {
		leftDN, leftErr := directory.ParseDN(entries[left].DN)
		rightDN, rightErr := directory.ParseDN(entries[right].DN)
		if leftErr != nil || rightErr != nil {
			return entries[left].DN < entries[right].DN
		}
		return leftDN.Key() < rightDN.Key()
	})
	return entries, references, nil
}

func decodeTranslucentSearchEntry(packet *ber.Packet) (directory.Entry, error) {
	if len(packet.Children) < 2 || len(packet.Children[1].Children) != 2 {
		return directory.Entry{}, errors.New("malformed translucent search entry")
	}
	operation := packet.Children[1]
	rawDN, err := syncConsumerPacketBytes(operation.Children[0])
	if err != nil {
		return directory.Entry{}, errors.New("malformed translucent search entry DN")
	}
	entry := directory.Entry{DN: string(rawDN)}
	for _, packetAttribute := range operation.Children[1].Children {
		if len(packetAttribute.Children) != 2 {
			return directory.Entry{}, errors.New("malformed translucent search attribute")
		}
		rawDescription, err := syncConsumerPacketBytes(packetAttribute.Children[0])
		if err != nil {
			return directory.Entry{}, errors.New("malformed translucent attribute description")
		}
		attribute := directory.Attribute{Description: string(rawDescription)}
		for _, packetValue := range packetAttribute.Children[1].Children {
			rawValue, err := syncConsumerPacketBytes(packetValue)
			if err != nil {
				return directory.Entry{}, errors.New("malformed translucent attribute value")
			}
			attribute.Values = append(attribute.Values, bytes.Clone(rawValue))
		}
		entry.Attributes = append(entry.Attributes, attribute)
	}
	return entry, nil
}

func mergeTranslucentEntry(remote, local directory.Entry) directory.Entry {
	merged := remote.Clone()
	local = local.Clone()
	for _, localAttribute := range local.Attributes {
		replaced := false
		for remoteIndex := range merged.Attributes {
			if !strings.EqualFold(
				merged.Attributes[remoteIndex].Description,
				localAttribute.Description,
			) {
				continue
			}
			merged.Attributes[remoteIndex].Values = localAttribute.Values
			replaced = true
			break
		}
		if !replaced {
			merged.Attributes = append(merged.Attributes, localAttribute)
		}
	}
	return merged
}

func translucentMergedRemoteEntry(
	reader storage.Reader,
	remote directory.Entry,
) (directory.Entry, error) {
	dn, err := directory.ParseDN(remote.DN)
	if err != nil {
		return directory.Entry{}, err
	}
	local, err := reader.Get(dn)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return remote.Clone(), nil
	}
	if err != nil {
		return directory.Entry{}, err
	}
	return mergeTranslucentEntry(remote, local), nil
}

func (server *Server) translucentCompareUsesRemote(
	ctx context.Context,
	database runtimeDatabase,
	dn directory.DN,
	attribute string,
) (bool, error) {
	remote := false
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		entry, err := readerForDatabase(reader, database).Get(dn)
		if errors.Is(err, storage.ErrEntryNotFound) {
			remote = true
			return nil
		}
		if err != nil {
			return err
		}
		remote = !entry.HasAttribute(attribute)
		return nil
	})
	return remote, err
}
