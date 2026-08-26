package server

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	defaultPasswdFile   = "/etc/passwd"
	maximumPasswdBytes  = int64(16 << 20)
	maximumPasswdUsers  = 100000
	maximumPasswdLine   = 1 << 20
	passwdReadOnlyError = "operation not supported within namingContext"
)

type passwdBackendRuntimeConfiguration struct {
	source string
	mu     sync.RWMutex
	info   os.FileInfo
	users  []passwdUser
	byName map[string]int
}

type passwdUser struct {
	name  string
	gecos string
}

func loadPasswdBackendRuntimeConfiguration(
	entry directory.Entry,
	database runtimeDatabase,
) (*passwdBackendRuntimeConfiguration, error) {
	if len(database.suffixes) != 1 {
		return nil, fmt.Errorf("%s passwd backend requires exactly one olcSuffix", entry.DN)
	}
	values := entry.Values("olcPasswdFile")
	if len(values) > 1 {
		return nil, fmt.Errorf("%s olcPasswdFile must be single-valued", entry.DN)
	}
	path := defaultPasswdFile
	if len(values) == 1 {
		path = strings.TrimSpace(string(values[0]))
		if path == "" || !filepath.IsAbs(path) {
			return nil, fmt.Errorf("%s olcPasswdFile must be an absolute path", entry.DN)
		}
	}
	users, info, err := readPasswdSnapshot(path)
	if err != nil {
		return nil, fmt.Errorf("%s olcPasswdFile %q: %w", entry.DN, path, err)
	}
	configuration := &passwdBackendRuntimeConfiguration{
		source: path,
		info:   info,
		users:  users,
		byName: indexPasswdUsers(users),
	}
	return configuration, nil
}

func readPasswdUsers(path string) ([]passwdUser, error) {
	users, _, err := readPasswdSnapshot(path)
	return users, err
}

func readPasswdSnapshot(path string) ([]passwdUser, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if err := validatePasswdSourceInfo(info); err != nil {
		return nil, nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	return readOpenedPasswdSnapshot(info, file)
}

func readOpenedPasswdSnapshot(
	before os.FileInfo,
	file *os.File,
) ([]passwdUser, os.FileInfo, error) {
	opened, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if err := validatePasswdSourceInfo(opened); err != nil {
		return nil, nil, err
	}
	if before == nil || !os.SameFile(before, opened) {
		return nil, nil, errors.New("passwd source changed while opening")
	}
	if opened.Size() > maximumPasswdBytes {
		return nil, nil, fmt.Errorf("passwd source exceeds %d bytes", maximumPasswdBytes)
	}

	reader := io.LimitReader(file, maximumPasswdBytes+1)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), maximumPasswdLine)
	users := make([]passwdUser, 0)
	var consumed int64
	for scanner.Scan() {
		line := bytes.Clone(scanner.Bytes())
		consumed += int64(len(line)) + 1
		if consumed > maximumPasswdBytes {
			return nil, nil, fmt.Errorf("passwd source exceeds %d bytes", maximumPasswdBytes)
		}
		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.SplitN(string(line), ":", 7)
		if len(fields) != 7 || fields[0] == "" || strings.ContainsRune(fields[0], '\x00') {
			return nil, nil, fmt.Errorf("invalid passwd record at line %d", len(users)+1)
		}
		users = append(users, passwdUser{name: fields[0], gecos: fields[4]})
		if len(users) > maximumPasswdUsers {
			return nil, nil, fmt.Errorf("passwd source exceeds %d users", maximumPasswdUsers)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return users, opened, nil
}

func validatePasswdSourceInfo(info os.FileInfo) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("passwd source must be a non-symlink regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("passwd source must not be group- or world-writable")
	}
	return nil
}

func indexPasswdUsers(users []passwdUser) map[string]int {
	byName := make(map[string]int, len(users))
	for index := range users {
		if _, found := byName[users[index].name]; !found {
			byName[users[index].name] = index
		}
	}
	return byName
}

func (configuration *passwdBackendRuntimeConfiguration) snapshot() (
	[]passwdUser,
	map[string]int,
	error,
) {
	if configuration == nil {
		return nil, nil, errors.New("passwd backend is not configured")
	}
	current, err := os.Lstat(configuration.source)
	if err != nil {
		return nil, nil, err
	}
	if err := validatePasswdSourceInfo(current); err != nil {
		return nil, nil, err
	}
	configuration.mu.RLock()
	unchanged := configuration.info != nil && os.SameFile(configuration.info, current) &&
		configuration.info.Size() == current.Size() &&
		configuration.info.ModTime().Equal(current.ModTime())
	if unchanged {
		users, byName := configuration.users, configuration.byName
		configuration.mu.RUnlock()
		return users, byName, nil
	}
	configuration.mu.RUnlock()

	users, opened, err := readPasswdSnapshot(configuration.source)
	if err != nil {
		return nil, nil, err
	}
	byName := indexPasswdUsers(users)
	configuration.mu.Lock()
	configuration.info = opened
	configuration.users = users
	configuration.byName = byName
	configuration.mu.Unlock()
	return users, byName, nil
}

func (server *Server) tryPasswdBackendOperation(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
) (bool, error) {
	if _, bind := message.Request.(ldapwire.BindRequest); bind {
		return false, nil
	}
	target, ok := metaRequestTargetDN(state, message.Request)
	if !ok {
		return false, nil
	}
	database := databaseForDN(state.runtime, target)
	if database == nil || database.passwdBackend == nil {
		return false, nil
	}
	if databaseRestricts(*database, requestDatabaseRestriction(message.Request)) {
		return true, writeResultForMessage(connection, message, ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"operation restricted",
		))
	}
	if request, ok := message.Request.(ldapwire.SearchRequest); ok {
		return true, server.searchPasswdBackend(ctx, connection, state, message, *database, request)
	}
	return true, writeResultForMessage(connection, message, ldapwire.ResultError(
		ldapwire.ResultUnwillingToPerform,
		passwdReadOnlyError,
	))
}

func (server *Server) tryPasswdBackendBind(
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	requestDN directory.DN,
) (bool, error) {
	database := databaseForDN(state.runtime, requestDN)
	if database == nil || database.passwdBackend == nil {
		return false, nil
	}
	if _, root := databaseAuthenticationRoot(state.runtime, *database, requestDN); root {
		return false, nil
	}
	return true, ldapwire.Write(connection, ldapwire.EncodeBindResponse(
		message.ID,
		ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"operation not supported within naming context",
		),
		nil,
	))
}

func (server *Server) searchPasswdBackend(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	database runtimeDatabase,
	request ldapwire.SearchRequest,
) error {
	controls, failure := parseRequestControlsWithDisallows(
		message.Controls,
		supportsAssertion|supportsManageDsaIT|supportsMatchedValues|supportsLazyCommit,
		state.runtime.disallows,
	)
	if failure != nil {
		return writeResultForMessage(connection, message, *failure)
	}
	base, err := normalizeSearchRequestBase(state.runtime, request.BaseDN)
	if err != nil {
		return writeResultForMessage(connection, message, ldapwire.ResultError(
			ldapwire.ResultInvalidDNSyntax,
			"invalid search base DN",
		))
	}
	suffix := database.suffixes[0]
	configuration := database.passwdBackend
	users, byName, err := configuration.snapshot()
	if err != nil {
		return server.internalOperationError(
			connection,
			message.ID,
			ldapwire.ApplicationSearchResultDone,
			fmt.Errorf("refresh passwd source: %w", err),
		)
	}
	limit := effectiveDatabaseSearchLimit(
		state.runtime,
		database,
		state.boundDN,
		server.config.MaxSearchEntries,
		request.SizeLimit,
	)
	deadline := time.Time{}
	if request.TimeLimit > 0 {
		deadline = server.clock().Add(time.Duration(request.TimeLimit) * time.Second)
	}
	entries := make([]directory.Entry, 0)
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}

	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		appendEntry := func(candidate directory.Entry) (bool, error) {
			if !deadline.IsZero() && !server.clock().Before(deadline) {
				result.Code = ldapwire.ResultTimeLimitExceeded
				return false, nil
			}
			if !server.allowed(state.runtime, reader, state.boundDN, candidate, "entry", nil, acl.Search) {
				return true, nil
			}
			matches, matchErr := server.filterMatches(
				state.runtime,
				reader,
				state.boundDN,
				candidate,
				request.Filter,
			)
			if matchErr != nil || !matches {
				return matchErr == nil, matchErr
			}
			if len(entries) >= limit {
				result.Code = ldapwire.ResultSizeLimitExceeded
				return false, nil
			}
			readable := server.attributesWithPrivilege(
				state.runtime,
				reader,
				state.boundDN,
				candidate,
				acl.Read,
				request.TypesOnly,
			)
			entries = append(entries, server.selectEntry(
				state.runtime,
				readable,
				request.Attributes,
				request.TypesOnly,
			))
			return true, nil
		}

		switch {
		case suffix.Equal(base):
			baseEntry := passwdBaseEntry(suffix)
			if controls.assertion != nil {
				matches, assertionErr := server.filterMatches(
					state.runtime, reader, state.boundDN, baseEntry, *controls.assertion,
				)
				if assertionErr != nil {
					return assertionErr
				}
				if !matches {
					result.Code = ldapwire.ResultAssertionFailed
					return nil
				}
			}
			if request.Scope != directory.ScopeSingleLevel {
				keepGoing, appendErr := appendEntry(baseEntry)
				if appendErr != nil || !keepGoing {
					return appendErr
				}
			}
			if request.Scope != directory.ScopeBase {
				for _, user := range users {
					select {
					case <-ctx.Done():
						return ctx.Err()
					default:
					}
					keepGoing, appendErr := appendEntry(passwdUserEntry(suffix, user))
					if appendErr != nil || !keepGoing {
						return appendErr
					}
				}
			}
			return nil
		case suffix.AncestorOf(base):
			parent, hasParent := base.Parent()
			if !hasParent || !suffix.Equal(parent) {
				result.Code = ldapwire.ResultNoSuchObject
				result.MatchedDN = suffix.String()
				return nil
			}
			if request.Scope == directory.ScopeSingleLevel {
				return nil
			}
			rdn := base.RDNValues()
			if len(rdn) == 0 {
				result.Code = ldapwire.ResultNoSuchObject
				result.MatchedDN = parent.String()
				return nil
			}
			index, found := byName[string(rdn[0].Value)]
			if !found {
				result.Code = ldapwire.ResultNoSuchObject
				result.MatchedDN = parent.String()
				return nil
			}
			candidate := passwdUserEntry(suffix, users[index])
			if controls.assertion != nil {
				matches, assertionErr := server.filterMatches(
					state.runtime, reader, state.boundDN, candidate, *controls.assertion,
				)
				if assertionErr != nil {
					return assertionErr
				}
				if !matches {
					result.Code = ldapwire.ResultAssertionFailed
					return nil
				}
			}
			_, appendErr := appendEntry(candidate)
			return appendErr
		default:
			result.Code = ldapwire.ResultNoSuchObject
			return nil
		}
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return server.internalOperationError(
			connection,
			message.ID,
			ldapwire.ApplicationSearchResultDone,
			err,
		)
	}
	return server.writeSearchResult(
		connection,
		message.ID,
		state,
		nil,
		nil,
		entries,
		result,
		pagedSearchCursor{},
		false,
	)
}

func passwdBaseEntry(suffix directory.DN) directory.Entry {
	entry := directory.Entry{DN: suffix.String()}
	rdn := suffix.RDNValues()
	if len(rdn) > 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: rdn[0].Type,
			Values:      [][]byte{bytes.Clone(rdn[0].Value)},
		})
	}
	entry.Attributes = append(entry.Attributes, directory.Attribute{
		Description: "objectClass",
		Values:      stringValues("organizationalUnit"),
	})
	return entry
}

func passwdUserEntry(suffix directory.DN, user passwdUser) directory.Entry {
	dn := "uid=" + ldap.EscapeDN(user.name) + "," + suffix.String()
	entry := directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("person", "uidObject")},
			{Description: "uid", Values: stringValues(user.name)},
			{Description: "cn", Values: stringValues(user.name)},
			{Description: "sn", Values: stringValues(user.name)},
		},
	}
	if user.gecos == "" {
		return entry
	}
	entry.Attributes = append(entry.Attributes, directory.Attribute{
		Description: "description",
		Values:      stringValues(user.gecos),
	})
	fullName := user.gecos
	if comma := strings.IndexByte(fullName, ','); comma >= 0 {
		fullName = fullName[:comma]
	}
	fullName = expandPasswdGECOSName(fullName, user.name)
	if fullName != "" && !strings.EqualFold(fullName, user.name) {
		entry.Attributes[2].Values = append(entry.Attributes[2].Values, []byte(fullName))
	}
	if space := strings.LastIndexByte(fullName, ' '); space >= 0 {
		entry.Attributes[3].Values = append(entry.Attributes[3].Values, []byte(fullName[space+1:]))
	}
	return entry
}

func expandPasswdGECOSName(value, username string) string {
	if !strings.Contains(value, "&") || username == "" {
		return value
	}
	expanded := username
	if expanded[0] >= 'a' && expanded[0] <= 'z' {
		expanded = strings.ToUpper(expanded[:1]) + expanded[1:]
	}
	return strings.ReplaceAll(value, "&", expanded)
}
