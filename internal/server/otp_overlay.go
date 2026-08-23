package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type otpRuntimeConfiguration struct {
	configDNKey string
	disabled    bool
}

func loadOTPRuntimeConfiguration(
	entry directory.Entry,
) (otpRuntimeConfiguration, error) {
	allowed := map[string]struct{}{
		"objectclass":           {},
		"olcoverlay":            {},
		"olcdisabled":           {},
		"entryuuid":             {},
		"entrycsn":              {},
		"createtimestamp":       {},
		"modifytimestamp":       {},
		"creatorsname":          {},
		"modifiersname":         {},
		"structuralobjectclass": {},
		"subschemasubentry":     {},
	}
	for _, attribute := range entry.Attributes {
		if _, ok := allowed[strings.ToLower(attribute.Description)]; !ok {
			return otpRuntimeConfiguration{}, fmt.Errorf(
				"%s has unsupported otp configuration attribute %q",
				entry.DN,
				attribute.Description,
			)
		}
	}
	disabled, _, err := singleBoolean(entry, "olcDisabled")
	if err != nil {
		return otpRuntimeConfiguration{}, err
	}
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return otpRuntimeConfiguration{}, err
	}
	return otpRuntimeConfiguration{
		configDNKey: dn.Key(),
		disabled:    disabled,
	}, nil
}

func activeOTPConfiguration(
	database *runtimeDatabase,
) *otpRuntimeConfiguration {
	if database == nil || database.otp == nil || database.otp.disabled {
		return nil
	}
	return database.otp
}

type otpBindAttempt struct {
	handled        bool
	staticPassword []byte
	syncChange     *syncChange
}

func (server *Server) prepareOTPBind(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	dn directory.DN,
	credential []byte,
) (bool, []byte, ldapwire.Result) {
	attempt := otpBindAttempt{}
	err := server.updateStorage(ctx, func(writer storage.Writer) error {
		tx := writerForDatabase(writer, database)
		userDN, err := normalizeOTPDirectoryDN(runtime, tx, dn)
		if err != nil {
			return err
		}
		user, err := tx.Get(userDN)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !runtime.schema.EntryHasObjectClass(user, "oathUser") {
			return nil
		}
		attempt.handled = true

		if static, matched, change, err := server.matchTOTPBind(
			writer,
			tx,
			runtime,
			database,
			user,
			credential,
			time.Now().Unix(),
		); err != nil {
			return err
		} else if matched {
			attempt.staticPassword = static
			attempt.syncChange = change
			return nil
		}

		static, matched, change, err := server.matchHOTPBind(
			writer,
			tx,
			runtime,
			database,
			user,
			credential,
		)
		if err != nil {
			return err
		}
		if matched {
			attempt.staticPassword = static
			attempt.syncChange = change
		}
		return nil
	})
	if err != nil {
		server.config.Logger.Debug(
			"OTP state transaction failed",
			"dn", dn.String(),
			"error", err,
		)
		return true, nil, ldapwire.ResultError(ldapwire.ResultOther, "")
	}
	if !attempt.handled {
		return false, nil, ldapwire.Result{Code: ldapwire.ResultSuccess}
	}
	if attempt.staticPassword == nil {
		return true, nil, ldapwire.ResultError(
			ldapwire.ResultInvalidCredentials,
			"",
		)
	}
	server.finishWriteEffects(ctx, nil, attempt.syncChange)
	return true, attempt.staticPassword, ldapwire.Result{Code: ldapwire.ResultSuccess}
}

func (server *Server) matchHOTPBind(
	writer storage.Writer,
	tx storage.Writer,
	runtime *runtimeState,
	database runtimeDatabase,
	user directory.Entry,
	credential []byte,
) ([]byte, bool, *syncChange, error) {
	ref, ok := otpSingleString(user, "oathHOTPToken")
	if !ok {
		return nil, false, nil, nil
	}
	token, found, err := lookupOTPReferenceEntry(runtime, tx, ref)
	if err != nil {
		return nil, false, nil, err
	}
	if !found {
		return nil, false, nil, nil
	}
	if !runtime.schema.EntryHasObjectClass(token, "oathHOTPToken") {
		return nil, false, nil, nil
	}
	secret, ok := otpSingleBytes(token, "oathSecret")
	if !ok {
		return nil, false, nil, nil
	}
	paramsRef, ok := otpSingleString(token, "oathHOTPParams")
	if !ok {
		return nil, false, nil, nil
	}
	params, found, err := lookupOTPReferenceEntry(runtime, tx, paramsRef)
	if err != nil {
		return nil, false, nil, err
	}
	if !found {
		return nil, false, nil, nil
	}
	if !runtime.schema.EntryHasObjectClass(params, "oathHOTPParams") {
		return nil, false, nil, nil
	}
	digits, ok := otpSingleInt(params, "oathOTPLength")
	if !ok || digits < 1 || digits > 8 || len(credential) < int(digits) {
		return nil, false, nil, nil
	}
	lookAhead, ok := otpSingleInt(params, "oathHOTPLookAhead")
	if !ok {
		return nil, false, nil, nil
	}
	algorithm, ok := otpSingleString(params, "oathHMACAlgorithm")
	if !ok {
		return nil, false, nil, nil
	}
	last := int64(-1)
	if token.HasAttribute("oathHOTPCounter") {
		last, ok = otpSingleInt(token, "oathHOTPCounter")
		if !ok {
			return nil, false, nil, nil
		}
	}
	static, supplied := splitOTPCredential(credential, int(digits))
	match, matchErr := matchHOTP(
		secret,
		string(supplied),
		last,
		lookAhead,
		int(digits),
		algorithm,
	)
	if matchErr != nil || !match.Matched {
		return nil, false, nil, nil
	}
	change, err := server.advanceOTPTokenState(
		writer,
		tx,
		runtime,
		database,
		token,
		map[string]int64{"oathHOTPCounter": match.Found},
	)
	if err != nil {
		return nil, false, nil, err
	}
	return static, true, change, nil
}

func (server *Server) matchTOTPBind(
	writer storage.Writer,
	tx storage.Writer,
	runtime *runtimeState,
	database runtimeDatabase,
	user directory.Entry,
	credential []byte,
	now int64,
) ([]byte, bool, *syncChange, error) {
	ref, ok := otpSingleString(user, "oathTOTPToken")
	if !ok {
		return nil, false, nil, nil
	}
	token, found, err := lookupOTPReferenceEntry(runtime, tx, ref)
	if err != nil {
		return nil, false, nil, err
	}
	if !found {
		return nil, false, nil, nil
	}
	if !runtime.schema.EntryHasObjectClass(token, "oathTOTPToken") {
		return nil, false, nil, nil
	}
	secret, ok := otpSingleBytes(token, "oathSecret")
	if !ok {
		return nil, false, nil, nil
	}
	paramsRef, ok := otpSingleString(token, "oathTOTPParams")
	if !ok {
		return nil, false, nil, nil
	}
	params, found, err := lookupOTPReferenceEntry(runtime, tx, paramsRef)
	if err != nil {
		return nil, false, nil, err
	}
	if !found {
		return nil, false, nil, nil
	}
	if !runtime.schema.EntryHasObjectClass(params, "oathTOTPParams") {
		return nil, false, nil, nil
	}
	digits, ok := otpSingleInt(params, "oathOTPLength")
	if !ok || digits < 1 || digits > 8 || len(credential) < int(digits) {
		return nil, false, nil, nil
	}
	period, ok := otpSingleInt(params, "oathTOTPTimeStepPeriod")
	if !ok {
		return nil, false, nil, nil
	}
	window := int64(0)
	if params.HasAttribute("oathTOTPTimeStepWindow") {
		window, ok = otpSingleInt(params, "oathTOTPTimeStepWindow")
		if !ok {
			return nil, false, nil, nil
		}
	}
	// Preserve OpenLDAP 2.6.13's read/write mismatch: drift is read from the
	// params entry, while a successful Bind writes it to the token entry.
	drift := int64(0)
	if params.HasAttribute("oathTOTPTimeStepDrift") {
		drift, ok = otpSingleInt(params, "oathTOTPTimeStepDrift")
		if !ok {
			return nil, false, nil, nil
		}
	}
	algorithm, ok := otpSingleString(params, "oathHMACAlgorithm")
	if !ok {
		return nil, false, nil, nil
	}
	last := int64(-1)
	if token.HasAttribute("oathTOTPLastTimeStep") {
		last, ok = otpSingleInt(token, "oathTOTPLastTimeStep")
		if !ok {
			return nil, false, nil, nil
		}
	}
	static, supplied := splitOTPCredential(credential, int(digits))
	match, matchErr := matchTOTP(
		secret,
		string(supplied),
		now,
		last,
		drift,
		period,
		window,
		int(digits),
		algorithm,
	)
	if matchErr != nil || !match.Matched {
		return nil, false, nil, nil
	}
	change, err := server.advanceOTPTokenState(
		writer,
		tx,
		runtime,
		database,
		token,
		map[string]int64{
			"oathTOTPLastTimeStep":  match.FoundStep,
			"oathTOTPTimeStepDrift": drift + match.DriftDelta,
		},
	)
	if err != nil {
		return nil, false, nil, err
	}
	return static, true, change, nil
}

func (server *Server) advanceOTPTokenState(
	writer storage.Writer,
	tx storage.Writer,
	runtime *runtimeState,
	database runtimeDatabase,
	token directory.Entry,
	values map[string]int64,
) (*syncChange, error) {
	before := token.Clone()
	for attribute, value := range values {
		token.ReplaceValues(attribute, [][]byte{[]byte(strconv.FormatInt(value, 10))})
	}
	tokenDN, err := parseOTPReferenceDN(runtime, tx, token.DN)
	if err != nil {
		return nil, err
	}
	if lastModEnabled(runtime, tokenDN) {
		actor := ""
		if database.rootDN != nil {
			actor = database.rootDN.String()
		}
		server.applyModifyOperationalAttributes(
			&token,
			actor,
			runtime.serverID,
		)
	}
	if err := tx.Put(token, true); err != nil {
		return nil, err
	}
	return server.recordSyncChange(
		writer,
		runtime,
		database,
		&before,
		&token,
	)
}

func parseOTPReferenceDN(
	runtime *runtimeState,
	reader storage.Reader,
	value string,
) (directory.DN, error) {
	var normalizer directory.DNAttributeNormalizer
	if runtime != nil {
		normalizer = runtime.schema
	}
	dn, err := parseRuntimeDN(value, normalizer)
	if err != nil {
		return directory.DN{}, err
	}
	return storage.NormalizeReaderDN(reader, dn)
}

func lookupOTPReferenceEntry(
	runtime *runtimeState,
	reader storage.Reader,
	value string,
) (directory.Entry, bool, error) {
	var normalizer directory.DNAttributeNormalizer
	if runtime != nil {
		normalizer = runtime.schema
	}
	dn, err := parseRuntimeDN(value, normalizer)
	if err != nil {
		return directory.Entry{}, false, nil
	}
	dn, err = storage.NormalizeReaderDN(reader, dn)
	if err != nil {
		return directory.Entry{}, false, err
	}
	entry, err := reader.Get(dn)
	switch {
	case err == nil:
		return entry, true, nil
	case errors.Is(err, storage.ErrEntryNotFound):
		return directory.Entry{}, false, nil
	default:
		return directory.Entry{}, false, err
	}
}

func normalizeOTPDirectoryDN(
	runtime *runtimeState,
	reader storage.Reader,
	dn directory.DN,
) (directory.DN, error) {
	return parseOTPReferenceDN(runtime, reader, dn.String())
}

func otpSingleBytes(entry directory.Entry, attribute string) ([]byte, bool) {
	values := entry.Values(attribute)
	if len(values) != 1 || len(values[0]) == 0 {
		return nil, false
	}
	return bytes.Clone(values[0]), true
}

func otpSingleString(entry directory.Entry, attribute string) (string, bool) {
	value, ok := otpSingleBytes(entry, attribute)
	if !ok {
		return "", false
	}
	trimmed := strings.TrimSpace(string(value))
	return trimmed, trimmed != ""
}

func otpSingleInt(entry directory.Entry, attribute string) (int64, bool) {
	value, ok := otpSingleString(entry, attribute)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil
}

func splitOTPCredential(credential []byte, digits int) ([]byte, []byte) {
	offset := len(credential) - digits
	return bytes.Clone(credential[:offset]), bytes.Clone(credential[offset:])
}
