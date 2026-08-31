package ldapdiff

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

const PagingControlOID = "1.2.840.113556.1.4.319"

type Options struct {
	IgnoreDiagnostic    bool
	IgnoreAttributes    map[string]struct{}
	OpaqueControlValues map[string]struct{}
	PreserveEntryOrder  bool
	NormalizeDN         func(string) (string, error)
}

type Attribute struct {
	Name   string   `json:"name"`
	Values []string `json:"values,omitempty"`
}

type Entry struct {
	DN         string      `json:"dn"`
	Attributes []Attribute `json:"attributes,omitempty"`
	sortKey    string
}

type Control struct {
	OID     string `json:"oid"`
	Encoded string `json:"encoded,omitempty"`
}

type Outcome struct {
	Code       uint16    `json:"code"`
	MatchedDN  string    `json:"matched_dn,omitempty"`
	Diagnostic string    `json:"diagnostic,omitempty"`
	Compare    *bool     `json:"compare,omitempty"`
	EntryCount *int      `json:"entry_count,omitempty"`
	Entries    []Entry   `json:"entries,omitempty"`
	Referrals  []string  `json:"referrals,omitempty"`
	Controls   []Control `json:"controls,omitempty"`
}

type Operation func(*ldap.Conn) Outcome

type Pair struct {
	Reference *ldap.Conn
	Candidate *ldap.Conn
	Options   Options
}

func Dial(referenceURI, candidateURI string, options Options) (*Pair, error) {
	reference, err := ldap.DialURL(referenceURI)
	if err != nil {
		return nil, fmt.Errorf("dial reference LDAP server: %w", err)
	}
	candidate, err := ldap.DialURL(candidateURI)
	if err != nil {
		_ = reference.Close()
		return nil, fmt.Errorf("dial candidate LDAP server: %w", err)
	}
	return &Pair{
		Reference: reference,
		Candidate: candidate,
		Options:   options,
	}, nil
}

func (pair *Pair) Close() error {
	if pair == nil {
		return nil
	}
	var referenceErr, candidateErr error
	if pair.Reference != nil {
		referenceErr = pair.Reference.Close()
	}
	if pair.Candidate != nil {
		candidateErr = pair.Candidate.Close()
	}
	return errors.Join(referenceErr, candidateErr)
}

func (pair *Pair) Run(name string, operation Operation) error {
	_, _, err := pair.Observe(name, operation)
	return err
}

func (pair *Pair) Observe(
	name string,
	operation Operation,
) (Outcome, Outcome, error) {
	if pair == nil || pair.Reference == nil || pair.Candidate == nil {
		return Outcome{}, Outcome{}, errors.New("LDAP differential pair is not connected")
	}
	if operation == nil {
		return Outcome{}, Outcome{}, errors.New("LDAP differential operation is required")
	}
	reference := operation(pair.Reference)
	candidate := operation(pair.Candidate)
	if err := CompareOutcomes(reference, candidate, pair.Options); err != nil {
		return reference, candidate, fmt.Errorf("%s: %w", name, err)
	}
	return reference, candidate, nil
}

func RunURIs(
	referenceURI,
	candidateURI,
	name string,
	options Options,
	operation Operation,
) error {
	pair, err := Dial(referenceURI, candidateURI, options)
	if err != nil {
		return err
	}
	defer pair.Close()
	return pair.Run(name, operation)
}

func ResultOutcome(err error) Outcome {
	outcome := Outcome{}
	if err == nil {
		return outcome
	}
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		outcome.Code = ldap.ErrorNetwork
		outcome.Diagnostic = err.Error()
		return outcome
	}
	outcome.Code = ldapError.ResultCode
	outcome.MatchedDN = strings.TrimSpace(ldapError.MatchedDN)
	if ldapError.Err != nil {
		outcome.Diagnostic = ldapError.Err.Error()
	}
	return outcome
}

func CompareOutcome(matched bool, err error) Outcome {
	outcome := ResultOutcome(err)
	if err != nil {
		return outcome
	}
	value := matched
	outcome.Compare = &value
	if matched {
		outcome.Code = ldap.LDAPResultCompareTrue
	} else {
		outcome.Code = ldap.LDAPResultCompareFalse
	}
	return outcome
}

func SearchOutcome(
	result *ldap.SearchResult,
	err error,
	options Options,
) Outcome {
	outcome := ResultOutcome(err)
	if result == nil {
		return outcome
	}
	for _, entry := range result.Entries {
		outcome.Entries = append(outcome.Entries, canonicalEntry(entry, options))
	}
	if !options.PreserveEntryOrder {
		sort.Slice(outcome.Entries, func(left, right int) bool {
			return canonicalEntryKey(outcome.Entries[left]) <
				canonicalEntryKey(outcome.Entries[right])
		})
	}
	for _, referral := range result.Referrals {
		outcome.Referrals = append(outcome.Referrals, strings.TrimSpace(referral))
	}
	sort.Strings(outcome.Referrals)
	for _, control := range result.Controls {
		if control == nil {
			continue
		}
		canonical := Control{OID: control.GetControlType()}
		if _, opaque := options.OpaqueControlValues[canonical.OID]; !opaque {
			if packet := control.Encode(); packet != nil {
				canonical.Encoded = hex.EncodeToString(packet.Bytes())
			}
		}
		outcome.Controls = append(outcome.Controls, canonical)
	}
	sort.Slice(outcome.Controls, func(left, right int) bool {
		if outcome.Controls[left].OID != outcome.Controls[right].OID {
			return outcome.Controls[left].OID < outcome.Controls[right].OID
		}
		return outcome.Controls[left].Encoded < outcome.Controls[right].Encoded
	})
	return outcome
}

func SearchCountOutcome(
	result *ldap.SearchResult,
	err error,
	options Options,
) Outcome {
	outcome := SearchOutcome(result, err, options)
	count := len(outcome.Entries)
	outcome.EntryCount = &count
	outcome.Entries = nil
	return outcome
}

func CompareOutcomes(reference, candidate Outcome, options Options) error {
	comparableReference := reference
	comparableCandidate := candidate
	comparableReference.MatchedDN = canonicalDN(reference.MatchedDN, options)
	comparableCandidate.MatchedDN = canonicalDN(candidate.MatchedDN, options)
	if options.IgnoreDiagnostic {
		comparableReference.Diagnostic = ""
		comparableCandidate.Diagnostic = ""
	}
	if reflect.DeepEqual(comparableReference, comparableCandidate) {
		return nil
	}
	return fmt.Errorf(
		"LDAP outcomes differ\nOpenLDAP: %s\nldap-go:  %s",
		formatOutcome(reference),
		formatOutcome(candidate),
	)
}

func canonicalEntry(entry *ldap.Entry, options Options) Entry {
	if entry == nil {
		return Entry{}
	}
	result := Entry{DN: canonicalDN(entry.DN, options)}
	attributes := make(map[string][]string, len(entry.Attributes))
	for _, attribute := range entry.Attributes {
		if attribute == nil {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(attribute.Name))
		baseName, _, _ := strings.Cut(name, ";")
		if _, ignored := options.IgnoreAttributes[name]; ignored {
			continue
		}
		if _, ignored := options.IgnoreAttributes[baseName]; ignored {
			continue
		}
		values := attribute.ByteValues
		if len(values) == 0 && len(attribute.Values) != 0 {
			values = make([][]byte, len(attribute.Values))
			for index := range attribute.Values {
				values[index] = []byte(attribute.Values[index])
			}
		}
		for _, value := range values {
			attributes[name] = append(attributes[name], hex.EncodeToString(value))
		}
		if _, exists := attributes[name]; !exists {
			attributes[name] = nil
		}
	}
	for name, values := range attributes {
		sort.Strings(values)
		result.Attributes = append(result.Attributes, Attribute{
			Name:   name,
			Values: values,
		})
	}
	sort.Slice(result.Attributes, func(left, right int) bool {
		return result.Attributes[left].Name < result.Attributes[right].Name
	})
	result.sortKey = canonicalEntryKey(result)
	return result
}

func canonicalDN(value string, options Options) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if options.NormalizeDN != nil {
		if normalized, err := options.NormalizeDN(value); err == nil {
			return normalized
		}
	}
	parsed, err := ldap.ParseDN(value)
	if err != nil {
		return value
	}
	rdns := make([]string, 0, len(parsed.RDNs))
	for _, rdn := range parsed.RDNs {
		attributes := make([]string, 0, len(rdn.Attributes))
		for _, attribute := range rdn.Attributes {
			attributes = append(attributes,
				strings.ToLower(attribute.Type)+"="+
					hex.EncodeToString([]byte(attribute.Value)))
		}
		sort.Strings(attributes)
		rdns = append(rdns, strings.Join(attributes, "+"))
	}
	return strings.Join(rdns, ",")
}

func canonicalEntryKey(entry Entry) string {
	if entry.sortKey != "" {
		return entry.sortKey
	}
	encoded, _ := json.Marshal(entry)
	return string(encoded)
}

func formatOutcome(outcome Outcome) string {
	const maximum = 32 << 10
	encoded, _ := json.Marshal(outcome)
	if len(encoded) <= maximum {
		return string(encoded)
	}
	prefix := strings.ToValidUTF8(string(encoded[:maximum]), "?")
	return fmt.Sprintf("%s...<%d bytes omitted>", prefix, len(encoded)-maximum)
}
