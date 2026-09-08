package server

import (
	"fmt"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/mdbentry"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var unsupportedRuntimeConfigurationAttributes = map[string]string{
	"olcdbcheckpoint":    "bbolt checkpoint scheduling is managed by its transaction and fsync lifecycle",
	"olcdbenvflags":      "LMDB environment flags do not apply to the bbolt storage engine",
	"olcdbmaxreaders":    "LMDB reader-slot limits do not apply to the bbolt storage engine",
	"olcdbmode":          "database file permissions are controlled when the bbolt file is created",
	"olcdbmultival":      "LMDB multivalue split thresholds do not apply to the bbolt storage engine",
	"olcdbnosync":        "runtime durability cannot be weakened through cn=config",
	"olcdbrtxnsize":      "LMDB read-transaction reset thresholds do not apply to bbolt",
	"olcdbsearchstack":   "the OpenLDAP search-stack limit is not implemented",
	"olclistenerthreads": "listener concurrency is configured by ldap-go process options",
	"olcthreadqueues":    "worker queues are configured by ldap-go process options",
	"olcthreads":         "worker concurrency is configured by ldap-go process options",
	"olctoolthreads":     "offline-tool concurrency is not configured through cn=config",
}

var portableRuntimeConfigurationDefaults = map[string]string{
	"olcdbmaxreaders":    "0",
	"olcdbmode":          "0600",
	"olcdbnosync":        "FALSE",
	"olcdbrtxnsize":      "10000",
	"olcdbsearchstack":   "16",
	"olclistenerthreads": "1",
	"olcthreadqueues":    "1",
	"olcthreads":         "16",
	"olctoolthreads":     "1",
}

func validateRuntimeConfigurationCapabilities(reader storage.Reader) error {
	return reader.ForEach(func(entry directory.Entry) error {
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return fmt.Errorf("parse configuration DN %q: %w", entry.DN, err)
		}
		if !isConfigurationDN(dn) {
			return nil
		}
		if err := validateSASLCBindingEntry(entry); err != nil {
			return err
		}
		if err := validateMonitoringConfigurationEntry(entry); err != nil {
			return err
		}
		if _, err := mdbentry.Configuration(entry); err != nil {
			return err
		}
		for _, attribute := range entry.Attributes {
			base, _, _ := strings.Cut(attribute.Description, ";")
			key := strings.ToLower(base)
			reason, unsupported := unsupportedRuntimeConfigurationAttributes[key]
			if !unsupported || len(attribute.Values) == 0 {
				continue
			}
			if portableRuntimeConfigurationDefault(key, attribute.Values) {
				continue
			}
			return fmt.Errorf(
				"%s configures unsupported runtime attribute %s: %s",
				entry.DN,
				attribute.Description,
				reason,
			)
		}
		return nil
	})
}

func portableRuntimeConfigurationDefault(
	attribute string,
	values [][]byte,
) bool {
	if len(values) != 1 {
		return false
	}
	value := strings.TrimSpace(string(values[0]))
	if expected, ok := portableRuntimeConfigurationDefaults[attribute]; ok {
		return strings.EqualFold(value, expected)
	}
	return false
}
