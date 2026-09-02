package server

import (
	"fmt"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var unsupportedRuntimeConfigurationAttributes = map[string]string{
	"olcdbcheckpoint":    "bbolt checkpoint scheduling is managed by its transaction and fsync lifecycle",
	"olcdbenvflags":      "LMDB environment flags do not apply to the bbolt storage engine",
	"olcdbmaxentrysize":  "per-entry storage limits are not implemented",
	"olcdbmaxreaders":    "LMDB reader-slot limits do not apply to the bbolt storage engine",
	"olcdbmode":          "database file permissions are controlled when the bbolt file is created",
	"olcdbmultival":      "LMDB multivalue split thresholds do not apply to the bbolt storage engine",
	"olcdbnosync":        "runtime durability cannot be weakened through cn=config",
	"olcdbrtxnsize":      "LMDB read-transaction reset thresholds do not apply to bbolt",
	"olcdbsearchstack":   "the OpenLDAP search-stack limit is not implemented",
	"olclistenerthreads": "listener concurrency is configured by ldap-go process options",
	"olclogfile":         "log destinations are controlled by the process service manager",
	"olclogfileformat":   "OpenLDAP logfile formatting is not implemented",
	"olclogfileonly":     "OpenLDAP logfile-only routing is not implemented",
	"olclogfilerotate":   "log rotation is controlled by the process service manager",
	"olcmonitoring":      "per-database monitoring enablement is not implemented",
	"olcsaslcbinding":    "server SASL channel-binding policy is not implemented",
	"olcthreadqueues":    "worker queues are configured by ldap-go process options",
	"olcthreads":         "worker concurrency is configured by ldap-go process options",
	"olctoolthreads":     "offline-tool concurrency is not configured through cn=config",
}

var portableRuntimeConfigurationDefaults = map[string]string{
	"olcdbmaxentrysize":  "0",
	"olcdbmaxreaders":    "0",
	"olcdbmode":          "0600",
	"olcdbnosync":        "FALSE",
	"olcdbrtxnsize":      "10000",
	"olcdbsearchstack":   "16",
	"olclistenerthreads": "1",
	"olclogfileonly":     "FALSE",
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
		for _, attribute := range entry.Attributes {
			base, _, _ := strings.Cut(attribute.Description, ";")
			key := strings.ToLower(base)
			reason, unsupported := unsupportedRuntimeConfigurationAttributes[key]
			if !unsupported || len(attribute.Values) == 0 {
				continue
			}
			if portableRuntimeConfigurationDefault(entry, key, attribute.Values) {
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
	entry directory.Entry,
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
	if attribute != "olcmonitoring" {
		return false
	}
	database := ""
	if values := entry.Values("olcDatabase"); len(values) > 0 {
		database = strings.ToLower(strings.TrimSpace(string(values[0])))
	}
	if strings.Contains(database, "frontend") || strings.Contains(database, "config") {
		return strings.EqualFold(value, "FALSE")
	}
	return strings.EqualFold(value, "TRUE")
}
