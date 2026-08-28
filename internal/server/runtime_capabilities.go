package server

import "fmt"

var supportedRuntimeDatabaseTypes = map[string]struct{}{
	"asyncmeta": {},
	"config":    {},
	"dnssrv":    {},
	"frontend":  {},
	"ldap":      {},
	"ldif":      {},
	"mdb":       {},
	"meta":      {},
	"monitor":   {},
	"null":      {},
	"passwd":    {},
	"relay":     {},
	"sock":      {},
	"sql":       {},
	"wt":        {},
}

var supportedRuntimeOverlayTypes = map[string]struct{}{
	"accesslog":   {},
	"allop":       {},
	"auditlog":    {},
	"autoca":      {},
	"chain":       {},
	"collect":     {},
	"constraint":  {},
	"dds":         {},
	"deref":       {},
	"dyngroup":    {},
	"dynlist":     {},
	"homedir":     {},
	"lastbind":    {},
	"glue":        {},
	"memberof":    {},
	"nestgroup":   {},
	"nops":        {},
	"otp":         {},
	"pbind":       {},
	"pcache":      {},
	"ppolicy":     {},
	"refint":      {},
	"remoteauth":  {},
	"retcode":     {},
	"rwm":         {},
	"seqmod":      {},
	"sock":        {},
	"sssvlv":      {},
	"syncprov":    {},
	"totp":        {},
	"translucent": {},
	"unique":      {},
	"valsort":     {},
}

func supportedRuntimeDatabaseType(value string) (string, bool) {
	backendType := databaseType(value)
	_, supported := supportedRuntimeDatabaseTypes[backendType]
	return backendType, supported
}

func requireSupportedRuntimeDatabaseType(entryDN, value string) (string, error) {
	backendType, supported := supportedRuntimeDatabaseType(value)
	if supported {
		return backendType, nil
	}
	return "", fmt.Errorf(
		"%s olcDatabase backend %q is unsupported",
		entryDN,
		backendType,
	)
}

// supportedRuntimeOverlayType returns the runtime's canonical overlay name.
// otp and totp remain distinct because this server implements both overlay
// configurations; proxycache is OpenLDAP's module name for the pcache overlay.
func supportedRuntimeOverlayType(value string) (string, bool) {
	overlayType := databaseType(value)
	if overlayType == "proxycache" {
		overlayType = "pcache"
	}
	_, supported := supportedRuntimeOverlayTypes[overlayType]
	return overlayType, supported
}

func requireSupportedRuntimeOverlayType(entryDN, value string) (string, error) {
	overlayType, supported := supportedRuntimeOverlayType(value)
	if supported {
		return overlayType, nil
	}
	return "", fmt.Errorf(
		"%s configures unsupported OpenLDAP overlay %q",
		entryDN,
		overlayType,
	)
}
