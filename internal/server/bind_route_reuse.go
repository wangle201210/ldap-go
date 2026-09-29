package server

import (
	"context"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

// Establish this proof before parseRuntimeConnectionDN: a custom normalizer
// could replace itself with a standard one during parsing. Published runtime
// schemas are immutable; online changes publish a replacement runtime instead.
// Every routing candidate is checked, not only the eventual selected database.
func (server *Server) canReuseSimpleBindRoute(state *connectionState, message ldapwire.Message, request ldapwire.BindRequest) bool {
	if state == nil || state.runtime == nil || state.saslSession != nil ||
		request.Version != 3 || request.Authentication.IsSASL || request.Name == "" ||
		len(request.Authentication.Simple) == 0 || len(message.Controls) != 0 || message.ControlsPresent {
		return false
	}
	runtime := state.runtime
	if runtime != server.runtime.Load() || runtime.revision == 0 || runtime.schema == nil ||
		runtime.features != (runtimeOperationFeatures{}) || runtime.externalPasswords.radiusEnabled ||
		!plainBoltSearchStore(server.config.Store) || !localProjectionReadOnly(runtime, nil) {
		return false
	}
	for index := range runtime.databases {
		database := &runtime.databases[index]
		if !simpleBindRouteDatabasePlain(database) {
			return false
		}
		switch databaseType(database.name) {
		case "config":
			if database.dnNormalizer != nil {
				return false
			}
		case "frontend":
			if len(database.suffixes) != 0 {
				return false
			}
		default:
			if !databaseUsesRuntimeDNIdentity(*database, runtime.schema) {
				return false
			}
		}
	}
	return true
}

// Loaded overlays are all recorded in monitorOverlays. The explicit checks
// also reject programmatically assembled configurations without that list.
func simpleBindRouteDatabasePlain(database *runtimeDatabase) bool {
	return len(database.monitorOverlays) == 0 && len(database.sockOverlays) == 0 &&
		!database.hidden && !database.disabled && !database.subordinate && !database.explicitGlue &&
		!database.shadow && !database.multiProvider && len(database.syncConsumers) == 0 && !database.syncProvider &&
		database.relay == nil && database.rwm == nil && database.ldapBackend == nil &&
		database.metaBackend == nil && database.asyncMetaBackend == nil && database.passwdBackend == nil &&
		database.dnssrvBackend == nil && database.sockBackend == nil && database.sqlBackend == nil &&
		database.ppolicy == nil && database.remoteAuth == nil && database.pbind == nil &&
		!database.lastBind && !database.lastBindOverlay && !database.lastBindForwardUpdates &&
		database.otp == nil && len(database.totpPasswords) == 0 && database.translucent == nil &&
		database.chain == nil && database.pcache == nil && database.homedir == nil && database.dds == nil &&
		!database.allOperationalAttrs && !database.allowedOverlay && !database.authzidOverlay &&
		!database.nopsOverlay && !database.noOpSearchOverlay && !database.serverSideSort &&
		database.autoca == nil && database.constraint == nil && database.collect == nil && database.seqmod == nil &&
		len(database.nestGroups) == 0 && !database.deref && database.dynlist == nil && database.dyngroup == nil &&
		database.unique == nil && database.valueSort == nil && database.accesslog == nil && database.auditlog == nil &&
		len(database.retcodes) == 0 && len(database.memberOf) == 0 && len(database.refint) == 0
}

func (server *Server) authenticateSimpleBindRoute(
	ctx context.Context,
	runtime *runtimeState,
	database *runtimeDatabase,
	dn directory.DN,
	password []byte,
	requestControl, reuse bool,
) (passwordBindResult, error) {
	rawDN := dn.String()
	if reuse && rawDN != "" && len(password) != 0 && database != nil &&
		databaseUsesRuntimeDNIdentity(*database, runtime.schema) {
		// The string entry point first classifies the rendered DN using legacy
		// configuration identity. Keep that distinction even for schema aliases
		// rendering as cn=config; never infer it from a textual suffix.
		legacy, err := runtime.legacyDNs.parse(rawDN)
		if err == nil && !isConfigurationDN(legacy) {
			// handleBind selected this database from this DN. All content
			// normalizers use runtime.schema and no callback ran since the proof;
			// the string entry point's two schema normalizations and rerouting
			// therefore produce the same display, identity and database.
			return server.authenticateResolvedPasswordBind(ctx, runtime, database, dn, rawDN, password, requestControl)
		}
	}
	return server.authenticatePasswordBind(ctx, runtime, rawDN, password, requestControl)
}
