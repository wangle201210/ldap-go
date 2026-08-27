package server

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var compatibleOpenLDAPPasswordModules = []string{
	"argon2",
	"pw-apr1",
	"pw-netscape",
	"pw-pbkdf2",
	"pw-radius",
	"pw-sha2",
	"pw-totp",
}

// validateOpenLDAPModuleConfiguration accepts declarations for features that
// are already implemented in-process. Other modules would require OpenLDAP's
// native dlopen/init_module ABI, which this server does not execute.
func validateOpenLDAPModuleConfiguration(reader storage.Reader) error {
	return reader.ForEach(func(entry directory.Entry) error {
		entryDN, err := directory.ParseDN(entry.DN)
		if err != nil {
			return fmt.Errorf("parse entry DN %q: %w", entry.DN, err)
		}
		if !configurationSuffix.Equal(entryDN) &&
			!configurationSuffix.AncestorOf(entryDN) {
			return nil
		}
		for _, raw := range entry.Values("olcModuleLoad") {
			module, _, err := parseOpenLDAPModuleLoad(string(raw))
			if err != nil {
				return fmt.Errorf("%s olcModuleLoad: %w", entry.DN, err)
			}
			if compatibleOpenLDAPModuleDeclaration(module) {
				continue
			}
			return fmt.Errorf(
				"%s olcModuleLoad module %q is unsupported: native OpenLDAP modules are not loaded",
				entry.DN,
				module,
			)
		}
		return nil
	})
}

func compatibleOpenLDAPModuleDeclaration(module string) bool {
	module = strings.TrimSpace(module)
	if module == "" {
		return false
	}
	for _, passwordModule := range compatibleOpenLDAPPasswordModules {
		if openLDAPPasswordModuleName(module, passwordModule) {
			return true
		}
	}

	// OpenLDAP only applies its static backend/overlay shortcut to a bare
	// module name. A pathname always proceeds to lt_dlopenext().
	if filepath.Base(module) != module || strings.ContainsRune(module, '\\') {
		return false
	}

	name := module
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	if len(name) > len("back_") && strings.EqualFold(name[:len("back_")], "back_") {
		backend := strings.ToLower(name[len("back_"):])
		_, supported := supportedRuntimeDatabaseTypes[backend]
		return supported && backend != "frontend"
	}

	// overlay_find() is case-sensitive; only canonical OpenLDAP module names
	// are inert compatibility declarations when the overlay is built in.
	if name != strings.ToLower(name) {
		return false
	}
	_, supported := supportedRuntimeOverlayType(name)
	return supported
}
