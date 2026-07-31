package server

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func loadRuntimeShadowSettings(
	entry directory.Entry,
	database *runtimeDatabase,
) error {
	updateDNValues := entry.Values("olcUpdateDN")
	if len(updateDNValues) > 1 {
		return fmt.Errorf("%s olcUpdateDN must be single-valued", entry.DN)
	}
	if len(updateDNValues) == 1 {
		updateDN, err := directory.ParseDN(string(updateDNValues[0]))
		if err != nil {
			return fmt.Errorf("%s olcUpdateDN: %w", entry.DN, err)
		}
		database.updateDN = &updateDN
	}

	multiValues := append(
		entry.Values("olcMultiProvider"),
		entry.Values("olcMirrorMode")...,
	)
	if len(multiValues) > 1 {
		return fmt.Errorf(
			"%s olcMultiProvider/olcMirrorMode must be single-valued",
			entry.DN,
		)
	}
	if len(multiValues) == 1 {
		switch {
		case strings.EqualFold(string(multiValues[0]), "TRUE"):
			database.multiProvider = true
		case strings.EqualFold(string(multiValues[0]), "FALSE"):
		default:
			return fmt.Errorf(
				"%s olcMultiProvider has invalid value %q",
				entry.DN,
				multiValues[0],
			)
		}
	}

	hasSyncrepl := len(database.syncConsumers) > 0
	if hasSyncrepl && database.updateDN != nil {
		return fmt.Errorf(
			"%s cannot combine olcSyncrepl with olcUpdateDN",
			entry.DN,
		)
	}
	hasShadowSource := hasSyncrepl || database.updateDN != nil
	if database.multiProvider && !hasShadowSource {
		return fmt.Errorf(
			"%s olcMultiProvider requires olcSyncrepl or olcUpdateDN",
			entry.DN,
		)
	}

	for _, raw := range entry.Values("olcUpdateRef") {
		reference, err := validateShadowUpdateRef(string(raw))
		if err != nil {
			return fmt.Errorf("%s olcUpdateRef: %w", entry.DN, err)
		}
		database.updateRefs = append(database.updateRefs, reference)
	}
	if len(database.updateRefs) > 0 && !hasShadowSource {
		return fmt.Errorf(
			"%s olcUpdateRef requires olcSyncrepl or olcUpdateDN",
			entry.DN,
		)
	}
	database.shadow = hasShadowSource && !database.multiProvider
	return nil
}

func validateShadowUpdateRef(raw string) (string, error) {
	reference := referralURI(strings.TrimSpace(raw))
	if reference == "" {
		return "", fmt.Errorf("empty referral URL")
	}
	parsed, err := url.Parse(reference)
	if err != nil || parsed.Opaque != "" || parsed.Fragment != "" ||
		parsed.User != nil {
		return "", fmt.Errorf("invalid referral URL %q", raw)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "ldap", "ldaps", "ldapi", "ldap+tlcp":
	default:
		return "", fmt.Errorf("invalid referral URL %q", raw)
	}
	return reference, nil
}

func shadowUpdateResult(
	database runtimeDatabase,
	target directory.DN,
) ldapwire.Result {
	if len(database.updateRefs) == 0 {
		return ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"shadow context; no update referral",
		)
	}

	base := target
	bestDepth := -1
	for _, suffix := range database.suffixes {
		if (suffix.Equal(target) || suffix.AncestorOf(target)) &&
			suffix.Depth() > bestDepth {
			base = suffix
			bestDepth = suffix.Depth()
		}
	}
	referrals := make([]string, 0, len(database.updateRefs))
	for _, reference := range database.updateRefs {
		rewritten, ok := rewriteReferralURL(
			reference,
			base,
			&target,
			referralScopeDefault,
		)
		if ok {
			referrals = append(referrals, rewritten)
		}
	}
	if len(referrals) == 0 {
		return ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"shadow context; no update referral",
		)
	}
	return ldapwire.Result{
		Code:      ldapwire.ResultReferral,
		Referrals: referrals,
	}
}
