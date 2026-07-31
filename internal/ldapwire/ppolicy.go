package ldapwire

import ber "github.com/go-asn1-ber/asn1-ber"

type AccountUsabilityMoreInfo struct {
	Inactive            bool
	Reset               bool
	Expired             bool
	RemainingGrace      int64
	SecondsBeforeUnlock int64
}

func EncodePasswordPolicyResponseValue(
	expirationSeconds int64,
	graceAuthentications int64,
	policyError int64,
) []byte {
	response := ber.NewSequence("PasswordPolicyResponseValue")
	if expirationSeconds >= 0 || graceAuthentications >= 0 {
		warning := ber.Encode(
			ber.ClassContext,
			ber.TypeConstructed,
			0,
			nil,
			"warning",
		)
		tag := ber.Tag(0)
		value := expirationSeconds
		if expirationSeconds < 0 {
			tag = 1
			value = graceAuthentications
		}
		warning.AppendChild(ber.NewInteger(
			ber.ClassContext,
			ber.TypePrimitive,
			tag,
			value,
			"warningValue",
		))
		response.AppendChild(warning)
	}
	if policyError >= 0 {
		response.AppendChild(ber.NewInteger(
			ber.ClassContext,
			ber.TypePrimitive,
			1,
			policyError,
			"error",
		))
	}
	return response.Bytes()
}

func EncodeAccountUsabilityAvailable(secondsRemaining int64) []byte {
	return ber.NewInteger(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		secondsRemaining,
		"secondsRemaining",
	).Bytes()
}

func EncodeAccountUsabilityUnavailable(
	info AccountUsabilityMoreInfo,
) []byte {
	response := ber.Encode(
		ber.ClassContext,
		ber.TypeConstructed,
		1,
		nil,
		"moreInfo",
	)
	response.AppendChild(ber.NewLDAPBoolean(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		info.Inactive,
		"inactive",
	))
	response.AppendChild(ber.NewLDAPBoolean(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		info.Reset,
		"reset",
	))
	response.AppendChild(ber.NewLDAPBoolean(
		ber.ClassContext,
		ber.TypePrimitive,
		2,
		info.Expired,
		"expired",
	))
	response.AppendChild(ber.NewInteger(
		ber.ClassContext,
		ber.TypePrimitive,
		3,
		info.RemainingGrace,
		"remainingGrace",
	))
	response.AppendChild(ber.NewInteger(
		ber.ClassContext,
		ber.TypePrimitive,
		4,
		info.SecondsBeforeUnlock,
		"secondsBeforeUnlock",
	))
	return response.Bytes()
}
