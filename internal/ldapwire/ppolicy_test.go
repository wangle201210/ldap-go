package ldapwire

import (
	"encoding/hex"
	"testing"
)

func TestEncodePasswordPolicyResponseValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		expiration int64
		grace      int64
		policyErr  int64
		wantHex    string
	}{
		{
			name:       "empty",
			expiration: -1,
			grace:      -1,
			policyErr:  -1,
			wantHex:    "3000",
		},
		{
			name:       "expiration warning",
			expiration: 300,
			grace:      -1,
			policyErr:  -1,
			wantHex:    "3006a0048002012c",
		},
		{
			name:       "grace and error",
			expiration: -1,
			grace:      2,
			policyErr:  8,
			wantHex:    "3008a003810102810108",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := EncodePasswordPolicyResponseValue(
				test.expiration,
				test.grace,
				test.policyErr,
			)
			if hex.EncodeToString(got) != test.wantHex {
				t.Fatalf(
					"EncodePasswordPolicyResponseValue() = %x, want %s",
					got,
					test.wantHex,
				)
			}
		})
	}
}

func TestEncodeAccountUsabilityValue(t *testing.T) {
	t.Parallel()

	if got := EncodeAccountUsabilityAvailable(-1); hex.EncodeToString(got) != "8001ff" {
		t.Fatalf("EncodeAccountUsabilityAvailable() = %x", got)
	}
	got := EncodeAccountUsabilityUnavailable(AccountUsabilityMoreInfo{
		Inactive:            false,
		Reset:               true,
		Expired:             true,
		RemainingGrace:      -1,
		SecondsBeforeUnlock: 30,
	})
	const want = "a10f8001008101ff8201ff8301ff84011e"
	if hex.EncodeToString(got) != want {
		t.Fatalf(
			"EncodeAccountUsabilityUnavailable() = %x, want %s",
			got,
			want,
		)
	}
}
