package schema

import "testing"

func TestDNIdentityFingerprintTracksOnlyNamingSemantics(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	original := registry.DNIdentityFingerprint()
	if cloned := registry.Clone().DNIdentityFingerprint(); cloned != original {
		t.Fatalf("cloned registry fingerprint = %x, want %x", cloned, original)
	}

	uid, found := registry.AttributeType("uid")
	if !found {
		t.Fatal("built-in uid attribute is missing")
	}
	uid.Description = "description changes do not affect DN identity"
	if err := registry.UpsertAttributeType(uid); err != nil {
		t.Fatalf("UpsertAttributeType(description): %v", err)
	}
	if got := registry.DNIdentityFingerprint(); got != original {
		t.Fatalf("description-only fingerprint = %x, want %x", got, original)
	}

	uid.Equality = "caseExactMatch"
	if err := registry.UpsertAttributeType(uid); err != nil {
		t.Fatalf("UpsertAttributeType(equality): %v", err)
	}
	if got := registry.DNIdentityFingerprint(); got == original {
		t.Fatalf("equality change retained fingerprint %x", got)
	}
}
