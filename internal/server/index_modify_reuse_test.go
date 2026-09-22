package server

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/schema"
)

type wrappedModifyIndexRegistry struct {
	*schema.Registry
}

func TestDatabaseIndexEntryValuesReadOnly(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		registry databaseEqualityIndexRegistry
		want     bool
	}{
		{"concrete registry", registry, true},
		{"custom wrapper", wrappedModifyIndexRegistry{registry}, false},
		{"nil registry", nil, false},
		{"typed nil registry", (*schema.Registry)(nil), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			normalizer := &databaseEqualityIndexNormalizer{registry: test.registry}
			if got := normalizer.IndexEntryValuesReadOnly(); got != test.want {
				t.Fatalf("IndexEntryValuesReadOnly() = %v, want %v", got, test.want)
			}
		})
	}
}
