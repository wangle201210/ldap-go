package schema

import (
	"fmt"
	"sync"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func cachedNames(t testing.TB, registry *Registry, target string) preparedAttributeNames {
	t.Helper()
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	attribute := registry.attributes[schemaKey(target)]
	if attribute == nil {
		t.Fatalf("unknown target %q", target)
	}
	return registry.prepareAttributeNames(attribute)
}

func TestPreparedNamesInvalidateOnSchemaChanges(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	old := cachedNames(t, registry, "uid")
	child := AttributeType{OID: "1.2.3.995", Names: []string{"cachedChild"}, Superior: "uid"}
	if err := registry.RegisterAttributeType(child); err != nil {
		t.Fatal(err)
	}
	if len(registry.preparedNames.plans) != 0 {
		t.Fatal("registration retained old plans")
	}
	afterAdd := cachedNames(t, registry, "uid")
	if old.match("cachedChild") || !afterAdd.match("cachedChild") {
		t.Fatal("new subtype or old immutable plan changed")
	}
	child.Superior = "cn"
	if err := registry.UpsertAttributeType(child); err != nil {
		t.Fatal(err)
	}
	if len(registry.preparedNames.plans) != 0 {
		t.Fatal("replacement retained old plans")
	}
	if cachedNames(t, registry, "uid").match("cachedChild") || !afterAdd.match("cachedChild") {
		t.Fatal("replacement changed a published plan or failed to invalidate")
	}
	cloned := registry.Clone()
	if len(cloned.preparedNames.plans) != 0 {
		t.Fatal("clone inherited prepared state")
	}
	child.Superior = "uid"
	if err := cloned.UpsertAttributeType(child); err != nil {
		t.Fatal(err)
	}
	if !cachedNames(t, cloned, "uid").match("cachedChild") || cachedNames(t, registry, "uid").match("cachedChild") {
		t.Fatal("clone and original share preparation state")
	}
	if err := RegisterOpenLDAPAllowedSchema(registry); err != nil {
		t.Fatal(err)
	}
	if len(registry.preparedNames.plans) != 0 {
		t.Fatal("allowed schema registration retained plans")
	}
	cachedNames(t, registry, "uid")
	if err := RegisterOpenLDAPConfigurationSchema(registry); err != nil {
		t.Fatal(err)
	}
	if len(registry.preparedNames.plans) != 0 {
		t.Fatal("configuration schema replacement retained plans")
	}
}

func TestPreparedNamesConcurrentPreparation(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	failures := make(chan error, 9)
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < 100; i++ {
				matcher, err := registry.PrepareSubstringMatcher("uid", directory.Substring{Initial: []byte("sam")})
				if err != nil {
					failures <- err
					return
				}
				matched, err := matcher.Match(directory.Entry{Attributes: []directory.Attribute{{Description: "uid", Values: [][]byte{[]byte("sample")}}}})
				if err != nil || !matched {
					failures <- fmt.Errorf("stable UID changed: %v/%v", matched, err)
					return
				}
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for i := 0; i < 40; i++ {
			if err := registry.UpsertAttributeType(AttributeType{OID: "1.2.3.996", Names: []string{"unrelatedPreparedAttribute"}, Superior: "cn"}); err != nil {
				failures <- err
				return
			}
		}
	}()
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

func TestPreparedNamesCacheBounds(t *testing.T) {
	registry := NewRegistry()
	for i := 0; i < maxPreparedNamePlans+5; i++ {
		if err := registry.RegisterAttributeType(AttributeType{OID: fmt.Sprintf("1.2.3.%d", i), Names: []string{fmt.Sprintf("attr%d", i)}}); err != nil {
			t.Fatal(err)
		}
	}
	retained := cachedNames(t, registry, "attr0")
	for i := 0; i < maxPreparedNamePlans+5; i++ {
		name := fmt.Sprintf("attr%d", i)
		if !cachedNames(t, registry, name).match(name) {
			t.Fatal("eviction changed selection")
		}
		if len(registry.preparedNames.plans) > maxPreparedNamePlans || registry.preparedNames.bytes > maxPreparedNameBytes {
			t.Fatal("cache exceeded its bound")
		}
	}
	if !retained.match("attr0") || retained.match("attr1") {
		t.Fatal("eviction mutated a published map")
	}
	large := NewRegistry()
	for i := 0; i < maxPreparedNameBytes/64+1; i++ {
		key := fmt.Sprintf("attr%d", i)
		large.attributes[key] = &AttributeType{OID: fmt.Sprintf("1.2.3.%d", i)}
	}
	if !cachedNames(t, large, "attr0").match("attr0") {
		t.Fatal("oversized uncached plan changed selection")
	}
	if len(large.preparedNames.plans) != 0 || large.preparedNames.bytes != 0 {
		t.Fatal("oversized plan was cached")
	}
}
