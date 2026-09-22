package server

import (
	"errors"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type runtimeNamingContextFailureWriter struct {
	storage.Writer
	iterationError error
	metadataError  error
}

func (writer runtimeNamingContextFailureWriter) ForEachPartition(visit func(string, directory.Entry) error) error {
	if writer.iterationError != nil {
		return writer.iterationError
	}
	return writer.Writer.ForEachPartition(visit)
}

func (writer runtimeNamingContextFailureWriter) SetNamingContexts(contexts []string) error {
	if writer.metadataError != nil {
		return writer.metadataError
	}
	return writer.Writer.SetNamingContexts(contexts)
}

func (writer runtimeNamingContextFailureWriter) MaintenanceStorageReader() storage.Reader {
	return writer.Writer
}

func TestRefreshRuntimeNamingContextMetadata(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	runtime := &runtimeState{schema: registry}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		for _, dn := range []string{"cn=config", "dc=example,dc=com", "uid=orphan,dc=missing"} {
			if err := writer.Put(directory.Entry{DN: dn}, false); err != nil {
				return err
			}
		}
		want, err := storage.InferNamingContextsWithNormalizer(writer, registry)
		if err != nil {
			return err
		}
		wrapped := newHomedirTrackingWriter(accessContextWriter{Writer: writer}, runtime)
		if namingContextMetadataStorageReader(wrapped) != writer {
			t.Fatal("known transparent writer chain did not reach storage")
		}
		if err := refreshRuntimeNamingContexts(wrapped, runtime); err != nil {
			return err
		}
		got, err := writer.NamingContexts()
		if err == nil && !reflect.DeepEqual(got, want) {
			t.Fatalf("contexts = %q, want %q", got, want)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"iteration", "metadata"} {
		t.Run(failure, func(t *testing.T) {
			injected := errors.New("injected " + failure + " error")
			err := store.Update(t.Context(), func(writer storage.Writer) error {
				failing := runtimeNamingContextFailureWriter{Writer: writer}
				if failure == "iteration" {
					failing.iterationError = injected
				} else {
					failing.metadataError = injected
				}
				wrapped := newHomedirTrackingWriter(&accessContextWriter{Writer: failing}, runtime)
				if namingContextMetadataStorageReader(wrapped) != failing {
					t.Fatal("unknown writer was unwrapped")
				}
				return refreshRuntimeNamingContexts(wrapped, runtime)
			})
			if !errors.Is(err, injected) {
				t.Fatalf("error = %v, want injected error", err)
			}
		})
	}
}
