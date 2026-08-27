package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/go-ldap/ldif"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const maxRootDSEFileSize = int64(16 << 20)

type rootDSEConfigurationError struct {
	err error
}

func (failure *rootDSEConfigurationError) Error() string {
	return failure.err.Error()
}

func rootDSEConfigurationResult(err error) (ldapwire.Result, bool) {
	var failure *rootDSEConfigurationError
	if !errors.As(err, &failure) {
		return ldapwire.Result{}, false
	}
	return ldapwire.ResultError(
		ldapwire.ResultOther,
		"invalid cn=config: "+err.Error(),
	), true
}

func loadRootDSEConfiguration(
	reader storage.Reader,
	registry *schema.Registry,
	previous *runtimeState,
) ([]string, []directory.Attribute, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("load olcRootDSE: %w", err)
	}
	rawValues := entry.Values("olcRootDSE")
	files := make([]string, len(rawValues))
	for index, value := range rawValues {
		files[index] = string(value)
	}
	if previous != nil && slices.Equal(files, previous.rootDSEFiles) {
		return append([]string(nil), files...), cloneRootDSEAttributes(previous.rootDSEAttributes), nil
	}
	if len(files) == 0 {
		return nil, nil, nil
	}
	attributes, err := readRootDSEFile(files[len(files)-1], registry)
	if err != nil {
		return nil, nil, &rootDSEConfigurationError{err: fmt.Errorf(
			"olcRootDSE %q: %w",
			files[len(files)-1],
			err,
		)}
	}
	return files, attributes, nil
}

func readRootDSEFile(
	path string,
	registry *schema.Registry,
) ([]directory.Attribute, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRootDSEFileSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxRootDSEFileSize {
		return nil, fmt.Errorf("file exceeds %d-byte limit", maxRootDSEFileSize)
	}

	var attributes []directory.Attribute
	document := &ldif.LDIF{}
	for record, parseErr := range ldif.UnmarshalEntries(bytes.NewReader(data), document) {
		if parseErr != nil {
			return nil, fmt.Errorf("parse LDIF: %w", parseErr)
		}
		if record == nil || record.Entry == nil {
			return nil, errors.New("LDIF change records are not accepted")
		}
		if record.Entry.DN != "" {
			return nil, fmt.Errorf("entry DN %q is not the Root DSE", record.Entry.DN)
		}
		for _, source := range record.Entry.Attributes {
			if err := validateAttributeDescription(source.Name); err != nil {
				return nil, err
			}
			values := source.ByteValues
			if len(values) == 0 && len(source.Values) > 0 {
				values = make([][]byte, len(source.Values))
				for index, value := range source.Values {
					values[index] = []byte(value)
				}
			}
			if _, defined := registry.AttributeType(source.Name); defined {
				for _, value := range values {
					if err := registry.ValidateAttributeValue(source.Name, value); err != nil {
						return nil, err
					}
				}
			}
			mergeRootDSEAttribute(&attributes, directory.Attribute{
				Description: source.Name,
				Values:      cloneByteValues(values),
			})
		}
	}
	return attributes, nil
}

func mergeRootDSEAttributes(entry *directory.Entry, attributes []directory.Attribute) {
	if entry == nil {
		return
	}
	for _, attribute := range attributes {
		mergeRootDSEAttribute(&entry.Attributes, attribute)
	}
}

func mergeRootDSEAttribute(attributes *[]directory.Attribute, value directory.Attribute) {
	for index := range *attributes {
		if strings.EqualFold((*attributes)[index].Description, value.Description) {
			(*attributes)[index].Values = append(
				(*attributes)[index].Values,
				cloneByteValues(value.Values)...,
			)
			return
		}
	}
	*attributes = append(*attributes, directory.Attribute{
		Description: value.Description,
		Values:      cloneByteValues(value.Values),
	})
}

func cloneRootDSEAttributes(values []directory.Attribute) []directory.Attribute {
	cloned := make([]directory.Attribute, len(values))
	for index, attribute := range values {
		cloned[index] = directory.Attribute{
			Description: attribute.Description,
			Values:      cloneByteValues(attribute.Values),
		}
	}
	return cloned
}
