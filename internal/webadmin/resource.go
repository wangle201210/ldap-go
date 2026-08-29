package webadmin

import (
	"errors"
	"net/http"
	"sync"
	"unsafe"

	ldap "github.com/go-ldap/ldap/v3"
)

type ldapResponseLimitError struct {
	process bool
}

func (failure *ldapResponseLimitError) Error() string {
	if failure.process {
		return "Web administration LDAP response process budget exceeded"
	}
	return "LDAP response exceeds the Web administration operation budget"
}

func (application *Application) admitLDAPOperations(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !webRequestUsesLDAP(request.URL.Path) {
			next.ServeHTTP(response, request)
			return
		}
		select {
		case application.operations <- struct{}{}:
			defer func() { <-application.operations }()
			next.ServeHTTP(response, request)
		default:
			writeAPIError(response, http.StatusServiceUnavailable, apiError{
				Code:    "operation_capacity_reached",
				Message: "Web administration LDAP operation capacity reached",
			})
		}
	})
}

func webRequestUsesLDAP(path string) bool {
	switch path {
	case "/api/login", "/api/root-dse", "/api/root",
		"/api/search", "/api/entries", "/api/entry", "/api/entries/rename",
		"/api/rename", "/api/password-modify", "/api/password", "/api/schema",
		"/api/monitor", "/api/export", "/api/import":
		return true
	default:
		return false
	}
}

func (application *Application) search(
	client Client,
	request *ldap.SearchRequest,
) (*ldap.SearchResult, func(), error) {
	result, err := client.Search(request)
	if err != nil {
		return nil, nil, err
	}
	size := ldapSearchResultRetainedBytes(result)
	if size > application.config.MaxLDAPResponseBytes {
		application.responseRejects.Add(1)
		return nil, nil, &ldapResponseLimitError{}
	}
	for {
		active := application.responseBytes.Load()
		if size > application.config.MaxProcessResponseBytes-active {
			application.responseRejects.Add(1)
			return nil, nil, &ldapResponseLimitError{process: true}
		}
		if application.responseBytes.CompareAndSwap(active, active+size) {
			break
		}
	}
	var once sync.Once
	release := func() {
		once.Do(func() { application.responseBytes.Add(-size) })
	}
	return result, release, nil
}

func ldapSearchResultRetainedBytes(result *ldap.SearchResult) int64 {
	if result == nil {
		return 1
	}
	size := int64(unsafe.Sizeof(*result)) +
		int64(cap(result.Entries))*int64(unsafe.Sizeof((*ldap.Entry)(nil))) +
		int64(cap(result.Referrals))*int64(unsafe.Sizeof("")) +
		int64(cap(result.Controls))*int64(unsafe.Sizeof(ldap.Control(nil)))
	for _, referral := range result.Referrals {
		size += int64(len(referral))
	}
	for _, entry := range result.Entries {
		if entry == nil {
			continue
		}
		size += int64(unsafe.Sizeof(*entry)) + int64(len(entry.DN)) +
			int64(cap(entry.Attributes))*int64(unsafe.Sizeof((*ldap.EntryAttribute)(nil)))
		for _, attribute := range entry.Attributes {
			if attribute == nil {
				continue
			}
			size += int64(unsafe.Sizeof(*attribute)) + int64(len(attribute.Name)) +
				int64(cap(attribute.ByteValues))*int64(unsafe.Sizeof([]byte{})) +
				int64(cap(attribute.Values))*int64(unsafe.Sizeof(""))
			for _, value := range attribute.ByteValues {
				size += int64(len(value))
			}
			for _, value := range attribute.Values {
				size += int64(len(value))
			}
		}
	}
	if size < 1 {
		return 1
	}
	return size
}

func writeLDAPResponseLimitError(response http.ResponseWriter, err error) bool {
	var failure *ldapResponseLimitError
	if !errors.As(err, &failure) {
		return false
	}
	status := http.StatusRequestEntityTooLarge
	code := "ldap_response_too_large"
	if failure.process {
		status = http.StatusServiceUnavailable
		code = "ldap_response_capacity_reached"
	}
	writeAPIError(response, status, apiError{Code: code, Message: failure.Error()})
	return true
}
