package webadmin

import "net/http"

const recommendedCapabilitiesPageSize = 200

type capabilitiesResponse struct {
	MaxSearchSize       int   `json:"max_search_size"`
	MaxSearchSeconds    int   `json:"max_search_seconds"`
	MaxAttributes       int   `json:"max_attributes"`
	MaxImportChanges    int   `json:"max_import_changes"`
	MaxExportEntries    int   `json:"max_export_entries"`
	MaxExportBytes      int64 `json:"max_export_bytes"`
	RequestBodyLimit    int64 `json:"request_body_limit"`
	MaxMonitorEntries   int   `json:"max_monitor_entries"`
	BinaryMaxValues     int   `json:"binary_max_values"`
	BinaryMaxValueBytes int   `json:"binary_max_value_bytes"`
	BinaryMaxTotalBytes int   `json:"binary_max_total_bytes"`
	RecommendedPageSize int   `json:"page_size"`
}

// handleCapabilities exposes the effective Web administration resource limits
// for the authenticated UI without contacting LDAP.
func (application *Application) handleCapabilities(response http.ResponseWriter, request *http.Request) {
	if !methodAllowed(response, request, http.MethodGet) {
		return
	}
	current, ok := application.acquireSession(response, request)
	if !ok {
		return
	}
	defer application.releaseSession(current)

	writeJSON(response, http.StatusOK, capabilitiesResponse{
		MaxSearchSize:       application.config.MaxSearchSize,
		MaxSearchSeconds:    application.config.MaxSearchSeconds,
		MaxAttributes:       application.config.MaxAttributes,
		MaxImportChanges:    application.config.MaxImportChanges,
		MaxExportEntries:    application.config.MaxExportEntries,
		MaxExportBytes:      application.config.MaxExportBytes,
		RequestBodyLimit:    application.config.RequestBodyLimit,
		MaxMonitorEntries:   application.config.MaxMonitorEntries,
		BinaryMaxValues:     maximumBinaryAttributeValues,
		BinaryMaxValueBytes: maximumBinaryValueBytes,
		BinaryMaxTotalBytes: maximumBinaryTotalBytes,
		RecommendedPageSize: min(recommendedCapabilitiesPageSize, application.config.MaxSearchSize),
	})
}
