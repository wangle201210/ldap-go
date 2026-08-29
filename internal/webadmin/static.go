package webadmin

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed static/*
var staticFiles embed.FS

func (application *Application) staticHandler() http.Handler {
	root, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(root))
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/api/") {
			writeAPIError(response, http.StatusNotFound, apiError{
				Code: "not_found", Message: "API endpoint not found",
			})
			return
		}
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			methodAllowed(response, request, http.MethodGet, http.MethodHead)
			return
		}
		response.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(response, request)
	})
}
