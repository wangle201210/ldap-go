package server

import (
	"context"
	"net"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

// runAsyncMetaBackendSearch uses the shared target worker and transport code.
// Each plan owns an independently cancelable upstream operation, while the
// collector serializes merged LDAP responses onto the frontend connection.
func (server *Server) runAsyncMetaBackendSearch(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	database runtimeDatabase,
	request ldapwire.SearchRequest,
	plans []metaSearchPlan,
	limit int,
) (bool, error) {
	return server.runMetaBackendSearch(
		ctx,
		connection,
		state,
		message,
		database,
		request,
		plans,
		limit,
	)
}
