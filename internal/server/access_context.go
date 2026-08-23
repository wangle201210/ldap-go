package server

import (
	"context"
	"net"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type aclSubjectContextKey struct{}

type accessContextStore struct {
	storage.Store
}

func (store *accessContextStore) View(
	ctx context.Context,
	view func(storage.Reader) error,
) error {
	coordinator := newSQLBackendReadCoordinator(ctx)
	ctx = withSQLBackendReadCoordinator(ctx, coordinator)
	defer coordinator.close()
	return store.Store.View(ctx, func(reader storage.Reader) error {
		return view(accessReaderFromContext(ctx, reader))
	})
}

func (store *accessContextStore) Update(
	ctx context.Context,
	update func(storage.Writer) error,
) error {
	return store.Store.Update(ctx, func(writer storage.Writer) error {
		return update(accessWriterFromContext(ctx, writer))
	})
}

type accessContextReader struct {
	storage.Reader
	subject acl.Subject
	ctx     context.Context
}

func (reader accessContextReader) AccessContext() any {
	return reader.subject
}

func (reader accessContextReader) StorageContext() context.Context {
	return reader.ctx
}

type accessContextWriter struct {
	storage.Writer
	subject acl.Subject
	ctx     context.Context
}

func (writer accessContextWriter) AccessContext() any {
	return writer.subject
}

func (writer accessContextWriter) StorageContext() context.Context {
	return writer.ctx
}

func withACLSubject(ctx context.Context, subject acl.Subject) context.Context {
	return context.WithValue(ctx, aclSubjectContextKey{}, subject)
}

func accessReaderFromContext(ctx context.Context, reader storage.Reader) storage.Reader {
	subject, _ := ctx.Value(aclSubjectContextKey{}).(acl.Subject)
	return accessContextReader{Reader: reader, subject: subject, ctx: ctx}
}

func accessWriterFromContext(ctx context.Context, writer storage.Writer) storage.Writer {
	subject, _ := ctx.Value(aclSubjectContextKey{}).(acl.Subject)
	return accessContextWriter{Writer: writer, subject: subject, ctx: ctx}
}

func accessSubject(reader storage.Reader, subjectDN string) acl.Subject {
	subject := acl.Subject{DN: subjectDN, RealDN: subjectDN}
	if provider, ok := reader.(interface{ AccessContext() any }); ok {
		if contextual, ok := provider.AccessContext().(acl.Subject); ok {
			subject = contextual
			subject.DN = subjectDN
			if subject.RealDN == "" {
				subject.RealDN = subjectDN
			}
		}
	}
	return subject
}

func (server *Server) connectionACLSubject(state *connectionState) acl.Subject {
	if state == nil {
		return acl.Subject{}
	}
	subject := acl.Subject{
		DN:       state.boundDN,
		RealDN:   state.operationRealDN,
		PeerName: openLDAPConnectionName(remoteAddress(state.connection)),
		SockName: openLDAPConnectionName(localAddress(state.connection)),
		SockURL:  monitorListenerURL(localAddress(state.connection), server.config.ImplicitTLS),
	}
	strength := int(state.externalSSF)
	if state.secure {
		subject.TLSSSF = strength
	} else {
		subject.TransportSSF = strength
	}
	subject.SASLSSF = int(state.saslSSF)
	subject.SSF = max(subject.TransportSSF, subject.TLSSSF, subject.SASLSSF)
	if subject.RealDN == "" {
		subject.RealDN = subject.DN
	}
	return subject
}

func connectionOverallSSF(state *connectionState) uint32 {
	if state == nil {
		return 0
	}
	return max(state.externalSSF, state.saslSSF)
}

func localAddress(connection net.Conn) net.Addr {
	if connection == nil {
		return nil
	}
	return connection.LocalAddr()
}

func remoteAddress(connection net.Conn) net.Addr {
	if connection == nil {
		return nil
	}
	return connection.RemoteAddr()
}

func openLDAPConnectionName(address net.Addr) string {
	if address == nil {
		return ""
	}
	switch address.Network() {
	case "unix", "unixpacket":
		return "PATH=" + address.String()
	default:
		return "IP=" + address.String()
	}
}
