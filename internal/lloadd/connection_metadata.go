package lloadd

import (
	"errors"
	"net"
)

// ProxyProtocolTLV is one type-length-value record from a trusted PROXY v2
// listener. Values are copied when metadata crosses the listener boundary.
type ProxyProtocolTLV struct {
	Type  byte
	Value []byte
}

// ConnectionMetadata separates the logical addresses asserted by a trusted
// proxy from the transport peer that delivered the connection.
type ConnectionMetadata struct {
	ProxyProtocol               bool
	ProxyProtocolLocal          bool
	SourceAddress               net.Addr
	DestinationAddress          net.Addr
	TransportSourceAddress      net.Addr
	TransportDestinationAddress net.Addr
	TLVs                        []ProxyProtocolTLV
}

// ClientConnectionSnapshot is the read-only connection context consumed by
// monitoring and access decisions. AuthorizationIdentity is the identity that
// the ProxyAuthz path currently forwards for this client.
type ClientConnectionSnapshot struct {
	Metadata              ConnectionMetadata
	TLS                   bool
	AuthorizationIdentity string
}

type connectionMetadataProvider interface {
	ConnectionMetadata() ConnectionMetadata
}

type connectionMetadataConn struct {
	net.Conn
	metadata ConnectionMetadata
}

func (connection *connectionMetadataConn) LocalAddr() net.Addr {
	return connection.metadata.DestinationAddress
}

func (connection *connectionMetadataConn) RemoteAddr() net.Addr {
	return connection.metadata.SourceAddress
}

func (connection *connectionMetadataConn) NetConn() net.Conn {
	return connection.Conn
}

func (connection *connectionMetadataConn) Unwrap() net.Conn {
	return connection.Conn
}

func (connection *connectionMetadataConn) ConnectionMetadata() ConnectionMetadata {
	return cloneConnectionMetadata(connection.metadata)
}

// WithConnectionMetadata wraps an accepted connection so address-based access
// checks, monitoring, logging and connection state all observe the trusted
// logical source and destination while retaining the transport addresses.
func WithConnectionMetadata(
	connection net.Conn,
	metadata ConnectionMetadata,
) (net.Conn, error) {
	if connection == nil {
		return nil, errors.New("connection metadata requires a connection")
	}
	if metadata.SourceAddress == nil || metadata.DestinationAddress == nil {
		return nil, errors.New("connection metadata requires source and destination addresses")
	}
	if metadata.TransportSourceAddress == nil {
		metadata.TransportSourceAddress = connection.RemoteAddr()
	}
	if metadata.TransportDestinationAddress == nil {
		metadata.TransportDestinationAddress = connection.LocalAddr()
	}
	metadata = cloneConnectionMetadata(metadata)
	return &connectionMetadataConn{Conn: connection, metadata: metadata}, nil
}

// MetadataFromConnection finds metadata through the wrappers used by implicit
// TLS and socket-option transports. The returned value is an independent copy.
func MetadataFromConnection(connection net.Conn) (ConnectionMetadata, bool) {
	const maximumWrappers = 16
	for depth := 0; depth < maximumWrappers && connection != nil; depth++ {
		if provider, ok := connection.(connectionMetadataProvider); ok {
			return provider.ConnectionMetadata(), true
		}
		var next net.Conn
		switch wrapped := connection.(type) {
		case interface{ NetConn() net.Conn }:
			next = wrapped.NetConn()
		case interface{ Unwrap() net.Conn }:
			next = wrapped.Unwrap()
		default:
			return ConnectionMetadata{}, false
		}
		if next == nil || next == connection {
			return ConnectionMetadata{}, false
		}
		connection = next
	}
	return ConnectionMetadata{}, false
}

// ClientConnectionSnapshots returns an independent snapshot of active client
// metadata without exposing live connections or credential material.
func (proxy *Proxy) ClientConnectionSnapshots() []ClientConnectionSnapshot {
	proxy.mu.Lock()
	clients := make([]*clientConnection, 0, len(proxy.clients))
	for client := range proxy.clients {
		clients = append(clients, client)
	}
	proxy.mu.Unlock()

	snapshots := make([]ClientConnectionSnapshot, 0, len(clients))
	for _, client := range clients {
		client.mu.Lock()
		if !client.closed {
			snapshots = append(snapshots, ClientConnectionSnapshot{
				Metadata:              cloneConnectionMetadata(client.metadata),
				TLS:                   client.tlsActive,
				AuthorizationIdentity: string(client.authzID),
			})
		}
		client.mu.Unlock()
	}
	return snapshots
}

func cloneConnectionMetadata(metadata ConnectionMetadata) ConnectionMetadata {
	metadata.SourceAddress = cloneNetworkAddress(metadata.SourceAddress)
	metadata.DestinationAddress = cloneNetworkAddress(metadata.DestinationAddress)
	metadata.TransportSourceAddress = cloneNetworkAddress(metadata.TransportSourceAddress)
	metadata.TransportDestinationAddress = cloneNetworkAddress(metadata.TransportDestinationAddress)
	if metadata.TLVs != nil {
		cloned := make([]ProxyProtocolTLV, len(metadata.TLVs))
		for index, tlv := range metadata.TLVs {
			cloned[index] = ProxyProtocolTLV{
				Type:  tlv.Type,
				Value: append([]byte(nil), tlv.Value...),
			}
		}
		metadata.TLVs = cloned
	}
	return metadata
}

func cloneNetworkAddress(address net.Addr) net.Addr {
	switch value := address.(type) {
	case *net.TCPAddr:
		if value == nil {
			return nil
		}
		return &net.TCPAddr{
			IP:   append(net.IP(nil), value.IP...),
			Port: value.Port,
			Zone: value.Zone,
		}
	case *net.UnixAddr:
		if value == nil {
			return nil
		}
		return &net.UnixAddr{Name: value.Name, Net: value.Net}
	default:
		return address
	}
}
