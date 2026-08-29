//go:build !linux && !darwin && !freebsd

package server

import "net"

func unixPeerCredentials(net.Conn) (uint32, uint32, bool, error) {
	return 0, 0, false, nil
}
