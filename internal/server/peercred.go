package server

import (
	"fmt"
	"net"
)

func peercredExternalIdentity(connection net.Conn) (string, error) {
	if connection == nil || connection.LocalAddr() == nil ||
		connection.LocalAddr().Network() != "unix" {
		return "", nil
	}
	uid, gid, available, err := unixPeerCredentials(connection)
	if err != nil {
		return "", err
	}
	if !available {
		return "", nil
	}
	return fmt.Sprintf(
		"gidNumber=%d+uidNumber=%d,cn=peercred,cn=external,cn=auth",
		gid,
		uid,
	), nil
}
