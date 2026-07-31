package server

import (
	"net"
	"strings"
	"syscall"
	"time"
)

func configureSyncConsumerDialer(
	dialer *net.Dialer,
	config syncConsumerConfig,
) error {
	if config.keepalive.set {
		dialer.KeepAliveConfig = net.KeepAliveConfig{
			Enable:   true,
			Idle:     syncConsumerKeepaliveDuration(config.keepalive.idle),
			Interval: syncConsumerKeepaliveDuration(config.keepalive.interval),
			Count:    syncConsumerKeepaliveCount(config.keepalive.probes),
		}
	}
	if config.tcpUserTimeout <= 0 {
		return nil
	}
	dialer.Control = func(
		network,
		_ string,
		raw syscall.RawConn,
	) error {
		if !strings.HasPrefix(network, "tcp") {
			return nil
		}
		var optionErr error
		if err := raw.Control(func(fileDescriptor uintptr) {
			optionErr = setSyncConsumerTCPUserTimeout(
				fileDescriptor,
				config.tcpUserTimeout,
			)
		}); err != nil {
			return err
		}
		return optionErr
	}
	return nil
}

func syncConsumerKeepaliveDuration(seconds int) time.Duration {
	if seconds == 0 {
		return -1
	}
	return time.Duration(seconds) * time.Second
}

func syncConsumerKeepaliveCount(count int) int {
	if count == 0 {
		return -1
	}
	return count
}
