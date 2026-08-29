//go:build !windows

package main

import (
	"os"
	"syscall"
)

func mainShutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
}

func serveShutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func serveManagementSignals() []os.Signal {
	return []os.Signal{syscall.SIGHUP}
}

func serveIsGentleSignal(signal os.Signal) bool {
	return signal == syscall.SIGHUP
}
