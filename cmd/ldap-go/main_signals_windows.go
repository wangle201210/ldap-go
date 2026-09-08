//go:build windows

package main

import (
	"os"
	"syscall"
)

func mainShutdownSignals() []os.Signal {
	// Windows delivers console close, logoff, and shutdown events as SIGTERM.
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func serveShutdownSignals() []os.Signal {
	return mainShutdownSignals()
}

func serveManagementSignals() []os.Signal {
	return nil
}

func serveIsGentleSignal(os.Signal) bool {
	return false
}
