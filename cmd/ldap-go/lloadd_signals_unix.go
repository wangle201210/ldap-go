//go:build !windows

package main

import (
	"os"
	"syscall"
)

func lloaddShutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func lloaddManagementSignals() []os.Signal {
	return []os.Signal{syscall.SIGHUP, syscall.SIGUSR1}
}

func lloaddIsShutdownSignal(signal os.Signal) bool {
	return signal == syscall.SIGHUP
}

func lloaddIsReloadSignal(signal os.Signal) bool {
	return signal == syscall.SIGUSR1
}
