//go:build windows

package main

import "os"

func lloaddShutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

func lloaddManagementSignals() []os.Signal {
	return nil
}

func lloaddIsShutdownSignal(os.Signal) bool {
	return false
}

func lloaddIsReloadSignal(os.Signal) bool {
	return false
}
