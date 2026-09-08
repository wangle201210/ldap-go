//go:build windows

package main

import "os"

func lloaddShutdownSignals() []os.Signal {
	return mainShutdownSignals()
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
