//go:build windows

package main

import "os"

func mainShutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
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
