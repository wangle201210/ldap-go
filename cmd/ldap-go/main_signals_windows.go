//go:build windows

package main

import "os"

func mainShutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
