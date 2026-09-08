package main

import (
	"os"
	"slices"
	"syscall"
	"testing"
)

func TestShutdownSignalContract(t *testing.T) {
	for _, test := range []struct {
		name       string
		shutdown   []os.Signal
		management []os.Signal
	}{
		{name: "main", shutdown: mainShutdownSignals()},
		{name: "serve", shutdown: serveShutdownSignals(), management: serveManagementSignals()},
		{name: "lloadd", shutdown: lloaddShutdownSignals(), management: lloaddManagementSignals()},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, required := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
				if !slices.Contains(test.shutdown, required) {
					t.Errorf("shutdown does not handle %s", required)
				}
			}
			for _, management := range test.management {
				if slices.Contains(test.shutdown, management) {
					t.Errorf("management signal %s also cancels the shutdown context", management)
				}
			}
		})
	}
}
