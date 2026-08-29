//go:build windows

package main

type systemdNotifier struct{}

func openSystemdNotifier(func(string) string) (*systemdNotifier, bool, error) {
	return nil, false, nil
}

func (*systemdNotifier) Notify(string) error { return nil }
func (*systemdNotifier) Close() error        { return nil }

func notifySystemd(func(string) string, string) (bool, error) {
	return false, nil
}
