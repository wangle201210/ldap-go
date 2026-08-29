//go:build windows

package main

func notifySystemd(func(string) string, string) (bool, error) {
	return false, nil
}
