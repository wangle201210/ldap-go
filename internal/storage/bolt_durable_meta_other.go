//go:build windows || plan9 || openbsd

package storage

import "os"

func openBoltDurableMetaFile(string) (*os.File, error) {
	return nil, nil
}
