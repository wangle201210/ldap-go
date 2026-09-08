package server

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

const openLDAPLogOpenFlags = 0

func openLDAPLogChangeTime(_ *os.File, information os.FileInfo) (time.Time, error) {
	return information.ModTime().Truncate(time.Second), nil
}

func validateOpenLDAPLogHandle(file *os.File, _ os.FileInfo) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &information); err != nil {
		return err
	}
	if information.NumberOfLinks != 1 || information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("logfile must be a regular file with exactly one hard link")
	}
	return nil
}
