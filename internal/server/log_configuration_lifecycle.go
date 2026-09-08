package server

import (
	"fmt"
	"sync/atomic"
	"time"
)

// A candidate owns one reference until activation or transaction cleanup takes it.
// The indirection also makes shallow runtime copies safe.
type preparedOpenLDAPLogFile struct {
	file atomic.Pointer[openLDAPLogFile]
}

func (prepared *preparedOpenLDAPLogFile) close() {
	if prepared != nil {
		_ = prepared.file.Swap(nil).close()
	}
}

func (monitor *monitorState) prepareLogFile(
	configuration openLDAPLogFileConfiguration,
	clock func() time.Time,
) (*preparedOpenLDAPLogFile, error) {
	prepared := &preparedOpenLDAPLogFile{}
	monitor.logFileMu.RLock()
	current := monitor.logFile.Load()
	if current != nil && current.configuration.path == configuration.path {
		current.mu.Lock()
		current.references++
		current.mu.Unlock()
		prepared.file.Store(current)
		monitor.logFileMu.RUnlock()
		return prepared, nil
	}
	monitor.logFileMu.RUnlock()
	file, err := openConfiguredLDAPLogFile(configuration, clock)
	if err != nil {
		return nil, invalidLogConfiguration(fmt.Sprintf("olcLogFile cannot open %q: %v", configuration.path, err))
	}
	prepared.file.Store(file)
	return prepared, nil
}

func (monitor *monitorState) installLogFile(
	prepared *preparedOpenLDAPLogFile,
	configuration openLDAPLogFileConfiguration,
) {
	monitor.logFileMu.Lock()
	defer monitor.logFileMu.Unlock()
	next := prepared.file.Swap(nil)
	if monitor.logFileClosed {
		_ = next.close()
		return
	}
	previous := monitor.logFile.Load()
	// Keep rotation accounting and the current inode across unrelated changes.
	if previous != nil && previous.configuration.path == configuration.path {
		previous.mu.Lock()
		previous.configuration = configuration
		previous.mu.Unlock()
		_ = next.close()
		return
	}
	if next != nil {
		next.mu.Lock()
		next.configuration = configuration
		next.mu.Unlock()
	}
	monitor.logFile.Store(next)
	_ = previous.close()
}

func (monitor *monitorState) closeLogFile() {
	monitor.logFileMu.Lock()
	defer monitor.logFileMu.Unlock()
	monitor.logFileClosed = true
	_ = monitor.logFile.Swap(nil).close()
}
