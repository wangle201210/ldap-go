package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// servePIDFile owns a pidfile created exclusively for the current process.
type servePIDFile struct {
	mu      sync.Mutex
	path    string
	file    *os.File
	info    os.FileInfo
	content string
	closed  bool
}

// acquireServePIDFile creates an absolute pidfile path without replacing any
// existing file. Existing files are rejected even when their PID is stale.
func acquireServePIDFile(path string) (*servePIDFile, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("pidfile path must be absolute: %q", path)
	}
	path = filepath.Clean(path)
	content := strconv.Itoa(os.Getpid()) + "\n"

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create pidfile %q: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("stat pidfile %q: %w", path, err),
			closeAndRemoveOwnedPIDFile(file, path, nil),
		)
	}
	pidfile := &servePIDFile{
		path:    path,
		file:    file,
		info:    info,
		content: content,
	}

	if err := file.Chmod(0o600); err != nil {
		return nil, errors.Join(
			fmt.Errorf("set pidfile %q permissions: %w", path, err),
			pidfile.discard(),
		)
	}
	if n, err := io.WriteString(file, content); err != nil || n != len(content) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return nil, errors.Join(
			fmt.Errorf("write pidfile %q: %w", path, err),
			pidfile.discard(),
		)
	}
	if err := file.Sync(); err != nil {
		return nil, errors.Join(
			fmt.Errorf("sync pidfile %q: %w", path, err),
			pidfile.discard(),
		)
	}
	return pidfile, nil
}

// Close releases the pidfile and removes it only while the path still refers
// to the file created by this handle and contains this process's exact PID.
func (p *servePIDFile) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true

	closeErr := p.file.Close()
	owned, err := pidFileMatches(p.path, p.info, p.content)
	if err != nil {
		return errors.Join(closeErr, err)
	}
	if !owned {
		return closeErr
	}

	// Recheck identity and contents immediately before removal to avoid deleting
	// a path that was replaced or modified while it was being inspected.
	owned, err = pidFileMatches(p.path, p.info, p.content)
	if err != nil {
		return errors.Join(closeErr, err)
	}
	if !owned {
		return closeErr
	}
	if err := os.Remove(p.path); err != nil && !os.IsNotExist(err) {
		return errors.Join(closeErr, fmt.Errorf("remove pidfile %q: %w", p.path, err))
	}
	return closeErr
}

func (p *servePIDFile) discard() error {
	p.closed = true
	return closeAndRemoveOwnedPIDFile(p.file, p.path, p.info)
}

func closeAndRemoveOwnedPIDFile(file *os.File, path string, expected os.FileInfo) error {
	closeErr := file.Close()
	if expected == nil {
		return closeErr
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return closeErr
		}
		return errors.Join(closeErr, err)
	}
	if !os.SameFile(expected, info) {
		return closeErr
	}
	removeErr := os.Remove(path)
	if os.IsNotExist(removeErr) {
		removeErr = nil
	}
	return errors.Join(closeErr, removeErr)
}

func pidFileMatches(path string, expected os.FileInfo, content string) (bool, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("lstat pidfile %q for cleanup: %w", path, err)
	}
	if !os.SameFile(expected, pathInfo) {
		return false, nil
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("open pidfile %q for cleanup: %w", path, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("stat pidfile %q for cleanup: %w", path, err)
	}
	if !os.SameFile(expected, info) || info.Size() != int64(len(content)) {
		return false, nil
	}
	buffer := make([]byte, len(content))
	if _, err := io.ReadFull(file, buffer); err != nil {
		return false, fmt.Errorf("read pidfile %q for cleanup: %w", path, err)
	}
	return string(buffer) == content, nil
}
