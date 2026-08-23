package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var errBoltPathLockBusy = errors.New("database path is locked")

// The sidecar is deliberately persistent. Removing a lock file after unlock
// would let a waiter lock the old inode while a new opener locks a replacement.
type boltPathLock struct {
	key       string
	exclusive bool
	once      sync.Once
	err       error
}

type boltPathLockState struct {
	file      *os.File
	readers   int
	exclusive bool
}

var boltPathLocks = struct {
	sync.Mutex
	states map[string]*boltPathLockState
}{states: make(map[string]*boltPathLockState)}

func acquireBoltPathLock(databasePath string, exclusive bool) (*boltPathLock, error) {
	lockPath, err := boltPathLockPath(databasePath)
	if err != nil {
		return nil, err
	}

	boltPathLocks.Lock()
	defer boltPathLocks.Unlock()
	if state := boltPathLocks.states[lockPath]; state != nil {
		if exclusive || state.exclusive {
			return nil, fmt.Errorf("%w: %q", errBoltPathLockBusy, databasePath)
		}
		state.readers++
		return &boltPathLock{key: lockPath}, nil
	}

	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open sidecar %q: %w", lockPath, err)
	}
	locked, err := tryPlatformFileLock(file, exclusive)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock sidecar %q: %w", lockPath, err)
	}
	if !locked {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %q", errBoltPathLockBusy, databasePath)
	}

	state := &boltPathLockState{file: file, exclusive: exclusive}
	if !exclusive {
		state.readers = 1
	}
	boltPathLocks.states[lockPath] = state
	return &boltPathLock{key: lockPath, exclusive: exclusive}, nil
}

func (lock *boltPathLock) Close() error {
	if lock == nil {
		return nil
	}
	lock.once.Do(func() {
		boltPathLocks.Lock()
		defer boltPathLocks.Unlock()
		state := boltPathLocks.states[lock.key]
		if state == nil || state.exclusive != lock.exclusive {
			lock.err = errors.New("database path lock state is inconsistent")
			return
		}
		if !state.exclusive && state.readers > 1 {
			state.readers--
			return
		}
		delete(boltPathLocks.states, lock.key)
		lock.err = errors.Join(
			unlockPlatformFile(state.file),
			state.file.Close(),
		)
	})
	return lock.err
}

func boltPathLockPath(databasePath string) (string, error) {
	absolute, err := filepath.Abs(databasePath)
	if err != nil {
		return "", fmt.Errorf("resolve database path: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(absolute); resolveErr == nil {
		absolute = resolved
	}
	parent := filepath.Dir(absolute)
	if resolved, resolveErr := filepath.EvalSymlinks(parent); resolveErr == nil {
		parent = resolved
	}
	return filepath.Join(parent, filepath.Base(absolute)) + ".lock", nil
}
