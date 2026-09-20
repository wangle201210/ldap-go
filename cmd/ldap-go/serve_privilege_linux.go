package main

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"

	"github.com/ebitengine/purego"
)

type serveCredentialFunctions struct {
	setgroups func(uintptr, *uint32) int32
	setgid    func(uint32) int32
	setuid    func(uint32) int32
	errno     func() *int32
}

var loadServeCredentialFunctions = sync.OnceValues(func() (*serveCredentialFunctions, error) {
	functions := new(serveCredentialFunctions)
	for _, symbol := range []struct {
		name     string
		function any
	}{
		{"setgroups", &functions.setgroups},
		{"setgid", &functions.setgid},
		{"setuid", &functions.setuid},
		{"__errno_location", &functions.errno},
	} {
		// libc is already loaded by purego, even inside a chroot without libraries.
		address, err := purego.Dlsym(purego.RTLD_DEFAULT, symbol.name)
		if err != nil {
			return nil, fmt.Errorf("resolve libc %s: %w", symbol.name, err)
		}
		purego.RegisterFunc(symbol.function, address)
	}
	return functions, nil
})

func callServeCredentialFunction(call func(*serveCredentialFunctions) int32) error {
	functions, err := loadServeCredentialFunctions()
	if err != nil {
		return err
	}
	// purego's fakecgo sets runtime.iscgo, so syscall.AllThreadsSyscall panics.
	// libc's setxid wrappers synchronize credentials across all pthreads,
	// including those created by fakecgo; raw Linux syscalls affect one thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if call(functions) != 0 {
		// errno belongs to the calling OS thread.
		return syscall.Errno(*functions.errno())
	}
	return nil
}

func serveSetgroups(groups []int) error {
	gids := make([]uint32, len(groups))
	for index, gid := range groups {
		gids[index] = uint32(gid)
	}
	var first *uint32
	if len(gids) != 0 {
		first = &gids[0]
	}
	return callServeCredentialFunction(func(functions *serveCredentialFunctions) int32 {
		return functions.setgroups(uintptr(len(gids)), first)
	})
}

func serveSetgid(gid int) error {
	return callServeCredentialFunction(func(functions *serveCredentialFunctions) int32 {
		return functions.setgid(uint32(gid))
	})
}

func serveSetuid(uid int) error {
	return callServeCredentialFunction(func(functions *serveCredentialFunctions) int32 {
		return functions.setuid(uint32(uid))
	})
}
