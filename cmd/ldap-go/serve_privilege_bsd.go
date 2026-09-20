//go:build darwin || freebsd

package main

import "syscall"

func serveSetgroups(groups []int) error { return syscall.Setgroups(groups) }
func serveSetgid(gid int) error         { return syscall.Setgid(gid) }
func serveSetuid(uid int) error         { return syscall.Setuid(uid) }
