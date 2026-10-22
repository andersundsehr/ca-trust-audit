//go:build linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// Query the actual terminal without an external command or cgo dependency.
func terminalColumns(f *os.File) int {
	var size struct{ rows, columns, xpixel, ypixel uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&size)))
	if errno != 0 {
		return 0
	}
	if size.columns == 0 {
		return 80
	}
	return int(size.columns)
}
