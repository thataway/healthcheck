//go:build linux
// +build linux

package network

import (
	"os"
	"syscall"
)

//SetSocketMark ...
func (utils sockUtils) SetSocketMark(fd, mark int) error {
	return os.NewSyscallError("set-socket-mark",
		syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark))
}
