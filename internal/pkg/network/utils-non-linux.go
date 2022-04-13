//go:build !linux
// +build !linux

package network

//SetSocketMark ...
func (utils sockUtils) SetSocketMark(fd, mark int) error {
	_, _ = fd, mark
	return nil
}
