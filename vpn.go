// +build !android

package main

import "syscall"

// HUGE THANKS TO https://github.com/cbeuw/Cloak/blob/master/cmd/ck-client/protector.go
func protector(string, string, syscall.RawConn) error {
	return nil
}
