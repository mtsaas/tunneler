//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

func configureShareProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000200 | 0x00000008}
}
