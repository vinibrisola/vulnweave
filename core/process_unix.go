//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

func configureBatchCommand(c *exec.Cmd, line string) {}
func configureProcessCancellation(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error {
		if c.Process == nil {
			return nil
		}
		return syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
	}
}
