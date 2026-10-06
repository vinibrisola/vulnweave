package main

import (
	"os/exec"
	"strconv"
	"syscall"
)

// cmd.exe parses its own command line; Go's default argv escaping targets
// CommandLineToArgvW and corrupts the nested quotes required by batch files.
func configureBatchCommand(c *exec.Cmd, line string) {
	c.SysProcAttr = &syscall.SysProcAttr{CmdLine: `cmd.exe /d /s /v:off /c ` + line, HideWindow: true}
}

func configureProcessCancellation(c *exec.Cmd) {
	c.Cancel = func() error {
		if c.Process == nil {
			return nil
		}
		_ = exec.Command("taskkill.exe", "/T", "/F", "/PID", strconv.Itoa(c.Process.Pid)).Run()
		return c.Process.Kill()
	}
}
