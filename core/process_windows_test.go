package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Run on a real Windows host to verify CreateProcess -> cmd.exe -> wrapper.
func TestWindowsWrapperWithSpacePath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "project with spaces")
	os.MkdirAll(dir, 0700)
	wrapper := filepath.Join(dir, "mvnw.cmd")
	os.WriteFile(wrapper, []byte("@echo off\r\necho WRAPPER_OK %~1\r\n"), 0600)
	r := runCmd(dir, "wrapper-test", wrapper, []string{"dependency:tree"})
	if !r.Success || !strings.Contains(r.Output, "WRAPPER_OK dependency:tree") {
		t.Fatalf("%+v", r)
	}
}
