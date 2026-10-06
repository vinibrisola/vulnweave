package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseJavaHomeRequiresRealLauncher(t *testing.T) {
	home := t.TempDir()
	name := "java"
	if runtime.GOOS == "windows" {
		name = "java.exe"
	}
	bin := filepath.Join(home, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, name), []byte("stub"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := parseJavaHome("Property settings:\n    java.home = " + home + "\n")
	if got != home {
		t.Fatalf("expected %q, got %q", home, got)
	}
}

func TestNormalizedJavaHomeIgnoresInvalidInheritedHome(t *testing.T) {
	java, err := exec.LookPath("java")
	if err != nil {
		t.Skip("java not available")
	}
	oldHome, hadHome := os.LookupEnv("JAVA_HOME")
	oldOverride, hadOverride := os.LookupEnv(commandOverrideKey("java"))
	t.Cleanup(func() {
		if hadHome {
			_ = os.Setenv("JAVA_HOME", oldHome)
		} else {
			_ = os.Unsetenv("JAVA_HOME")
		}
		if hadOverride {
			_ = os.Setenv(commandOverrideKey("java"), oldOverride)
		} else {
			_ = os.Unsetenv(commandOverrideKey("java"))
		}
	})
	_ = os.Setenv("JAVA_HOME", filepath.Join(t.TempDir(), "not-a-jdk"))
	_ = os.Setenv(commandOverrideKey("java"), java)
	home := normalizedJavaHome()
	if home == "" {
		t.Fatal("expected a probed java.home")
	}
	if javaExecutableForHome(home) == "" {
		t.Fatalf("normalized JAVA_HOME is not executable: %s", home)
	}
}
