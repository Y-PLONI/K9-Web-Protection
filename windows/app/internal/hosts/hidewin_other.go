//go:build !windows

package hosts

import "os/exec"

func hideWindow(*exec.Cmd) {}
