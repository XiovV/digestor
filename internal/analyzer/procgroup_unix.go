//go:build unix

package analyzer

import (
	"os/exec"
	"syscall"
)

// killProcessGroup runs cmd in its own process group and makes cancelling
// it kill the whole group, so processes started by claude don't outlive it.
func killProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
