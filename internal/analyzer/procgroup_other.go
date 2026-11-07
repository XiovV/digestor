//go:build !unix

package analyzer

import "os/exec"

// killProcessGroup is a no-op where process groups aren't available; only
// claude itself is killed on cancellation.
func killProcessGroup(cmd *exec.Cmd) {}
