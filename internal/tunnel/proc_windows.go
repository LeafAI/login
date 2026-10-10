//go:build windows

package tunnel

import "os/exec"

func inOwnProcessGroup(*exec.Cmd) {}

// killTree kills the process; Windows has no process groups to signal.
func killTree(cmd *exec.Cmd) {
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
}
