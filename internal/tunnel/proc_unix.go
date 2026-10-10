//go:build !windows

package tunnel

import (
	"os/exec"
	"syscall"
)

// inOwnProcessGroup makes the command the leader of a new process group, so the whole tree it starts can be
// signalled at once and is not hit by (or left behind after) signals meant for the parent.
func inOwnProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killTree kills the process group of cmd (negative pid), falling back to the process itself.
func killTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		cmd.Process.Kill()
	}
}
