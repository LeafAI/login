// Package filelock is a small portable cross-process lock (O_EXCL lock file with stale takeover).
package filelock

import (
	"errors"
	"os"
	"time"
)

// Lock takes the lock at path and returns the unlock function.
func Lock(path string) (func(), error) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if st, serr := os.Stat(path); serr == nil && time.Since(st.ModTime()) > 15*time.Second {
			os.Remove(path) // stale lock from a crashed process
			continue
		}
		if time.Now().After(deadline) {
			return nil, errors.New("filelock: timed out waiting for " + path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
