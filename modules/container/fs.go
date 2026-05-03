package container

import (
	"io/fs"
	"os"
)

// FS is the read-only filesystem surface the container checks depend on.
// Production uses osFS (real filesystem); tests inject a fstest.MapFS-like
// implementation to exercise edge cases without touching the host.
type FS interface {
	ReadFile(name string) ([]byte, error)
	Stat(name string) (fs.FileInfo, error)
	Lstat(name string) (fs.FileInfo, error)
}

type osFS struct{}

func (osFS) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }
func (osFS) Stat(name string) (fs.FileInfo, error) {
	return os.Stat(name)
}
func (osFS) Lstat(name string) (fs.FileInfo, error) {
	return os.Lstat(name)
}

// DefaultFS is the filesystem used by registered checks.
// It is a package-level variable so test code can swap it.
var DefaultFS FS = osFS{}
