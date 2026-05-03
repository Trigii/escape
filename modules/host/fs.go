package host

import (
	"io/fs"
	"os"
)

type FS interface {
	ReadFile(name string) ([]byte, error)
	Stat(name string) (fs.FileInfo, error)
	ReadDir(name string) ([]fs.DirEntry, error)
}

type osFS struct{}

func (osFS) ReadFile(name string) ([]byte, error)         { return os.ReadFile(name) }
func (osFS) Stat(name string) (fs.FileInfo, error)        { return os.Stat(name) }
func (osFS) ReadDir(name string) ([]fs.DirEntry, error)   { return os.ReadDir(name) }

var DefaultFS FS = osFS{}
