// Package tests provides shared helpers for unit tests.
//
// We intentionally don't use testify or other helper libraries — the
// stdlib testing package is enough and keeps the audit surface tiny.
package tests

import (
	"errors"
	"io/fs"
	"strings"
	"time"
)

// MockFS is a tiny in-memory FS suitable for the container/k8s/host
// FS interfaces. It only implements ReadFile/Stat/Lstat/ReadDir.
type MockFS struct {
	Files map[string]string // absolute path -> content
	Dirs  map[string][]string
}

func New() *MockFS {
	return &MockFS{
		Files: map[string]string{},
		Dirs:  map[string][]string{},
	}
}

func (m *MockFS) ReadFile(name string) ([]byte, error) {
	c, ok := m.Files[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return []byte(c), nil
}

func (m *MockFS) Stat(name string) (fs.FileInfo, error) {
	if _, ok := m.Files[name]; ok {
		return &mockInfo{name: name, isDir: false}, nil
	}
	if _, ok := m.Dirs[name]; ok {
		return &mockInfo{name: name, isDir: true}, nil
	}
	return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
}

func (m *MockFS) Lstat(name string) (fs.FileInfo, error) { return m.Stat(name) }

func (m *MockFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, ok := m.Dirs[name]
	if !ok {
		return nil, errors.New("no such directory: " + name)
	}
	out := make([]fs.DirEntry, 0, len(entries))
	for _, e := range entries {
		isDir := strings.HasSuffix(e, "/")
		name := strings.TrimSuffix(e, "/")
		out = append(out, &mockDirEntry{name: name, isDir: isDir})
	}
	return out, nil
}

type mockInfo struct {
	name  string
	isDir bool
}

func (m *mockInfo) Name() string       { return m.name }
func (m *mockInfo) Size() int64        { return 0 }
func (m *mockInfo) Mode() fs.FileMode  { return 0o644 }
func (m *mockInfo) ModTime() time.Time { return time.Time{} }
func (m *mockInfo) IsDir() bool        { return m.isDir }
func (m *mockInfo) Sys() any           { return nil }

type mockDirEntry struct {
	name  string
	isDir bool
}

func (m *mockDirEntry) Name() string               { return m.name }
func (m *mockDirEntry) IsDir() bool                { return m.isDir }
func (m *mockDirEntry) Type() fs.FileMode          { return 0 }
func (m *mockDirEntry) Info() (fs.FileInfo, error) { return &mockInfo{name: m.name, isDir: m.isDir}, nil }
