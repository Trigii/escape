package kubernetes

import (
	"io/fs"
	"os"
)

// FS mirrors the container module's FS abstraction so K8s checks
// are testable without a real /var/run/secrets/... tree.
type FS interface {
	ReadFile(name string) ([]byte, error)
	Stat(name string) (fs.FileInfo, error)
}

type osFS struct{}

func (osFS) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }
func (osFS) Stat(name string) (fs.FileInfo, error) {
	return os.Stat(name)
}

// DefaultFS is swappable for tests.
var DefaultFS FS = osFS{}

// Env is an indirection over os.Getenv for testability.
var Env = os.Getenv

// SATokenPath / SACAPath / SANamespacePath follow the well-known
// in-pod ServiceAccount conventions.
const (
	SATokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	SACAPath        = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	SANamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)
