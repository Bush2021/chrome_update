//go:build !windows

package zucc

import "os"

// mapping reads and writes files whole outside Windows.
type mapping struct {
	data  []byte
	path  string
	write bool
}

func mapFile(path string, size int64) (*mapping, error) {
	if size > 0 {
		return &mapping{data: make([]byte, size), path: path, write: true}, os.WriteFile(path, nil, 0o644)
	}
	b, err := os.ReadFile(path)
	return &mapping{data: b, path: path}, err
}

func (m *mapping) close() error {
	if m.write {
		return os.WriteFile(m.path, m.data, 0o644)
	}
	return nil
}
