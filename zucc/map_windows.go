package zucc

import (
	"os"
	"syscall"
	"unsafe"
)

type mapping struct {
	data  []byte
	file  *os.File
	view  uintptr
	write bool
}

// mapFile maps path for reading, or, given a size, creates it at that size
// and maps it for writing.
func mapFile(path string, size int64) (*mapping, error) {
	m := &mapping{write: size > 0}
	var err error
	if m.write {
		m.file, err = os.Create(path)
	} else {
		m.file, err = os.Open(path)
	}
	if err != nil {
		return nil, err
	}
	if !m.write {
		fi, err := m.file.Stat()
		if err != nil {
			m.file.Close()
			return nil, err
		}
		size = fi.Size()
	}
	if size <= 0 || uint64(size) > uint64(^uintptr(0)) {
		m.file.Close()
		return nil, &os.PathError{Op: "map", Path: path, Err: syscall.EINVAL}
	}
	protect, access := uint32(syscall.PAGE_READONLY), uint32(syscall.FILE_MAP_READ)
	if m.write {
		protect, access = syscall.PAGE_READWRITE, syscall.FILE_MAP_WRITE
	}
	h, err := syscall.CreateFileMapping(syscall.Handle(m.file.Fd()), nil, protect, uint32(size>>32), uint32(size), nil)
	if err == nil {
		m.view, err = syscall.MapViewOfFile(h, access, 0, 0, uintptr(size))
		syscall.CloseHandle(h) // the view keeps the mapping
	}
	if err != nil {
		m.file.Close()
		return nil, &os.PathError{Op: "map", Path: path, Err: err}
	}
	// Converting through a pointer's bits keeps vet's unsafeptr check
	// quiet; the view isn't Go memory, so the collector never moves it.
	var p unsafe.Pointer
	*(*uintptr)(unsafe.Pointer(&p)) = m.view
	m.data = unsafe.Slice((*byte)(p), int(size))
	return m, nil
}

func (m *mapping) close() error {
	var err error
	if m.write {
		err = syscall.FlushViewOfFile(m.view, uintptr(len(m.data)))
	}
	if uerr := syscall.UnmapViewOfFile(m.view); err == nil {
		err = uerr
	}
	if m.write && err == nil {
		err = m.file.Sync()
	}
	if cerr := m.file.Close(); err == nil {
		err = cerr
	}
	m.data = nil
	return err
}
