// Package pefile reads Windows executables: the architecture, the resource
// tree, the version resource and the imported DLLs. It works on any OS, over
// an io.ReaderAt, without loading the file.
package pefile

import (
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

func Arch(f *pe.File) (string, error) {
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86", nil
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x64", nil
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64", nil
	}
	return "", fmt.Errorf("unsupported machine %#04x", f.Machine)
}

// Type and Name are "#<id>" for numeric entries.
type Resource struct {
	Type, Name, Lang string
	Offset, Size     int64
}

const TypeVersion = "#16"

func fileOffset(f *pe.File, rva uint32) (int64, error) {
	for _, s := range f.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+max(s.VirtualSize, s.Size) {
			return int64(rva-s.VirtualAddress) + int64(s.Offset), nil
		}
	}
	return 0, fmt.Errorf("rva %#x is in no section", rva)
}

func dataDirectory(f *pe.File, i int) pe.DataDirectory {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if i < len(oh.DataDirectory) {
			return oh.DataDirectory[i]
		}
	case *pe.OptionalHeader64:
		if i < len(oh.DataDirectory) {
			return oh.DataDirectory[i]
		}
	}
	return pe.DataDirectory{}
}

func Resources(r io.ReaderAt, f *pe.File) ([]Resource, error) {
	dir := dataDirectory(f, pe.IMAGE_DIRECTORY_ENTRY_RESOURCE)
	if dir.Size == 0 {
		return nil, nil
	}
	base, err := fileOffset(f, dir.VirtualAddress)
	if err != nil {
		return nil, err
	}
	var readErr error
	read := func(off int64, n int) []byte {
		b := make([]byte, n)
		if _, err := r.ReadAt(b, off); err != nil && readErr == nil {
			readErr = err
		}
		return b
	}
	u16 := func(off int64) uint16 { return binary.LittleEndian.Uint16(read(off, 2)) }
	u32 := func(off int64) uint32 { return binary.LittleEndian.Uint32(read(off, 4)) }
	name := func(v uint32) string {
		if v&0x80000000 == 0 {
			return fmt.Sprintf("#%d", v)
		}
		o := base + int64(v&0x7fffffff)
		n := int(u16(o))
		raw := read(o+2, n*2)
		w := make([]uint16, n)
		for i := range w {
			w[i] = binary.LittleEndian.Uint16(raw[i*2:])
		}
		return string(utf16.Decode(w))
	}
	var out []Resource
	var walk func(off int64, path []string) error
	walk = func(off int64, path []string) error {
		if len(path) > 2 {
			return errors.New("resource tree is deeper than type, name and language")
		}
		entries := int64(u16(off+12)) + int64(u16(off+14))
		if entries > 4096 {
			return fmt.Errorf("resource directory with %d entries", entries)
		}
		for i := range entries {
			e := off + 16 + i*8
			p := append(path[:len(path):len(path)], name(u32(e)))
			data := u32(e + 4)
			if readErr != nil {
				return readErr
			}
			if data&0x80000000 != 0 {
				if err := walk(base+int64(data&0x7fffffff), p); err != nil {
					return err
				}
				continue
			}
			if len(p) != 3 {
				return errors.New("resource data outside type, name and language")
			}
			leaf := base + int64(data)
			at, err := fileOffset(f, u32(leaf))
			if err != nil {
				return err
			}
			out = append(out, Resource{Type: p[0], Name: p[1], Lang: p[2], Offset: at, Size: int64(u32(leaf + 4))})
		}
		return readErr
	}
	return out, walk(base, nil)
}

func Find(rs []Resource, typ, name string) (Resource, bool) {
	for _, r := range rs {
		if r.Type == typ && strings.EqualFold(r.Name, name) {
			return r, true
		}
	}
	return Resource{}, false
}

type Version [4]uint16

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d.%d", v[0], v[1], v[2], v[3]) }

type VersionInfo struct {
	File, Product Version
	// From the first string table only.
	Strings map[string]string
}

func ReadVersionInfo(r io.ReaderAt, f *pe.File) (*VersionInfo, error) {
	rs, err := Resources(r, f)
	if err != nil {
		return nil, err
	}
	res, ok := Find(rs, TypeVersion, "#1")
	if !ok {
		return nil, errors.New("no version resource")
	}
	if res.Size > 1<<20 {
		return nil, fmt.Errorf("version resource of %d bytes", res.Size)
	}
	b := make([]byte, res.Size)
	if _, err := r.ReadAt(b, res.Offset); err != nil {
		return nil, err
	}
	return parseVersionInfo(b)
}

// node is one VS_VERSIONINFO-style block: a key, its value and children.
type node struct {
	key      string
	value    []byte
	text     bool
	children []node
}

func align4(n int) int { return (n + 3) &^ 3 }

// parseNode reads the block at the start of b (offsets aligned relative to
// the start of the resource, which b's start is).
func parseNode(b []byte, start int) (node, int, error) {
	if len(b)-start < 6 {
		return node{}, 0, errors.New("truncated version block")
	}
	length := int(binary.LittleEndian.Uint16(b[start:]))
	valueLen := int(binary.LittleEndian.Uint16(b[start+2:]))
	isText := binary.LittleEndian.Uint16(b[start+4:]) == 1
	end := start + length
	if length < 6 || end > len(b) {
		return node{}, 0, errors.New("bad version block length")
	}
	i := start + 6
	var key []uint16
	for ; i+1 < end; i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			i += 2
			break
		}
		key = append(key, c)
	}
	n := node{key: string(utf16.Decode(key)), text: isText}
	i = align4(i)
	if valueLen > 0 {
		size := valueLen
		if isText {
			size = valueLen * 2
		}
		if i+size > end {
			size = end - i
		}
		if size > 0 {
			n.value = b[i : i+size]
		}
		i = align4(i + size)
	}
	for i < end {
		child, next, err := parseNode(b, i)
		if err != nil {
			return node{}, 0, err
		}
		n.children = append(n.children, child)
		i = align4(next)
	}
	return n, end, nil
}

func utf16String(b []byte) string {
	w := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		w = append(w, c)
	}
	return string(utf16.Decode(w))
}

func parseVersionInfo(b []byte) (*VersionInfo, error) {
	root, _, err := parseNode(b, 0)
	if err != nil {
		return nil, err
	}
	if root.key != "VS_VERSION_INFO" {
		return nil, fmt.Errorf("version resource starts with %q", root.key)
	}
	vi := &VersionInfo{Strings: map[string]string{}}
	if len(root.value) >= 52 && binary.LittleEndian.Uint32(root.value) == 0xFEEF04BD {
		v := root.value
		ms, ls := binary.LittleEndian.Uint32(v[8:]), binary.LittleEndian.Uint32(v[12:])
		vi.File = Version{uint16(ms >> 16), uint16(ms), uint16(ls >> 16), uint16(ls)}
		ms, ls = binary.LittleEndian.Uint32(v[16:]), binary.LittleEndian.Uint32(v[20:])
		vi.Product = Version{uint16(ms >> 16), uint16(ms), uint16(ls >> 16), uint16(ls)}
	}
	for _, c := range root.children {
		if c.key != "StringFileInfo" || len(c.children) == 0 {
			continue
		}
		for _, s := range c.children[0].children {
			vi.Strings[s.key] = utf16String(s.value)
		}
	}
	return vi, nil
}

// debug/pe's ImportedLibraries is unimplemented and its ImportedSymbols
// skips imports by ordinal, which is how setdll adds Chrome++ to
// chrome.exe, so the descriptors are read here.
func ImportedDLLs(r io.ReaderAt, f *pe.File) ([]string, error) {
	dir := dataDirectory(f, pe.IMAGE_DIRECTORY_ENTRY_IMPORT)
	if dir.Size == 0 {
		return nil, nil
	}
	off, err := fileOffset(f, dir.VirtualAddress)
	if err != nil {
		return nil, err
	}
	var dlls []string
	desc := make([]byte, 20)
	for i := 0; i < 4096; i++ {
		if _, err := r.ReadAt(desc, off+int64(i)*20); err != nil {
			return nil, err
		}
		nameRVA := binary.LittleEndian.Uint32(desc[12:])
		if nameRVA == 0 {
			return dlls, nil
		}
		at, err := fileOffset(f, nameRVA)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 256)
		n, err := r.ReadAt(buf, at)
		if n == 0 && err != nil {
			return nil, err
		}
		name := buf[:n]
		if end := strings.IndexByte(string(name), 0); end >= 0 {
			name = name[:end]
		}
		dlls = append(dlls, string(name))
	}
	return nil, errors.New("import directory without an end")
}
