// Package pefiletest writes small Windows images for tests: enough of a PE
// file for package pefile to read its architecture, version resource and
// imports, so that tests can stand in for chrome.exe or a Chrome++ DLL.
// The images do not run.
package pefiletest

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"os"
	"slices"
	"unicode/utf16"
)

type Image struct {
	Machine                     uint16
	FileVersion, ProductVersion [4]uint16
	Strings                     map[string]string
	Imports                     []string
}

const (
	fileAlign = 0x200
	headers   = 0x400
	rva       = 0x1000
)

func (img Image) Bytes() []byte {
	var sec bytes.Buffer
	res := resources(img.versionInfo())
	sec.Write(res)
	padTo(&sec, 4)
	importsAt := sec.Len()
	if len(img.Imports) > 0 {
		names := importsAt + 20*(len(img.Imports)+1)
		var nameBytes bytes.Buffer
		for _, dll := range img.Imports {
			d := make([]byte, 20)
			binary.LittleEndian.PutUint32(d[12:], uint32(rva+names+nameBytes.Len()))
			sec.Write(d)
			nameBytes.WriteString(dll)
			nameBytes.WriteByte(0)
		}
		sec.Write(make([]byte, 20))
		sec.Write(nameBytes.Bytes())
	}
	size := uint32(sec.Len())
	padTo(&sec, fileAlign)

	var dirs [16]pe.DataDirectory
	dirs[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE] = pe.DataDirectory{VirtualAddress: rva, Size: uint32(len(res))}
	if len(img.Imports) > 0 {
		dirs[pe.IMAGE_DIRECTORY_ENTRY_IMPORT] = pe.DataDirectory{VirtualAddress: uint32(rva + importsAt), Size: size - uint32(importsAt)}
	}
	imageSize := uint32(rva + (int(size)+0xfff)&^0xfff)

	var b bytes.Buffer
	dos := make([]byte, 0x40)
	copy(dos, "MZ")
	binary.LittleEndian.PutUint32(dos[0x3c:], 0x40)
	b.Write(dos)
	b.WriteString("PE\x00\x00")
	var opt any
	if img.Machine == pe.IMAGE_FILE_MACHINE_I386 {
		opt = &pe.OptionalHeader32{Magic: 0x10b, ImageBase: 0x400000, SectionAlignment: 0x1000, FileAlignment: fileAlign,
			MajorSubsystemVersion: 6, SizeOfImage: imageSize, SizeOfHeaders: headers, Subsystem: 2,
			NumberOfRvaAndSizes: 16, DataDirectory: dirs}
	} else {
		opt = &pe.OptionalHeader64{Magic: 0x20b, ImageBase: 0x140000000, SectionAlignment: 0x1000, FileAlignment: fileAlign,
			MajorSubsystemVersion: 6, SizeOfImage: imageSize, SizeOfHeaders: headers, Subsystem: 2,
			NumberOfRvaAndSizes: 16, DataDirectory: dirs}
	}
	binary.Write(&b, binary.LittleEndian, pe.FileHeader{
		Machine:              img.Machine,
		NumberOfSections:     1,
		SizeOfOptionalHeader: uint16(binary.Size(opt)),
		Characteristics:      pe.IMAGE_FILE_EXECUTABLE_IMAGE,
	})
	binary.Write(&b, binary.LittleEndian, opt)
	binary.Write(&b, binary.LittleEndian, pe.SectionHeader32{
		Name:             [8]uint8{'.', 'r', 's', 'r', 'c'},
		VirtualSize:      size,
		VirtualAddress:   rva,
		SizeOfRawData:    uint32(sec.Len()),
		PointerToRawData: headers,
		Characteristics:  pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ,
	})
	padTo(&b, headers)
	b.Write(sec.Bytes())
	return b.Bytes()
}

func (img Image) Write(path string) error { return os.WriteFile(path, img.Bytes(), 0o644) }

func padTo(b *bytes.Buffer, n int) { b.Write(make([]byte, (n-b.Len()%n)%n)) }

// resources lays out a resource tree holding one version resource, 16/1/1033.
func resources(version []byte) []byte {
	const dirSize, entrySize = 16, 8
	dir := func(b *bytes.Buffer, id, target uint32) {
		d := make([]byte, dirSize+entrySize)
		binary.LittleEndian.PutUint16(d[14:], 1)
		binary.LittleEndian.PutUint32(d[16:], id)
		binary.LittleEndian.PutUint32(d[20:], target)
		b.Write(d)
	}
	const level = dirSize + entrySize
	const subdir = 0x80000000
	var b bytes.Buffer
	dir(&b, 16, subdir|level)
	dir(&b, 1, subdir|2*level)
	dir(&b, 1033, 3*level)
	leaf := make([]byte, 16)
	binary.LittleEndian.PutUint32(leaf, rva+3*level+16)
	binary.LittleEndian.PutUint32(leaf[4:], uint32(len(version)))
	b.Write(leaf)
	b.Write(version)
	return b.Bytes()
}

func (img Image) versionInfo() []byte {
	fixed := make([]byte, 52)
	le := binary.LittleEndian
	le.PutUint32(fixed, 0xfeef04bd)
	le.PutUint32(fixed[4:], 0x10000)
	put := func(at int, v [4]uint16) {
		le.PutUint32(fixed[at:], uint32(v[0])<<16|uint32(v[1]))
		le.PutUint32(fixed[at+4:], uint32(v[2])<<16|uint32(v[3]))
	}
	put(8, img.FileVersion)
	put(16, img.ProductVersion)
	le.PutUint32(fixed[28:], 0x40004) // VOS_NT_WINDOWS32
	le.PutUint32(fixed[32:], 1)       // VFT_APP

	keys := make([]string, 0, len(img.Strings))
	for k := range img.Strings {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var strs [][]byte
	for _, k := range keys {
		strs = append(strs, node(k, utf16z(img.Strings[k]), true))
	}
	table := node("040904B0", nil, true, strs...)
	return node("VS_VERSION_INFO", fixed, false, node("StringFileInfo", nil, true, table))
}

func utf16z(s string) []byte {
	var b bytes.Buffer
	for _, c := range utf16.Encode([]rune(s)) {
		binary.Write(&b, binary.LittleEndian, c)
	}
	b.Write([]byte{0, 0})
	return b.Bytes()
}

// node writes one block of a version resource. Blocks start 4-aligned, so
// padding relative to the block's start is padding relative to the
// resource's.
func node(key string, value []byte, text bool, children ...[]byte) []byte {
	var b bytes.Buffer
	b.Write(make([]byte, 6))
	b.Write(utf16z(key))
	padTo(&b, 4)
	b.Write(value)
	for _, c := range children {
		padTo(&b, 4)
		b.Write(c)
	}
	out := b.Bytes()
	valueLen := len(value)
	if text {
		valueLen /= 2
	}
	binary.LittleEndian.PutUint16(out, uint16(len(out)))
	binary.LittleEndian.PutUint16(out[2:], uint16(valueLen))
	if text {
		out[4] = 1
	}
	return out
}
