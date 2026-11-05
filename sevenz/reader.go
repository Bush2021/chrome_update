// Package sevenz reads the 7z archives that Chrome's installer and
// Chrome++ releases are made of. It supports the Copy, LZMA, LZMA2, BCJ,
// BCJ2 and ARM64 coders, and reads files in archive order, so a solid
// folder is decoded once.
package sevenz

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"strings"
)

var (
	ErrFormat      = errors.New("sevenz: not a valid 7z archive")
	ErrUnsupported = errors.New("sevenz: unsupported 7z feature")
	ErrChecksum    = errors.New("sevenz: checksum mismatch")
)

const (
	signatureSize = 32
	// maxHeader bounds the header, encoded or not, held in memory.
	maxHeader = 16 << 20
)

var magic = []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}

type File struct {
	// Name uses forward slashes.
	Name string
	Size int64
	Dir  bool

	crc    uint32
	hasCRC bool
	folder int // -1 without data
}

// Reader holds the archive's file list. Next and Read go through the
// files in order, as archive/tar does.
type Reader struct {
	Files []*File

	ra      io.ReaderAt
	size    int64
	streams *streams

	next   int
	cur    *File
	folder int
	out    io.Reader
	left   int64
	sum    hash.Hash32
	err    error
}

func NewReader(ra io.ReaderAt, size int64) (*Reader, error) {
	r := &Reader{ra: ra, size: size, folder: -1, sum: crc32.NewIEEE()}
	if err := r.init(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Reader) init() error {
	var sig [signatureSize]byte
	if _, err := r.ra.ReadAt(sig[:], 0); err != nil {
		return fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if !bytes.Equal(sig[:6], magic) {
		return fmt.Errorf("%w: no signature", ErrFormat)
	}
	if sig[6] != 0 {
		return fmt.Errorf("%w: format version %d.%d", ErrUnsupported, sig[6], sig[7])
	}
	if crc32.ChecksumIEEE(sig[12:]) != binary.LittleEndian.Uint32(sig[8:]) {
		return fmt.Errorf("%w: the start header", ErrChecksum)
	}
	off := binary.LittleEndian.Uint64(sig[12:])
	n := binary.LittleEndian.Uint64(sig[20:])
	if n == 0 {
		return nil
	}
	room := uint64(r.size - signatureSize)
	if r.size < signatureSize || off > room || n > room-off {
		return fmt.Errorf("%w: the header lies outside the archive", ErrFormat)
	}
	if n > maxHeader {
		return fmt.Errorf("%w: a %d-byte header", ErrUnsupported, n)
	}
	buf := make([]byte, n)
	if _, err := r.ra.ReadAt(buf, int64(signatureSize+off)); err != nil {
		return fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if crc32.ChecksumIEEE(buf) != binary.LittleEndian.Uint32(sig[28:]) {
		return fmt.Errorf("%w: the header", ErrChecksum)
	}
	// An encoded header is the streams info of one folder that holds the
	// real header. 7-Zip never nests them, but nothing forbids it.
	for range 4 {
		p := parser{b: buf}
		switch p.byte() {
		case idHeader:
			s, files := p.header()
			if p.err != nil {
				return p.err
			}
			return r.setFiles(s, files)
		case idEncodedHeader:
			s := p.streamsInfo()
			if p.err != nil {
				return p.err
			}
			if len(s.folders) == 0 {
				return fmt.Errorf("%w: an encoded header without data", ErrFormat)
			}
			var err error
			if buf, err = r.decodeHeader(s); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: unknown header type", ErrFormat)
		}
	}
	return fmt.Errorf("%w: headers nested too deep", ErrUnsupported)
}

func (r *Reader) decodeHeader(s *streams) ([]byte, error) {
	f := &s.folders[0]
	if f.size() > maxHeader {
		return nil, fmt.Errorf("%w: a %d-byte header", ErrUnsupported, f.size())
	}
	out, err := r.folderReader(s, 0)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, f.size())
	if _, err := io.ReadFull(out, buf); err != nil {
		return nil, fmt.Errorf("the header: %w", err)
	}
	if f.hasCRC && crc32.ChecksumIEEE(buf) != f.crc {
		return nil, fmt.Errorf("%w: the header", ErrChecksum)
	}
	return buf, nil
}

func (r *Reader) setFiles(s *streams, files []entry) error {
	r.streams = s
	r.Files = make([]*File, len(files))
	sub := 0
	for i, e := range files {
		f := &File{Name: strings.ReplaceAll(e.name, `\`, "/"), folder: -1}
		switch {
		case e.emptyStream:
			f.Dir = !e.isEmpty
		case sub == len(s.subs):
			return fmt.Errorf("%w: more files than streams", ErrFormat)
		default:
			ss := s.subs[sub]
			sub++
			f.Size, f.crc, f.hasCRC, f.folder = ss.size, ss.crc, ss.hasCRC, ss.folder
		}
		r.Files[i] = f
	}
	if sub != len(s.subs) {
		return fmt.Errorf("%w: more streams than files", ErrFormat)
	}
	return nil
}

// Next moves to the next file and returns it, or io.EOF after the last.
// The rest of the previous file is skipped, which in a solid folder means
// decoding it.
func (r *Reader) Next() (*File, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.next == len(r.Files) {
		r.cur = nil
		return nil, io.EOF
	}
	f := r.Files[r.next]
	r.next++
	if f.folder >= 0 {
		if f.folder == r.folder && r.left > 0 {
			if _, err := io.CopyN(io.Discard, r.out, r.left); err != nil {
				r.err = fmt.Errorf("%s: %w", r.cur.Name, eofIsFormat(err))
				return nil, r.err
			}
		}
		if f.folder != r.folder {
			out, err := r.folderReader(r.streams, f.folder)
			if err != nil {
				r.err = fmt.Errorf("%s: %w", f.Name, err)
				return nil, r.err
			}
			r.out, r.folder = out, f.folder
		}
	}
	r.cur, r.left = f, f.Size
	r.sum.Reset()
	return f, nil
}

// Read reads the current file and checks its CRC32 at the end.
func (r *Reader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if r.cur == nil || r.left == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	n, err := r.out.Read(p)
	r.left -= int64(n)
	r.sum.Write(p[:n])
	switch {
	case r.left == 0 && r.cur.hasCRC && r.sum.Sum32() != r.cur.crc:
		err = fmt.Errorf("%w: %s", ErrChecksum, r.cur.Name)
	case err == io.EOF && r.left > 0:
		err = fmt.Errorf("%s: %w", r.cur.Name, eofIsFormat(err))
	case err == io.EOF:
		err = nil
	}
	if err != nil {
		r.err = err
	}
	return n, err
}

func eofIsFormat(err error) error {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return fmt.Errorf("%w: data ends early", ErrFormat)
	}
	return err
}
