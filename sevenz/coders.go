package sevenz

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/go-compressions/xz/lzma"
)

// Method IDs of 7-Zip's Methods.txt.
const (
	methodCopy  = 0x00
	methodLZMA2 = 0x21
	methodARM64 = 0x0A
	methodLZMA  = 0x030101
	methodBCJ   = 0x03030103
	methodBCJ2  = 0x0303011B
)

func (r *Reader) folderReader(s *streams, i int) (io.Reader, error) {
	f := &s.folders[i]
	off := signatureSize + s.packPos
	for _, n := range s.packSizes[:f.pack] {
		off += n
	}
	packs := make([]io.Reader, len(f.packed))
	for j := range packs {
		n := s.packSizes[f.pack+j]
		if off > r.size || n > r.size-off {
			return nil, fmt.Errorf("%w: a pack stream lies outside the archive", ErrFormat)
		}
		packs[j] = io.NewSectionReader(r.ra, off, n)
		off += n
	}
	return f.output(f.main, packs)
}

// output builds the reader of coder c's output, which yields exactly the
// size the header gives it.
func (f *folder) output(c int, packs []io.Reader) (io.Reader, error) {
	cd := &f.coders[c]
	ins := make([]io.Reader, cd.in)
	for j := range ins {
		in := cd.first + j
		for _, b := range f.binds {
			if b.in == in {
				r, err := f.output(b.out, packs)
				if err != nil {
					return nil, err
				}
				ins[j] = r
			}
		}
		for k, p := range f.packed {
			if p == in {
				ins[j] = packs[k]
			}
		}
	}
	r, err := newCoder(cd, ins, f.sizes[c])
	if err != nil {
		return nil, err
	}
	return &exact{r: r, left: f.sizes[c]}, nil
}

func newCoder(c *coder, ins []io.Reader, size int64) (io.Reader, error) {
	want := 1
	if c.id == methodBCJ2 {
		want = 4
	}
	if len(ins) != want {
		return nil, fmt.Errorf("%w: method %#x with %d inputs", ErrFormat, c.id, len(ins))
	}
	switch c.id {
	case methodCopy:
		return ins[0], nil
	case methodLZMA:
		if len(c.props) != 5 {
			return nil, fmt.Errorf("%w: LZMA properties", ErrFormat)
		}
		// The .lzma header is the coder's properties and the size.
		var h [13]byte
		copy(h[:], c.props)
		binary.LittleEndian.PutUint64(h[5:], uint64(size))
		return lzma.NewReader(io.MultiReader(bytes.NewReader(h[:]), ins[0]))
	case methodLZMA2:
		if len(c.props) != 1 {
			return nil, fmt.Errorf("%w: LZMA2 properties", ErrFormat)
		}
		dict, err := lzma.DictCapFromProp(c.props[0])
		if err != nil {
			return nil, err
		}
		cfg := lzma.Reader2Config{}
		if uint64(dict) <= math.MaxInt {
			cfg.DictCap = int(dict)
		}
		// Reader2 reads chunk headers a few bytes at a time.
		return cfg.NewReader2(bufio.NewReaderSize(ins[0], 64<<10))
	case methodBCJ:
		if len(c.props) != 0 {
			return nil, fmt.Errorf("%w: BCJ properties", ErrFormat)
		}
		x := &x86{prevPos: ^uint32(4)}
		return newFilter(ins[0], x.convert, 0), nil
	case methodARM64:
		var start uint32
		switch len(c.props) {
		case 0:
		case 4:
			start = binary.LittleEndian.Uint32(c.props)
		default:
			return nil, fmt.Errorf("%w: ARM64 properties", ErrFormat)
		}
		if start%4 != 0 {
			return nil, fmt.Errorf("%w: ARM64 start offset", ErrFormat)
		}
		return newFilter(ins[0], arm64, start), nil
	case methodBCJ2:
		if len(c.props) != 0 {
			return nil, fmt.Errorf("%w: BCJ2 properties", ErrFormat)
		}
		return newBCJ2(ins, size), nil
	}
	return nil, fmt.Errorf("%w: method %#x", ErrUnsupported, c.id)
}

// exact ends a stream at its declared size and reports one that ends
// before it.
type exact struct {
	r    io.Reader
	left int64
}

func (e *exact) Read(p []byte) (int, error) {
	if e.left == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > e.left {
		p = p[:e.left]
	}
	n, err := e.r.Read(p)
	e.left -= int64(n)
	if err == io.EOF {
		if e.left > 0 {
			return n, fmt.Errorf("%w: a stream ends early", ErrFormat)
		}
		err = nil
	}
	return n, err
}
