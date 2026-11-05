package sevenz

import (
	"encoding/binary"
	"io"
)

// filter applies a branch converter to a stream. convert decodes buf,
// which starts at stream position pos, and returns how many leading bytes
// are final; the rest wait for more input, and at the end pass unchanged.
type filter struct {
	src     io.Reader
	convert func(buf []byte, pos uint32) int
	pos     uint32
	buf     []byte
	r, w    int // buf[r:w] is final
	end     int // buf[w:end] waits
	eof     bool
	err     error
}

func newFilter(src io.Reader, convert func([]byte, uint32) int, start uint32) *filter {
	return &filter{src: src, convert: convert, pos: start, buf: make([]byte, 64<<10)}
}

func (f *filter) Read(p []byte) (int, error) {
	for f.r == f.w {
		if f.err != nil {
			return 0, f.err
		}
		if f.eof {
			if f.w == f.end {
				return 0, io.EOF
			}
			f.w = f.end
			break
		}
		f.end = copy(f.buf, f.buf[f.w:f.end])
		f.r, f.w = 0, 0
		n, err := f.src.Read(f.buf[f.end:])
		f.end += n
		if err == io.EOF {
			f.eof = true
		} else if err != nil {
			f.err = err
		}
		f.w = f.convert(f.buf[:f.end], f.pos)
		f.pos += uint32(f.w)
	}
	n := copy(p, f.buf[f.r:f.w])
	f.r += n
	return n, nil
}

// x86 is liblzma's x86 BCJ decoder (simple/x86.c, 0BSD), which 7-Zip's
// BCJ matches.
type x86 struct {
	prevMask, prevPos uint32
}

func test86(b byte) bool { return b == 0 || b == 0xFF }

var maskToBit = [5]uint32{0, 1, 2, 2, 3}

func (x *x86) convert(buf []byte, now uint32) int {
	if len(buf) < 5 {
		return 0
	}
	if now-x.prevPos > 5 {
		x.prevPos = now - 5
	}
	limit := len(buf) - 5
	i := 0
	for i <= limit {
		b := buf[i]
		if b != 0xE8 && b != 0xE9 {
			i++
			continue
		}
		offset := now + uint32(i) - x.prevPos
		x.prevPos = now + uint32(i)
		if offset > 5 {
			x.prevMask = 0
		} else {
			for range offset {
				x.prevMask &= 0x77
				x.prevMask <<= 1
			}
		}
		b = buf[i+4]
		if !test86(b) || x.prevMask>>1 > 4 || x.prevMask>>1 == 3 {
			i++
			x.prevMask |= 1
			if test86(b) {
				x.prevMask |= 0x10
			}
			continue
		}
		src := binary.LittleEndian.Uint32(buf[i+1:])
		var dest uint32
		for {
			dest = src - (now + uint32(i) + 5)
			if x.prevMask == 0 {
				break
			}
			j := maskToBit[x.prevMask>>1]
			if !test86(byte(dest >> (24 - j*8))) {
				break
			}
			src = dest ^ (1<<(32-j*8) - 1)
		}
		dest &= 0x01FFFFFF
		if dest&0x01000000 != 0 {
			dest |= 0xFF000000
		}
		binary.LittleEndian.PutUint32(buf[i+1:], dest)
		i += 5
		x.prevMask = 0
	}
	return i
}

// arm64 is liblzma's ARM64 decoder (simple/arm64.c, 0BSD), the filter
// 7-Zip shares with xz: BL and ADRP targets are made relative again.
func arm64(buf []byte, now uint32) int {
	i := 0
	for ; i+4 <= len(buf); i += 4 {
		pc := now + uint32(i)
		instr := binary.LittleEndian.Uint32(buf[i:])
		switch {
		case instr>>26 == 0x25:
			instr = 0x94000000 | (instr-pc>>2)&0x03FFFFFF
		case instr&0x9F000000 == 0x90000000:
			src := instr>>29&3 | instr>>3&0x001FFFFC
			if (src+0x00020000)&0x001C0000 != 0 {
				continue
			}
			dest := src - pc>>12
			instr = instr&0x9000001F | dest&3<<29 | dest&0x0003FFFC<<3 | -(dest&0x00020000)&0x00E00000
		default:
			continue
		}
		binary.LittleEndian.PutUint32(buf[i:], instr)
	}
	return i
}
