package sevenz

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// bcj2 is 7-Zip's BCJ2 decoder (C/Bcj2.c, public domain). The main stream
// holds x86 code with the targets of CALL (E8), JMP (E9) and Jcc (0F 8x)
// taken out. After each such opcode a range-coded bit says whether a
// target follows; if so it comes, big-endian and absolute, from the call
// stream for E8 and the jump stream otherwise.
type bcj2 struct {
	main, call, jump, rc *bufio.Reader
	left                 int64
	ip                   uint32 // output position
	prev                 byte
	rng, code            uint32
	probs                [2 + 256]uint16 // Jcc, E9, then E8 by the byte before it
	pend                 [4]byte         // a target not yet handed out
	pendAt, pendN        int
	started, done        bool
	err                  error
}

func newBCJ2(ins []io.Reader, size int64) *bcj2 {
	d := &bcj2{
		main: bufio.NewReaderSize(ins[0], 64<<10),
		call: bufio.NewReaderSize(ins[1], 16<<10),
		jump: bufio.NewReaderSize(ins[2], 16<<10),
		rc:   bufio.NewReaderSize(ins[3], 16<<10),
		left: size,
	}
	for i := range d.probs {
		d.probs[i] = 1 << 10
	}
	return d
}

func (d *bcj2) init() error {
	var b [5]byte
	if _, err := io.ReadFull(d.rc, b[:]); err != nil {
		return eofIsFormat(err)
	}
	d.code = binary.BigEndian.Uint32(b[1:])
	if b[0] != 0 || d.code == 0xFFFFFFFF {
		return fmt.Errorf("%w: BCJ2 range coder", ErrFormat)
	}
	d.rng = 0xFFFFFFFF
	return nil
}

func (d *bcj2) bit(p *uint16) (bool, error) {
	if d.rng < 1<<24 {
		c, err := d.rc.ReadByte()
		if err != nil {
			return false, eofIsFormat(err)
		}
		d.rng <<= 8
		d.code = d.code<<8 | uint32(c)
	}
	bound := (d.rng >> 11) * uint32(*p)
	if d.code < bound {
		d.rng = bound
		*p += (1<<11 - *p) >> 5
		return false, nil
	}
	d.rng -= bound
	d.code -= bound
	*p -= *p >> 5
	return true, nil
}

func (d *bcj2) Read(p []byte) (int, error) {
	if d.err == nil && !d.started {
		d.started = true
		d.err = d.init()
	}
	n := 0
	for n < len(p) && d.err == nil {
		if d.pendN > 0 {
			c := copy(p[n:], d.pend[d.pendAt:d.pendAt+d.pendN])
			n += c
			d.pendAt += c
			d.pendN -= c
			continue
		}
		if d.left == 0 {
			break
		}
		d.err = d.step(p, &n)
	}
	if n > 0 {
		return n, nil
	}
	if d.err != nil {
		return 0, d.err
	}
	if !d.done {
		d.done = true
		for _, s := range []*bufio.Reader{d.main, d.call, d.jump} {
			if _, err := s.Peek(1); err != io.EOF {
				d.err = fmt.Errorf("%w: BCJ2 input left over", ErrFormat)
				return 0, d.err
			}
		}
	}
	return 0, io.EOF
}

// step copies main stream bytes to p[*n:] up to and including the next
// opcode, then decodes what follows the opcode.
func (d *bcj2) step(p []byte, n *int) error {
	if d.main.Buffered() == 0 {
		if _, err := d.main.Peek(1); err != nil {
			return eofIsFormat(err)
		}
	}
	buf, _ := d.main.Peek(d.main.Buffered())
	buf = buf[:min(int64(len(buf)), int64(len(p)-*n), d.left)]
	prev := d.prev
	i := 0
	op := -1
	for i < len(buf) {
		b := buf[i]
		i++
		if b&0xFE == 0xE8 || prev == 0x0F && b&0xF0 == 0x80 {
			op = int(b)
			break
		}
		prev = b
	}
	copy(p[*n:], buf[:i])
	d.main.Discard(i)
	*n += i
	d.left -= int64(i)
	d.ip += uint32(i)
	if op < 0 {
		d.prev = prev
		return nil
	}
	// Nothing follows an opcode that ends the output. 7-Zip's decoders
	// before 23.00 read no bit for it either, so no encoder relies on one.
	if d.left == 0 {
		d.prev = byte(op)
		return nil
	}
	prob := &d.probs[0]
	switch op {
	case 0xE8:
		prob = &d.probs[2+int(prev)]
	case 0xE9:
		prob = &d.probs[1]
	}
	conv, err := d.bit(prob)
	if err != nil {
		return err
	}
	if !conv {
		d.prev = byte(op)
		return nil
	}
	src := d.jump
	if op == 0xE8 {
		src = d.call
	}
	var t [4]byte
	if _, err := io.ReadFull(src, t[:]); err != nil {
		return eofIsFormat(err)
	}
	dest := binary.BigEndian.Uint32(t[:]) - (d.ip + 4)
	d.ip += 4
	binary.LittleEndian.PutUint32(d.pend[:], dest)
	d.pendAt, d.pendN = 0, int(min(4, d.left))
	d.left -= int64(d.pendN)
	d.prev = byte(dest >> 24)
	return nil
}
