package sevenz

import (
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"unicode/utf16"
)

// Property IDs of 7zFormat.txt.
const (
	idEnd                   = 0x00
	idHeader                = 0x01
	idArchiveProperties     = 0x02
	idAdditionalStreamsInfo = 0x03
	idMainStreamsInfo       = 0x04
	idFilesInfo             = 0x05
	idPackInfo              = 0x06
	idUnpackInfo            = 0x07
	idSubStreamsInfo        = 0x08
	idSize                  = 0x09
	idCRC                   = 0x0A
	idFolder                = 0x0B
	idCodersUnpackSize      = 0x0C
	idNumUnpackStream       = 0x0D
	idEmptyStream           = 0x0E
	idEmptyFile             = 0x0F
	idAnti                  = 0x10
	idName                  = 0x11
	idEncodedHeader         = 0x17
)

type coder struct {
	id    uint64
	in    int // packed-side streams; each coder has one output
	first int // index of its first input among the folder's inputs
	props []byte
}

type bindPair struct{ in, out int }

type folder struct {
	coders []coder
	binds  []bindPair
	packed []int // the inputs fed by pack streams, in pack stream order
	sizes  []int64
	main   int // the coder whose output is the folder's
	crc    uint32
	hasCRC bool
	pack   int // index of the folder's first pack stream
}

func (f *folder) size() int64 { return f.sizes[f.main] }

type substream struct {
	folder int
	size   int64
	crc    uint32
	hasCRC bool
}

type streams struct {
	packPos   int64
	packSizes []int64
	folders   []folder
	subs      []substream
}

type entry struct {
	name                 string
	emptyStream, isEmpty bool
}

// parser reads a header. Its first error sticks, and reads after it
// return zero values, so callers check err once per structure.
type parser struct {
	b   []byte
	err error
}

func (p *parser) fail(format string, a ...any) {
	if p.err == nil {
		p.err = fmt.Errorf("%w: %s", ErrFormat, fmt.Sprintf(format, a...))
	}
	p.b = nil
}

func (p *parser) unsupported(format string, a ...any) {
	if p.err == nil {
		p.err = fmt.Errorf("%w: %s", ErrUnsupported, fmt.Sprintf(format, a...))
	}
	p.b = nil
}

func (p *parser) byte() byte {
	if len(p.b) == 0 {
		p.fail("the header ends early")
		return 0
	}
	c := p.b[0]
	p.b = p.b[1:]
	return c
}

func (p *parser) take(n uint64) []byte {
	if n > uint64(len(p.b)) {
		p.fail("the header ends early")
		return nil
	}
	s := p.b[:n]
	p.b = p.b[n:]
	return s
}

func (p *parser) uint32() uint32 {
	b := p.take(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

// number reads 7z's variable-length integer: the leading one bits of the
// first byte count the little-endian bytes that follow, and the rest of
// the first byte holds the highest bits.
func (p *parser) number() uint64 {
	first := p.byte()
	mask := byte(0x80)
	var v uint64
	for i := range 8 {
		if first&mask == 0 {
			return v | uint64(first&(mask-1))<<(8*i)
		}
		v |= uint64(p.byte()) << (8 * i)
		mask >>= 1
	}
	return v
}

func (p *parser) size() int64 {
	n := p.number()
	if n > math.MaxInt64 {
		p.fail("a size is out of range")
		return 0
	}
	return int64(n)
}

// count reads a number of items that need at least 1/per bytes each, so
// a damaged count cannot make a large allocation.
func (p *parser) count(per int) int {
	n := p.number()
	if n > uint64(len(p.b))*uint64(per) {
		p.fail("a count exceeds the header")
		return 0
	}
	return int(n)
}

func (p *parser) bits(n int) []bool {
	b := p.take(uint64((n + 7) / 8))
	v := make([]bool, n)
	if b != nil {
		for i := range v {
			v[i] = b[i/8]&(0x80>>(i%8)) != 0
		}
	}
	return v
}

func (p *parser) defined(n int) []bool {
	if p.byte() == 0 {
		return p.bits(n)
	}
	v := make([]bool, n)
	for i := range v {
		v[i] = true
	}
	return v
}

func (p *parser) digests(n int) ([]uint32, []bool) {
	def := p.defined(n)
	crcs := make([]uint32, n)
	for i, d := range def {
		if d {
			crcs[i] = p.uint32()
		}
	}
	return crcs, def
}

func (p *parser) streamsInfo() *streams {
	s := &streams{}
	id := p.byte()
	if id == idPackInfo {
		p.packInfo(s)
		id = p.byte()
	}
	if id == idUnpackInfo {
		p.unpackInfo(s)
		id = p.byte()
	}
	if id == idSubStreamsInfo {
		p.subStreamsInfo(s)
		id = p.byte()
	} else {
		for i := range s.folders {
			f := &s.folders[i]
			s.subs = append(s.subs, substream{i, f.size(), f.crc, f.hasCRC})
		}
	}
	if id != idEnd {
		p.fail("unexpected property %#x in streams info", id)
	}
	if p.err == nil {
		p.checkPacks(s)
	}
	return s
}

func (p *parser) packInfo(s *streams) {
	s.packPos = p.size()
	n := p.count(1)
	s.packSizes = make([]int64, n)
	sized := false
	for p.err == nil {
		switch id := p.byte(); id {
		case idEnd:
			if !sized && n > 0 {
				p.fail("pack info lacks sizes")
			}
			return
		case idSize:
			for i := range s.packSizes {
				s.packSizes[i] = p.size()
			}
			sized = true
		case idCRC:
			p.digests(n)
		default:
			p.fail("unexpected property %#x in pack info", id)
		}
	}
}

func (p *parser) unpackInfo(s *streams) {
	if p.byte() != idFolder {
		p.fail("unpack info lacks folders")
		return
	}
	n := p.count(1)
	if p.byte() != 0 {
		p.unsupported("external folders")
		return
	}
	s.folders = make([]folder, n)
	for i := range s.folders {
		p.folder(&s.folders[i])
	}
	if p.byte() != idCodersUnpackSize {
		p.fail("unpack info lacks sizes")
		return
	}
	for i := range s.folders {
		f := &s.folders[i]
		f.sizes = make([]int64, len(f.coders))
		for j := range f.sizes {
			f.sizes[j] = p.size()
		}
	}
	id := p.byte()
	if id == idCRC {
		crcs, def := p.digests(n)
		for i := range s.folders {
			s.folders[i].crc, s.folders[i].hasCRC = crcs[i], def[i]
		}
		id = p.byte()
	}
	if id != idEnd {
		p.fail("unexpected property %#x in unpack info", id)
	}
}

const maxCoders = 4

func (p *parser) folder(f *folder) {
	n := p.count(1)
	if n == 0 || n > maxCoders {
		p.unsupported("a folder of %d coders", n)
		return
	}
	f.coders = make([]coder, n)
	inputs := 0
	for i := range f.coders {
		c := &f.coders[i]
		flags := p.byte()
		if flags&0xC0 != 0 {
			p.unsupported("coder flags %#x", flags)
			return
		}
		idLen := uint64(flags & 0x0F)
		if idLen > 8 {
			p.unsupported("a %d-byte method ID", idLen)
			return
		}
		for _, b := range p.take(idLen) {
			c.id = c.id<<8 | uint64(b)
		}
		c.in = 1
		if flags&0x10 != 0 {
			in, out := p.number(), p.number()
			if in == 0 || in > 4 || out != 1 {
				p.unsupported("a coder of %d inputs and %d outputs", in, out)
				return
			}
			c.in = int(in)
		}
		if flags&0x20 != 0 {
			c.props = p.take(p.number())
		}
		c.first = inputs
		inputs += c.in
	}
	bound := make([]bool, inputs)
	fed := make([]bool, n)
	f.binds = make([]bindPair, n-1)
	for i := range f.binds {
		in, out := p.number(), p.number()
		if in >= uint64(inputs) || out >= uint64(n) || bound[in] || fed[out] {
			p.fail("a bad bind pair")
			return
		}
		bound[in], fed[out] = true, true
		f.binds[i] = bindPair{int(in), int(out)}
	}
	packed := inputs - len(f.binds)
	f.packed = make([]int, packed)
	if packed == 1 {
		for i, b := range bound {
			if !b {
				f.packed[0] = i
			}
		}
	} else {
		for i := range f.packed {
			in := p.number()
			if in >= uint64(inputs) || bound[in] {
				p.fail("a bad packed stream")
				return
			}
			bound[in] = true
			f.packed[i] = int(in)
		}
	}
	for i, b := range fed {
		if !b {
			f.main = i
		}
	}
	// Every coder but the main one feeds another, and n-1 bind pairs feed
	// distinct inputs from distinct outputs; a coder that feeds itself,
	// directly or not, would leave some coder unreachable from the main one.
	seen := make([]bool, n)
	var walk func(c int) bool
	walk = func(c int) bool {
		if seen[c] {
			return false
		}
		seen[c] = true
		for _, b := range f.binds {
			if b.in >= f.coders[c].first && b.in < f.coders[c].first+f.coders[c].in && !walk(b.out) {
				return false
			}
		}
		return true
	}
	if !walk(f.main) || slices.Contains(seen, false) {
		p.fail("coders do not form a tree")
	}
}

func (p *parser) subStreamsInfo(s *streams) {
	nums := make([]int, len(s.folders))
	for i := range nums {
		nums[i] = 1
	}
	id := p.byte()
	if id == idNumUnpackStream {
		for i := range nums {
			nums[i] = p.count(1) // all but one need a size
		}
		id = p.byte()
	}
	for i := range s.folders {
		f := &s.folders[i]
		if nums[i] == 0 {
			continue
		}
		var sum int64
		for range nums[i] - 1 {
			if id != idSize {
				p.fail("substream sizes are missing")
				return
			}
			n := p.size()
			sum += n
			if n < 0 || sum > f.size() {
				p.fail("substreams exceed their folder")
				return
			}
			s.subs = append(s.subs, substream{folder: i, size: n})
		}
		s.subs = append(s.subs, substream{folder: i, size: f.size() - sum})
		if nums[i] == 1 && f.hasCRC {
			last := &s.subs[len(s.subs)-1]
			last.crc, last.hasCRC = f.crc, true
		}
	}
	if id == idSize {
		id = p.byte()
	}
	for p.err == nil && id != idEnd {
		if id != idCRC {
			p.fail("unexpected property %#x in substreams info", id)
			return
		}
		var unknown []*substream
		for i := range s.subs {
			if !s.subs[i].hasCRC {
				unknown = append(unknown, &s.subs[i])
			}
		}
		crcs, def := p.digests(len(unknown))
		for i, u := range unknown {
			u.crc, u.hasCRC = crcs[i], def[i]
		}
		id = p.byte()
	}
}

// checkPacks assigns each folder its pack streams and checks that every
// pack stream has exactly one folder.
func (p *parser) checkPacks(s *streams) {
	next := 0
	for i := range s.folders {
		f := &s.folders[i]
		f.pack = next
		next += len(f.packed)
	}
	if next != len(s.packSizes) {
		p.fail("folders use %d pack streams of %d", next, len(s.packSizes))
		return
	}
	end := s.packPos
	for _, n := range s.packSizes {
		if n < 0 || end > math.MaxInt64-n {
			p.fail("pack streams are out of range")
			return
		}
		end += n
	}
}

func (p *parser) header() (*streams, []entry) {
	s := &streams{}
	var files []entry
	id := p.byte()
	if id == idArchiveProperties {
		for p.err == nil && p.byte() != 0 {
			p.take(p.number())
		}
		id = p.byte()
	}
	if id == idAdditionalStreamsInfo {
		p.unsupported("additional streams")
		return nil, nil
	}
	if id == idMainStreamsInfo {
		s = p.streamsInfo()
		id = p.byte()
	}
	if id == idFilesInfo {
		files = p.filesInfo()
		id = p.byte()
	}
	if id != idEnd {
		p.fail("unexpected property %#x in the header", id)
	}
	return s, files
}

func (p *parser) filesInfo() []entry {
	n := p.count(1)
	files := make([]entry, n)
	var empty []int
	named := false
	for p.err == nil {
		t := p.byte()
		if t == idEnd {
			break
		}
		q := parser{b: p.take(p.number())}
		switch t {
		case idEmptyStream:
			empty = empty[:0]
			for i, e := range q.bits(n) {
				files[i].emptyStream = e
				if e {
					empty = append(empty, i)
				}
			}
		case idEmptyFile:
			for i, e := range q.bits(len(empty)) {
				files[empty[i]].isEmpty = e
			}
		case idAnti:
			if slices.Contains(q.bits(len(empty)), true) {
				q.unsupported("anti items")
			}
		case idName:
			if q.byte() != 0 {
				q.unsupported("external names")
			}
			for i := range files {
				files[i].name = q.name()
			}
			named = true
		}
		if q.err != nil && p.err == nil {
			p.err = q.err
		}
	}
	if p.err == nil && n > 0 && !named {
		p.fail("files have no names")
	}
	return files
}

func (p *parser) name() string {
	var u []uint16
	for p.err == nil {
		b := p.take(2)
		if b == nil {
			break
		}
		c := binary.LittleEndian.Uint16(b)
		if c == 0 {
			return string(utf16.Decode(u))
		}
		u = append(u, c)
	}
	return ""
}
