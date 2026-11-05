package unpacktest

import (
	"encoding/binary"
	"hash/crc32"
)

// XZ makes a one-block xz stream of uncompressed LZMA2 chunks, for test
// servers that hand out xz packages.
func XZ(data []byte) []byte {
	le := binary.LittleEndian
	var b []byte
	b = append(b, 0xFD, '7', 'z', 'X', 'Z', 0, 0, 1) // CRC32 check
	b = le.AppendUint32(b, crc32.ChecksumIEEE(b[6:8]))
	start := len(b)
	header := []byte{2, 0, 0x21, 1, 0, 0, 0, 0} // one LZMA2 filter, 4 KiB dictionary
	b = append(b, header...)
	b = le.AppendUint32(b, crc32.ChecksumIEEE(header))
	for i, rest := 0, data; len(rest) > 0; i++ {
		n := min(len(rest), 64<<10)
		ctl := byte(2)
		if i == 0 {
			ctl = 1 // resets the dictionary
		}
		b = append(b, ctl, byte((n-1)>>8), byte(n-1))
		b = append(b, rest[:n]...)
		rest = rest[n:]
	}
	b = append(b, 0)
	unpadded := len(b) - start + 4 // with the check, without padding
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	b = le.AppendUint32(b, crc32.ChecksumIEEE(data))
	index := binary.AppendUvarint([]byte{0, 1}, uint64(unpadded))
	index = binary.AppendUvarint(index, uint64(len(data)))
	for len(index)%4 != 0 {
		index = append(index, 0)
	}
	index = le.AppendUint32(index, crc32.ChecksumIEEE(index))
	b = append(b, index...)
	footer := le.AppendUint32(nil, uint32(len(index)/4-1))
	footer = append(footer, 0, 1)
	b = le.AppendUint32(b, crc32.ChecksumIEEE(footer))
	return append(append(b, footer...), 'Y', 'Z')
}
