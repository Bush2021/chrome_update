// Package unpack turns Google's packages into files: it decodes xz streams,
// reads the installer a CRX3 package holds, and extracts CHROME.7Z from the
// installer, all without loading them into memory.
package unpack

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/bodgit/sevenzip"
	"github.com/ulikunitz/xz"

	"github.com/Bush2021/chrome_update/pefile"
)

// total is 0 when unknown.
type Progress func(done, total int64)

func noProgress(int64, int64) {}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

type progressWriter struct {
	w        io.Writer
	done     int64
	total    int64
	progress Progress
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.done += int64(n)
	p.progress(p.done, p.total)
	return n, err
}

// dst appears only once the output matches wantSHA256.
func DecodeXZ(ctx context.Context, src, dst, wantSHA256 string, total int64, progress Progress) error {
	if progress == nil {
		progress = noProgress
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	r, err := xz.NewReader(bufio.NewReaderSize(ctxReader{ctx, in}, 1<<20))
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(src), err)
	}
	return writeVerified(dst, wantSHA256, func(w io.Writer) error {
		_, err := io.CopyBuffer(&progressWriter{w: w, total: total, progress: progress}, r, make([]byte, 1<<20))
		return err
	})
}

func writeVerified(dst, want string, fill func(io.Writer) error) error {
	part := dst + ".part"
	f, err := os.Create(part)
	if err != nil {
		return err
	}
	h := sha256.New()
	bw := bufio.NewWriterSize(io.MultiWriter(f, h), 1<<20)
	err = fill(bw)
	if err == nil {
		err = bw.Flush()
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), want) {
		err = fmt.Errorf("%s does not match its SHA-256", filepath.Base(dst))
	}
	if err != nil {
		os.Remove(part)
		return err
	}
	return os.Rename(part, dst)
}

type Installer struct {
	io.ReaderAt
	Size int64
	file *os.File
}

func (i *Installer) Close() error { return i.file.Close() }

// path is a CRX3 package or a bare installer. A package's ZIP stores the
// installer uncompressed, so it is read in place.
func OpenInstaller(path string) (*Installer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	head := make([]byte, 12)
	if _, err := f.ReadAt(head, 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	if string(head[:2]) == "MZ" {
		return &Installer{ReaderAt: f, Size: st.Size(), file: f}, nil
	}
	if string(head[:4]) != "Cr24" || binary.LittleEndian.Uint32(head[4:]) != 3 {
		f.Close()
		return nil, fmt.Errorf("%s is neither a CRX3 package nor an installer", filepath.Base(path))
	}
	zipStart := 12 + int64(binary.LittleEndian.Uint32(head[8:]))
	if zipStart >= st.Size() {
		f.Close()
		return nil, fmt.Errorf("%s: header past the end", filepath.Base(path))
	}
	zr, err := zip.NewReader(io.NewSectionReader(f, zipStart, st.Size()-zipStart), st.Size()-zipStart)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	for _, e := range zr.File {
		if !strings.HasSuffix(strings.ToLower(e.Name), ".exe") {
			continue
		}
		if e.Method != zip.Store {
			f.Close()
			return nil, fmt.Errorf("%s: the installer is compressed (method %d)", filepath.Base(path), e.Method)
		}
		off, err := e.DataOffset()
		if err != nil {
			f.Close()
			return nil, err
		}
		n := int64(e.UncompressedSize64)
		return &Installer{ReaderAt: io.NewSectionReader(f, zipStart+off, n), Size: n, file: f}, nil
	}
	f.Close()
	return nil, fmt.Errorf("%s holds no installer", filepath.Base(path))
}

func chromeArchive(inst *Installer) (*sevenzip.Reader, error) {
	pf, err := pe.NewFile(inst)
	if err != nil {
		return nil, fmt.Errorf("installer: %w", err)
	}
	rs, err := pefile.Resources(inst, pf)
	if err != nil {
		return nil, fmt.Errorf("installer resources: %w", err)
	}
	for _, name := range []string{"CHROME.7Z", "CHROME.PACKED.7Z"} {
		for _, r := range rs {
			if strings.EqualFold(r.Name, name) {
				if r.Offset+r.Size > inst.Size {
					return nil, fmt.Errorf("%s runs past the installer's end", name)
				}
				return sevenzip.NewReader(io.NewSectionReader(inst, r.Offset, r.Size), r.Size)
			}
		}
	}
	return nil, errors.New("the installer holds no CHROME.7Z")
}

// dir must not exist yet.
func ExtractChrome(ctx context.Context, inst *Installer, dir string, progress Progress) (string, error) {
	if progress == nil {
		progress = noProgress
	}
	z, err := chromeArchive(inst)
	if err != nil {
		return "", err
	}
	var total int64
	var version string
	for _, f := range z.File {
		total += int64(f.UncompressedSize)
		rel, ok := strings.CutPrefix(f.Name, "Chrome-bin/")
		if !ok {
			continue
		}
		if first, _, more := strings.Cut(rel, "/"); more && isVersion(first) {
			if version != "" && version != first {
				return "", fmt.Errorf("the archive holds two versions, %s and %s", version, first)
			}
			version = first
		}
	}
	if version == "" {
		return "", errors.New("the archive holds no version folder")
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		return "", err
	}
	pw := &progressWriter{total: total, progress: progress}
	buf := make([]byte, 1<<20)
	for _, f := range z.File {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		rel, ok := strings.CutPrefix(f.Name, "Chrome-bin/")
		if !ok || rel == "" {
			pw.done += int64(f.UncompressedSize)
			continue
		}
		if err := extractFile(f, dir, rel, pw, buf); err != nil {
			return "", err
		}
	}
	for _, need := range []string{"chrome.exe", filepath.Join(version, "chrome.dll")} {
		if _, err := os.Stat(filepath.Join(dir, need)); err != nil {
			return "", fmt.Errorf("the archive lacks %s", need)
		}
	}
	return version, nil
}

// sevenzip checks the archive's headers but not each file's CRC32.
func extractFile(f *sevenzip.File, dir, rel string, pw *progressWriter, buf []byte) error {
	clean := path.Clean(rel)
	if !filepath.IsLocal(filepath.FromSlash(clean)) {
		return fmt.Errorf("unsafe path %q in the archive", f.Name)
	}
	dst := filepath.Join(dir, filepath.FromSlash(clean))
	if f.FileInfo().IsDir() {
		return os.MkdirAll(dst, 0o755)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("%s: %w", f.Name, err)
	}
	defer rc.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	h := crc32.NewIEEE()
	pw.w = io.MultiWriter(out, h)
	n, err := io.CopyBuffer(pw, rc, buf)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("%s: %w", f.Name, err)
	}
	if n != int64(f.UncompressedSize) || (f.CRC32 != 0 && h.Sum32() != f.CRC32) {
		return fmt.Errorf("%s: damaged in the archive", f.Name)
	}
	return nil
}

func isVersion(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return false
		}
	}
	return true
}
