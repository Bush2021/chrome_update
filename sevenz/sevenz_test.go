package sevenz

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"io"
	"io/fs"
	"maps"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// sevenZip finds 7-Zip, which writes the archives these tests read. CI
// must have it; elsewhere the tests skip without it.
func sevenZip(t testing.TB) string {
	t.Helper()
	for _, name := range []string{"7z", "7zz", "7za"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	if os.Getenv("CI") != "" {
		t.Fatal("7-Zip is not in PATH")
	}
	t.Skip("7-Zip is not in PATH")
	return ""
}

// tree writes files that exercise every coder: compressible text, random
// data (in which the branch filters find opcodes to convert), real machine
// code, many small files sharing a solid folder, an empty file and an
// empty folder.
func tree(t testing.TB, small bool) string {
	t.Helper()
	dir := t.TempDir()
	rng := rand.New(rand.NewChaCha8([32]byte{7}))
	random := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(rng.Uint32())
		}
		return b
	}
	scale := 1
	if small {
		scale = 16
	}
	text := strings.Repeat("Chrome-bin/156.0.8078.80/Locales/en-US.pak\n", 8000/scale)
	files := map[string][]byte{
		"text.txt":            []byte(text),
		"random.bin":          random(300 << 10 / scale),
		"a/b/c.txt":           []byte("nested"),
		"名字.txt":              []byte("unicode name"),
		"empty":               nil,
		"bin/tail.exe":        random(3),
		"bin/thousand.dll":    random(1000),
		"bin/aligned-arm.dll": random(4096 + 2),
	}
	if exe, err := os.ReadFile(os.Args[0]); err == nil {
		files["bin/code.exe"] = exe[:min(len(exe), (2<<20)/scale)]
	}
	for i := range 40 / scale {
		files[filepath.ToSlash(filepath.Join("many", string(rune('a'+i%26))+strings.Repeat("x", i)))] = random(i * 97)
	}
	for name, b := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "dir", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func pack(t testing.TB, src string, args ...string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "a.7z")
	cmd := exec.Command(sevenZip(t), append(append([]string{"a", "-t7z", "-bd", "-bso0", "-bsp0", out}, args...), "*")...)
	cmd.Dir = src
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("7z %v: %v\n%s", args, err, b)
	}
	return out
}

func open(t testing.TB, path string) *Reader {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	st, _ := f.Stat()
	r, err := NewReader(f, st.Size())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func methods(r *Reader) []uint64 {
	var ids []uint64
	for _, f := range r.streams.folders {
		for _, c := range f.coders {
			if !slices.Contains(ids, c.id) {
				ids = append(ids, c.id)
			}
		}
	}
	return ids
}

// compare reads every file of r, or every other one when skip is set,
// and checks it against src.
func compare(t *testing.T, r *Reader, src string, skip bool) {
	t.Helper()
	want := map[string]bool{} // name -> is a directory
	filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if rel, _ := filepath.Rel(src, p); rel != "." {
			want[filepath.ToSlash(rel)] = d.IsDir()
		}
		return err
	})
	got := map[string]bool{}
	for i := 0; ; i++ {
		f, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got[f.Name] = f.Dir
		if f.Dir || skip && i%2 == 0 {
			continue
		}
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		orig, _ := os.ReadFile(filepath.Join(src, filepath.FromSlash(f.Name)))
		if !bytes.Equal(b, orig) || f.Size != int64(len(orig)) {
			t.Fatalf("%s: read %d bytes (size %d), want %d", f.Name, len(b), f.Size, len(orig))
		}
	}
	for name, dir := range want {
		if d, ok := got[name]; !ok || d != dir {
			t.Errorf("%s: listed %v as directory %v, want directory %v", name, ok, d, dir)
		}
	}
	if len(got) != len(want) {
		t.Errorf("listed %d entries, want %d", len(got), len(want))
	}
}

func TestArchives(t *testing.T) {
	src := tree(t, false)
	for _, c := range []struct {
		name string
		args []string
		want []uint64
	}{
		{"copy", []string{"-mx0"}, []uint64{methodCopy}},
		{"lzma", []string{"-m0=LZMA:d1m"}, []uint64{methodLZMA}},
		{"lzma2", []string{"-m0=LZMA2:d1m", "-mmt=off"}, []uint64{methodLZMA2}},
		{"lzma2 blocks", []string{"-m0=LZMA2:d1m:c64k", "-mmt=4"}, []uint64{methodLZMA2}},
		{"bcj", []string{"-m0=BCJ", "-m1=LZMA2"}, []uint64{methodBCJ, methodLZMA2}},
		// Chromium's create_installer_archive.py
		{"bcj2", []string{"-m0=BCJ2", "-m1=LZMA:d27:fb128", "-m2=LZMA:d22:fb128:mf=bt2", "-m3=LZMA:d22:fb128:mf=bt2",
			"-mb0:1", "-mb0s1:2", "-mb0s2:3"}, []uint64{methodBCJ2, methodLZMA}},
		{"arm64", []string{"-m0=ARM64", "-m1=LZMA2"}, []uint64{methodARM64, methodLZMA2}},
		{"non-solid, plain header", []string{"-m0=LZMA2", "-ms=off", "-mhc=off"}, []uint64{methodLZMA2}},
		// Chrome++'s release workflow
		{"chrome++", []string{"-mx=9", "-m0=lzma2", "-mmt=on"}, []uint64{methodLZMA2}},
	} {
		t.Run(c.name, func(t *testing.T) {
			archive := pack(t, src, c.args...)
			for _, m := range c.want {
				if !slices.Contains(methods(open(t, archive)), m) {
					t.Fatalf("7-Zip used methods %#x, not %#x", methods(open(t, archive)), m)
				}
			}
			compare(t, open(t, archive), src, false)
			compare(t, open(t, archive), src, true)
		})
	}
}

func TestChromePlusRelease(t *testing.T) {
	r := open(t, "testdata/Chrome++_v1.19.0_x86_x64_arm64.7z")
	want := map[string]string{
		"x86/App/version.dll":   "0d4cc8cb9a297fe723af72f083a92c74a11347975467c6ca0cc28c081ccf2d10",
		"x64/App/version.dll":   "86447687fec3ad107daa75aaf85b45139b99c09ada7f8e9d28d9f29d0114f663",
		"arm64/App/version.dll": "7dd30aabba531630729cafacc18c98d3f8b086319869f997601bfc598713a4a6",
		"x86/App/chrome++.ini":  "b7dd5cea9506f67684e908dc7e883d0e813328c845982681af61a6158dc1003f",
	}
	want["x64/App/chrome++.ini"] = want["x86/App/chrome++.ini"]
	want["arm64/App/chrome++.ini"] = want["x86/App/chrome++.ini"]
	for _, m := range []uint64{methodBCJ2, methodARM64, methodLZMA, methodLZMA2} {
		if !slices.Contains(methods(r), m) {
			t.Errorf("the release no longer uses method %#x", m)
		}
	}
	for {
		f, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if f.Dir {
			continue
		}
		h := sha256.New()
		if _, err := io.Copy(h, r); err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != want[f.Name] {
			t.Errorf("%s: SHA-256 %s, want %s", f.Name, got, want[f.Name])
		}
		delete(want, f.Name)
	}
	if len(want) > 0 {
		t.Errorf("missing %v", want)
	}
}

// contents reads every file, as a caller would.
func contents(b []byte) (map[string]string, error) {
	r, err := NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for {
		f, err := r.Next()
		if err == io.EOF {
			return m, nil
		}
		if err != nil {
			return nil, err
		}
		d, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		m[f.Name] = string(d)
	}
}

// TestDamage cuts and changes archives: reading must fail or, where the
// change misses everything read, return the same files.
func TestDamage(t *testing.T) {
	src := tree(t, true)
	for _, args := range [][]string{
		{"-m0=BCJ2", "-m1=LZMA", "-m2=LZMA", "-m3=LZMA", "-mb0:1", "-mb0s1:2", "-mb0s2:3"},
		{"-m0=ARM64", "-m1=LZMA2"},
		{"-mx0", "-mhc=off"},
	} {
		b, err := os.ReadFile(pack(t, src, args...))
		if err != nil {
			t.Fatal(err)
		}
		orig, err := contents(b)
		if err != nil {
			t.Fatal(err)
		}
		for n := 0; n < len(b); n += max(1, len(b)/300) {
			if _, err := contents(b[:n]); err == nil {
				t.Fatalf("%v: read %d of %d bytes without an error", args, n, len(b))
			}
		}
		for i := 0; i < len(b); i += max(1, len(b)/1000) {
			c := slices.Clone(b)
			c[i] ^= 0x55
			if m, err := contents(c); err == nil && !maps.Equal(m, orig) {
				t.Fatalf("%v: byte %d of %d changed the files without an error", args, i, len(b))
			}
			// With the header's CRC32s right again the change reaches the
			// parser, which must only fail.
			fixCRCs(c)
			contents(c)
		}
	}
}

// fixCRCs rewrites the CRC32s of the start header and the header.
func fixCRCs(b []byte) {
	if len(b) < signatureSize {
		return
	}
	off, n := binary.LittleEndian.Uint64(b[12:]), binary.LittleEndian.Uint64(b[20:])
	if room := uint64(len(b) - signatureSize); off <= room && n <= room-off {
		binary.LittleEndian.PutUint32(b[28:], crc32.ChecksumIEEE(b[signatureSize+off:][:n]))
	}
	binary.LittleEndian.PutUint32(b[8:], crc32.ChecksumIEEE(b[12:signatureSize]))
}

func TestErrors(t *testing.T) {
	if _, err := NewReader(bytes.NewReader([]byte("not an archive at all, but long enough")), 38); !errors.Is(err, ErrFormat) {
		t.Errorf("garbage: %v", err)
	}
	b, err := os.ReadFile(pack(t, tree(t, true), "-m0=PPMd"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contents(b); !errors.Is(err, ErrUnsupported) {
		t.Errorf("PPMd: %v", err)
	}
}

func FuzzReader(f *testing.F) {
	src := tree(f, true)
	for _, args := range [][]string{{"-mx0"}, {"-m0=LZMA2"}, {"-m0=BCJ2", "-m1=LZMA", "-m2=LZMA", "-m3=LZMA", "-mb0:1", "-mb0s1:2", "-mb0s2:3"}, {"-m0=ARM64", "-m1=LZMA2", "-mhc=off"}} {
		b, err := os.ReadFile(pack(f, src, args...))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		contents(b)
		fixCRCs(b)
		contents(b)
	})
}
