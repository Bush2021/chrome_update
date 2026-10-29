package unpack

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ulikunitz/xz"
)

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestDecodeXZ(t *testing.T) {
	data := make([]byte, 3<<20)
	rand.Read(data[:1<<20]) // the rest compresses
	var buf bytes.Buffer
	w, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(data)
	w.Close()
	dir := t.TempDir()
	src := filepath.Join(dir, "in.xz")
	os.WriteFile(src, buf.Bytes(), 0o644)

	dst := filepath.Join(dir, "out")
	var last int64
	if err := DecodeXZ(context.Background(), src, dst, sum(data), int64(len(data)), func(done, _ int64) { last = done }); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dst); !bytes.Equal(got, data) || last != int64(len(data)) {
		t.Fatalf("decoded %d bytes, progress %d", len(got), last)
	}

	bad := filepath.Join(dir, "bad")
	if err := DecodeXZ(context.Background(), src, bad, sum([]byte("other")), 0, nil); err == nil {
		t.Fatal("kept output with the wrong SHA-256")
	}
	for _, p := range []string{bad, bad + ".part"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s left behind", p)
		}
	}
}

func crx3(t *testing.T, name string, content []byte, method uint16) string {
	t.Helper()
	var z bytes.Buffer
	zw := zip.NewWriter(&z)
	fw, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: method})
	if err != nil {
		t.Fatal(err)
	}
	fw.Write(content)
	mw, _ := zw.Create("manifest.json")
	mw.Write([]byte("{}"))
	zw.Close()
	header := bytes.Repeat([]byte{0xAB}, 1310)
	var b bytes.Buffer
	b.WriteString("Cr24")
	binary.Write(&b, binary.LittleEndian, uint32(3))
	binary.Write(&b, binary.LittleEndian, uint32(len(header)))
	b.Write(header)
	b.Write(z.Bytes())
	p := filepath.Join(t.TempDir(), "package.crx3")
	os.WriteFile(p, b.Bytes(), 0o644)
	return p
}

func TestOpenInstallerFromCRX3(t *testing.T) {
	exe := append([]byte("MZ"), bytes.Repeat([]byte("installer"), 1000)...)
	inst, err := OpenInstaller(crx3(t, "156.0.8078.74_chrome_installer_uncompressed.exe", exe, zip.Store))
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()
	got, _ := io.ReadAll(io.NewSectionReader(inst, 0, inst.Size))
	if !bytes.Equal(got, exe) {
		t.Fatalf("read %d bytes, want the %d of the installer", len(got), len(exe))
	}
	if _, err := OpenInstaller(crx3(t, "x_chrome_installer_uncompressed.exe", exe, zip.Deflate)); err == nil {
		t.Error("opened a compressed installer in place")
	}
	if _, err := OpenInstaller(crx3(t, "readme.txt", exe, zip.Store)); err == nil {
		t.Error("opened a package without an installer")
	}
}

func TestOpenBareInstaller(t *testing.T) {
	p := filepath.Join(t.TempDir(), "installer.exe")
	os.WriteFile(p, []byte("MZ and the rest"), 0o644)
	inst, err := OpenInstaller(p)
	if err != nil {
		t.Fatal(err)
	}
	inst.Close()
	os.WriteFile(p, []byte("not a package"), 0o644)
	if _, err := OpenInstaller(p); err == nil {
		t.Error("opened garbage")
	}
}

func TestIsVersion(t *testing.T) {
	for s, want := range map[string]bool{"156.0.8078.74": true, "1.2.3": false, "156.0.8078.x": false, "Locales": false, "1..2.3": false} {
		if isVersion(s) != want {
			t.Errorf("isVersion(%q) != %v", s, want)
		}
	}
}

// TestExtractChromeFromARealPackage needs a package from Google, such as
// the 501 MB x64 CRX3: CHROME_UPDATE_TEST_PACKAGE=/path/to/package.crx3.
func TestExtractChromeFromARealPackage(t *testing.T) {
	pkg := os.Getenv("CHROME_UPDATE_TEST_PACKAGE")
	if pkg == "" {
		t.Skip("set CHROME_UPDATE_TEST_PACKAGE to a CRX3 package or an installer")
	}
	inst, err := OpenInstaller(pkg)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()
	dir := filepath.Join(t.TempDir(), "staging")
	version, err := ExtractChrome(context.Background(), inst, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("extracted %s", version)
	for _, f := range []string{"chrome.exe", "chrome_proxy.exe", filepath.Join(version, "chrome.dll")} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Error(err)
		}
	}
}
