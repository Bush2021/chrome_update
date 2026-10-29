package pefile

import (
	"bytes"
	"debug/pe"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Bush2021/chrome_update/pefile/pefiletest"
)

// testdata/chromeplus-1.18.3-x64.dll is version.dll from the x64 folder of
// Chrome++_v1.18.3_x86_x64_arm64.7z.
func openFixture(t *testing.T) (*os.File, *pe.File) {
	t.Helper()
	f, err := os.Open("testdata/chromeplus-1.18.3-x64.dll")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	pf, err := pe.NewFile(f)
	if err != nil {
		t.Fatal(err)
	}
	return f, pf
}

func TestArch(t *testing.T) {
	_, pf := openFixture(t)
	if a, err := Arch(pf); err != nil || a != "x64" {
		t.Fatalf("Arch = %q, %v", a, err)
	}
}

func TestReadVersionInfo(t *testing.T) {
	f, pf := openFixture(t)
	vi, err := ReadVersionInfo(f, pf)
	if err != nil {
		t.Fatal(err)
	}
	if vi.File != (Version{1, 18, 3, 0}) || vi.Product != (Version{1, 18, 3, 0}) {
		t.Errorf("fixed versions %v %v", vi.File, vi.Product)
	}
	for k, want := range map[string]string{
		"FileDescription":  "Chrome++ Next",
		"ProductVersion":   "1.18.3",
		"OriginalFilename": "chrome++.dll",
		"ProductName":      "chrome++",
	} {
		if got := vi.Strings[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestResources(t *testing.T) {
	f, pf := openFixture(t)
	rs, err := Resources(f, pf)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Find(rs, TypeVersion, "#1"); !ok {
		t.Fatalf("no version resource in %+v", rs)
	}
}

func TestImportedDLLs(t *testing.T) {
	f, pf := openFixture(t)
	dlls, err := ImportedDLLs(f, pf)
	if err != nil || !slices.ContainsFunc(dlls, func(d string) bool { return strings.EqualFold(d, "kernel32.dll") }) {
		t.Fatalf("ImportedDLLs = %v, %v", dlls, err)
	}
}

func TestParseVersionInfoRejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {1, 2, 3}, make([]byte, 64)} {
		if _, err := parseVersionInfo(b); err == nil {
			t.Errorf("parsed %v", b)
		}
	}
}

func TestBuiltImages(t *testing.T) {
	for _, tc := range []struct {
		machine uint16
		arch    string
	}{{pe.IMAGE_FILE_MACHINE_I386, "x86"}, {pe.IMAGE_FILE_MACHINE_AMD64, "x64"}, {pe.IMAGE_FILE_MACHINE_ARM64, "arm64"}} {
		img := pefiletest.Image{
			Machine:     tc.machine,
			FileVersion: [4]uint16{156, 0, 8078, 74},
			Strings:     map[string]string{"FileDescription": "Google Chrome", "ProductVersion": "156.0.8078.74"},
			Imports:     []string{"version-" + tc.arch + ".dll", "KERNEL32.dll"},
		}
		r := bytes.NewReader(img.Bytes())
		pf, err := pe.NewFile(r)
		if err != nil {
			t.Fatalf("%s: %v", tc.arch, err)
		}
		if a, err := Arch(pf); a != tc.arch || err != nil {
			t.Errorf("Arch = %q, %v; want %s", a, err, tc.arch)
		}
		vi, err := ReadVersionInfo(r, pf)
		if err != nil {
			t.Fatalf("%s: %v", tc.arch, err)
		}
		if vi.File != (Version{156, 0, 8078, 74}) || vi.Strings["FileDescription"] != "Google Chrome" || vi.Strings["ProductVersion"] != "156.0.8078.74" {
			t.Errorf("%s: version info %+v", tc.arch, vi)
		}
		dlls, err := ImportedDLLs(r, pf)
		if err != nil || !slices.Equal(dlls, img.Imports) {
			t.Errorf("%s: imports %v, %v", tc.arch, dlls, err)
		}
	}
}
