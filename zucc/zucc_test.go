package zucc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	zucchini "github.com/404Setup/go-zucchini"
)

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type files struct{ base, patch, dst string }

func write(t *testing.T, old, p []byte) files {
	t.Helper()
	dir := t.TempDir()
	f := files{filepath.Join(dir, "base.crx3"), filepath.Join(dir, "update.zuc"), filepath.Join(dir, "new.crx3")}
	os.WriteFile(f.base, old, 0o644)
	os.WriteFile(f.patch, p, 0o644)
	return f
}

func fixture(t *testing.T) (old, new, p []byte) {
	t.Helper()
	old = bytes.Repeat([]byte("package of Chrome 156.0.8078.48\n"), 4000)
	new = bytes.Repeat([]byte("package of Chrome 156.0.8078.74\n"), 4000)
	p, err := zucchini.GenerateBuffer(old, new)
	if err != nil {
		t.Fatal(err)
	}
	return old, new, p
}

func TestApply(t *testing.T) {
	old, new, p := fixture(t)
	f := write(t, old, p)
	if err := Apply(f.base, f.patch, f.dst, int64(len(new)), sum(new)); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(f.dst); !bytes.Equal(got, new) {
		t.Error("the rebuilt package differs")
	}
}

func TestApplyLeavesNothingOnFailure(t *testing.T) {
	old, new, p := fixture(t)
	garbage := bytes.Repeat([]byte{0xff}, 4096)
	cases := []struct {
		name     string
		old, p   []byte
		size     int64
		sum      string
		mismatch bool
	}{
		{"wrong SHA-256", old, p, int64(len(new)), sum(old), true},
		{"wrong base", new, p, int64(len(new)), sum(new), false},
		{"wrong size", old, p, int64(len(new)) + 1, sum(new), false},
		{"not a patch", old, garbage, int64(len(new)), sum(new), false},
		{"truncated patch", old, p[:len(p)/2], int64(len(new)), sum(new), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := write(t, c.old, c.p)
			err := Apply(f.base, f.patch, f.dst, c.size, c.sum)
			if err == nil || errors.Is(err, ErrMismatch) != c.mismatch {
				t.Fatalf("Apply = %v", err)
			}
			for _, path := range []string{f.dst, f.dst + ".part"} {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s is left: %v", filepath.Base(path), err)
				}
			}
		})
	}
}

func TestApplyWithoutBase(t *testing.T) {
	_, new, p := fixture(t)
	f := write(t, nil, p)
	os.Remove(f.base)
	if err := Apply(f.base, f.patch, f.dst, int64(len(new)), sum(new)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Apply = %v", err)
	}
}

// TestGooglePatch applies Google's x64 patch from Chrome 156.0.8078.48 to
// .74, whose pipeline is omaha/testdata/diff-48-x64.txt.
// CHROME_UPDATE_ZUCC_FIXTURE names a folder holding the base package as
// <sha256>.crx3 and the decoded patch as update.zuc.
func TestGooglePatch(t *testing.T) {
	dir := os.Getenv("CHROME_UPDATE_ZUCC_FIXTURE")
	if dir == "" {
		t.Skip("set CHROME_UPDATE_ZUCC_FIXTURE")
	}
	base := filepath.Join(dir, "f103730ff086d28c880c0de44e7fc6a7df72ce79c1e83dc6a46151031c490f6b.crx3")
	dst := filepath.Join(t.TempDir(), "new.crx3")
	if err := Apply(base, filepath.Join(dir, "update.zuc"), dst, 525473563, "a65959d8f3e34537dc4c8bcabb8ed14414d8d606dc936405460d4111109d2e38"); err != nil {
		t.Fatal(err)
	}
}
