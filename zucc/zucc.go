// Package zucc performs a zucc step of Google's update pipelines: it
// rebuilds a package from an earlier one and a Zucchini patch.
package zucc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	zucchini "github.com/404Setup/go-zucchini"
)

var ErrMismatch = errors.New("the rebuilt package does not match its expected SHA-256")

// Apply writes what patch makes of base to dst, which appears only once it
// has the given size and SHA-256. The files are mapped rather than read,
// so the work needs little more memory than Zucchini's own tables.
func Apply(base, patch, dst string, size int64, sum string) (err error) {
	if size <= 0 {
		return fmt.Errorf("the package size %d is not valid", size)
	}
	old, err := mapFile(base, 0)
	if err != nil {
		return err
	}
	defer old.close()
	p, err := mapFile(patch, 0)
	if err != nil {
		return err
	}
	defer p.close()
	part := dst + ".part"
	out, err := mapFile(part, size)
	if err != nil {
		os.Remove(part)
		return err
	}
	err = rebuild(old.data, p.data, out.data)
	if err == nil {
		got := sha256.Sum256(out.data)
		if !strings.EqualFold(hex.EncodeToString(got[:]), sum) {
			err = ErrMismatch
		}
	}
	if cerr := out.close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(part)
		return err
	}
	return os.Rename(part, dst)
}

// rebuild turns a fault reading a mapped file, or a patch Zucchini can't
// handle, into an error instead of a crash.
func rebuild(old, p, out []byte) (err error) {
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("zucchini: %v", r)
		}
	}()
	return zucchini.ApplyTo(old, p, out)
}
