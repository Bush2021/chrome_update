// Package fetch downloads files that must match a known size and SHA-256,
// resuming where an earlier attempt stopped.
package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Progress func(done, total int64)

type File struct {
	URLs   []string
	Size   int64
	SHA256 string
	Dest   string
	// Follow, if set, reads the file from its first byte while it downloads,
	// and Get waits for it. Its reader blocks at the bytes yet to come, and
	// they are not verified until Get returns. A failed Follow does not stop
	// the download. If the download starts over, Follow runs again on the
	// finished file, so it must not keep what an earlier run produced.
	Follow func(io.Reader) error
}

var ErrMismatch = errors.New("the download does not match its expected size or SHA-256")

const retries = 3

// A variable so that tests need not wait.
var backoff = func(n int) time.Duration { return time.Duration(1<<n) * time.Second }

// Get downloads f into f.Dest. A complete f.Dest is kept as it is, and the
// f.Dest+".part" an earlier attempt left is resumed. The bytes go to
// f.Dest only once they match f.Size and f.SHA256. When ctx ends, the
// partial file stays for the next attempt.
func Get(ctx context.Context, client *http.Client, f File, progress Progress) error {
	if client == nil {
		client = http.DefaultClient
	}
	if progress == nil {
		progress = func(int64, int64) {}
	}
	if len(f.URLs) == 0 {
		return fmt.Errorf("%s: no URL to download it from", filepath.Base(f.Dest))
	}
	ok, err := Matches(f.Dest, f.Size, f.SHA256)
	if err != nil {
		return err
	}
	if ok {
		progress(f.Size, f.Size)
		return replay(f)
	}
	part := f.Dest + ".part"
	w, err := os.OpenFile(part, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if w != nil {
			w.Close()
		}
	}()
	d := &download{f: f, w: w, h: sha256.New(), progress: progress}
	if err := d.rehash(); err != nil {
		return err
	}
	if err := d.follow(part); err != nil {
		return err
	}
	err = d.fromAny(ctx, client)
	mismatch := err == nil && (d.off != f.Size || !strings.EqualFold(hex.EncodeToString(d.h.Sum(nil)), f.SHA256))
	if mismatch {
		err = fmt.Errorf("%s: %w", filepath.Base(f.Dest), ErrMismatch)
	}
	if err == nil {
		err = w.Sync()
	}
	followed := d.t.close(err)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	w = nil
	if mismatch {
		os.Remove(part)
	}
	if err != nil {
		return err
	}
	if err := os.Rename(part, f.Dest); err != nil {
		return err
	}
	if d.t != nil && d.t.restarted {
		return replay(f)
	}
	return followed
}

func replay(f File) error {
	if f.Follow == nil {
		return nil
	}
	r, err := os.Open(f.Dest)
	if err != nil {
		return err
	}
	defer r.Close()
	return f.Follow(r)
}

// tail is the reader File.Follow gets. It has its own handle on the partial
// file, so a slow follower never holds the download back.
type tail struct {
	r      *os.File
	off    int64
	result chan error

	mu        sync.Mutex
	changed   sync.Cond
	size      int64
	restarted bool
	end       error
}

var errRestarted = errors.New("the download started over")

func (t *tail) Read(p []byte) (int, error) {
	t.mu.Lock()
	for t.off == t.size && t.end == nil && !t.restarted {
		t.changed.Wait()
	}
	size, restarted, end := t.size, t.restarted, t.end
	t.mu.Unlock()
	if restarted {
		return 0, errRestarted
	}
	if end != nil && (end != io.EOF || t.off == size) {
		return 0, end
	}
	if int64(len(p)) > size-t.off {
		p = p[:size-t.off]
	}
	n, err := t.r.ReadAt(p, t.off)
	t.off += int64(n)
	if err == io.EOF {
		// The file shrank under us: the next Read sees why.
		err = nil
	}
	return n, err
}

func (t *tail) update(change func()) {
	if t == nil {
		return
	}
	t.mu.Lock()
	change()
	t.mu.Unlock()
	t.changed.Broadcast()
}

// close ends the reader and returns Follow's result. With a nil err the
// reader gets the rest of the file and then io.EOF, otherwise err at once.
func (t *tail) close(err error) error {
	if t == nil {
		return nil
	}
	if err == nil {
		err = io.EOF
	}
	t.update(func() { t.end = err })
	result := <-t.result
	t.r.Close()
	return result
}

type permanent struct{ error }

func (p permanent) Unwrap() error { return p.error }

type download struct {
	f        File
	w        *os.File
	h        hash.Hash
	off      int64
	progress Progress
	t        *tail
}

func (d *download) follow(part string) error {
	if d.f.Follow == nil {
		return nil
	}
	r, err := os.Open(part)
	if err != nil {
		return err
	}
	d.t = &tail{r: r, size: d.off, result: make(chan error, 1)}
	d.t.changed.L = &d.t.mu
	go func() { d.t.result <- d.f.Follow(d.t) }()
	return nil
}

func (d *download) fromAny(ctx context.Context, client *http.Client) error {
	var lastErr error
	for _, url := range d.f.URLs {
		for attempt := 0; attempt <= retries; attempt++ {
			if attempt > 0 {
				select {
				case <-time.After(backoff(attempt - 1)):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			lastErr = d.from(ctx, client, url)
			if lastErr == nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if _, ok := errors.AsType[permanent](lastErr); ok {
				break
			}
		}
	}
	return lastErr
}

func (d *download) rehash() error {
	st, err := d.w.Stat()
	if err != nil {
		return err
	}
	if st.Size() > d.f.Size {
		return d.restart()
	}
	if _, err := d.w.Seek(0, io.SeekStart); err != nil {
		return err
	}
	n, err := io.Copy(d.h, d.w)
	if err != nil {
		return err
	}
	d.off = n
	d.progress(d.off, d.f.Size)
	return nil
}

func (d *download) restart() error {
	d.t.update(func() { d.t.restarted = true })
	if err := d.w.Truncate(0); err != nil {
		return err
	}
	if _, err := d.w.Seek(0, io.SeekStart); err != nil {
		return err
	}
	d.h.Reset()
	d.off = 0
	return nil
}

func (d *download) from(ctx context.Context, client *http.Client, url string) error {
	if d.off == d.f.Size {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return permanent{err}
	}
	if d.off > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", d.off))
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		if d.off > 0 {
			// The server ignored the range: start over.
			if err := d.restart(); err != nil {
				return permanent{err}
			}
		}
		if resp.ContentLength >= 0 && resp.ContentLength != d.f.Size {
			return permanent{fmt.Errorf("%s: %d bytes, want %d", url, resp.ContentLength, d.f.Size)}
		}
	case http.StatusPartialContent:
		var start, end, total int64
		if _, err := fmt.Sscanf(resp.Header.Get("Content-Range"), "bytes %d-%d/%d", &start, &end, &total); err != nil || start != d.off || total != d.f.Size {
			return permanent{fmt.Errorf("%s: unexpected Content-Range %q", url, resp.Header.Get("Content-Range"))}
		}
	case http.StatusRequestedRangeNotSatisfiable:
		if err := d.restart(); err != nil {
			return permanent{err}
		}
		return errors.New("the server refused the range; starting over")
	default:
		err := fmt.Errorf("%s: %s", url, resp.Status)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return permanent{err}
		}
		return err
	}
	if _, err := d.w.Seek(d.off, io.SeekStart); err != nil {
		return permanent{err}
	}
	buf := make([]byte, 1<<20)
	body := io.LimitReader(resp.Body, d.f.Size-d.off)
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if _, err := d.w.Write(buf[:n]); err != nil {
				return permanent{err}
			}
			d.h.Write(buf[:n])
			d.off += int64(n)
			d.t.update(func() { d.t.size = d.off })
			d.progress(d.off, d.f.Size)
		}
		if rerr == io.EOF {
			if d.off < d.f.Size {
				return io.ErrUnexpectedEOF
			}
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

func Matches(path string, size int64, sum string) (bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() != size {
		return false, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), sum), nil
}

func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
