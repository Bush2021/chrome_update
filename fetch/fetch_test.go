package fetch

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func init() { backoff = func(int) time.Duration { return time.Millisecond } }

func blob(t *testing.T, n int) ([]byte, string) {
	t.Helper()
	b := make([]byte, n)
	rand.Read(b)
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:])
}

func serve(t *testing.T, b []byte, handle func(w http.ResponseWriter, r *http.Request) bool) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handle != nil && handle(w, r) {
			return
		}
		http.ServeContent(w, r, "blob", time.Time{}, bytes.NewReader(b))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, urls []string, size int64, sum string) (string, error) {
	t.Helper()
	dest := filepath.Join(t.TempDir(), "file")
	return dest, Get(context.Background(), nil, File{URLs: urls, Size: size, SHA256: sum, Dest: dest}, nil)
}

func checkFile(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("file holds %d bytes, not the %d expected", len(got), len(want))
	}
	if _, err := os.Stat(path + ".part"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the partial file is still there: %v", err)
	}
}

func TestGet(t *testing.T) {
	b, sum := blob(t, 3<<20)
	srv := serve(t, b, nil)
	dest, err := get(t, []string{srv.URL}, int64(len(b)), sum)
	if err != nil {
		t.Fatal(err)
	}
	checkFile(t, dest, b)
}

func TestResumeAfterADrop(t *testing.T) {
	b, sum := blob(t, 3<<20)
	var calls, ranged atomic.Int32
	srv := serve(t, b, func(w http.ResponseWriter, r *http.Request) bool {
		if calls.Add(1) == 1 {
			w.Header().Set("Content-Length", "3145728")
			w.WriteHeader(http.StatusOK)
			w.Write(b[:1<<20])
			panic(http.ErrAbortHandler) // drops the connection mid-file
		}
		if strings.HasPrefix(r.Header.Get("Range"), "bytes=1048576-") {
			ranged.Add(1)
		}
		return false
	})
	dest, err := get(t, []string{srv.URL}, int64(len(b)), sum)
	if err != nil {
		t.Fatal(err)
	}
	checkFile(t, dest, b)
	if ranged.Load() != 1 {
		t.Errorf("%d requests resumed at 1 MiB", ranged.Load())
	}
}

func TestResumeAPartialFileFromAnEarlierRun(t *testing.T) {
	b, sum := blob(t, 2<<20)
	var fromStart atomic.Int32
	srv := serve(t, b, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Range") == "" {
			fromStart.Add(1)
		}
		return false
	})
	dest := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(dest+".part", b[:777], 0o644); err != nil {
		t.Fatal(err)
	}
	var last int64
	err := Get(context.Background(), nil, File{URLs: []string{srv.URL}, Size: int64(len(b)), SHA256: sum, Dest: dest}, func(done, total int64) { last = done })
	if err != nil {
		t.Fatal(err)
	}
	checkFile(t, dest, b)
	if fromStart.Load() != 0 || last != int64(len(b)) {
		t.Errorf("%d downloads from the start, last progress %d", fromStart.Load(), last)
	}
}

func TestServerIgnoringRanges(t *testing.T) {
	b, sum := blob(t, 1<<20)
	srv := serve(t, b, func(w http.ResponseWriter, r *http.Request) bool {
		w.Write(b) // 200 with the whole file, whatever the range
		return true
	})
	dest := filepath.Join(t.TempDir(), "file")
	os.WriteFile(dest+".part", b[:1000], 0o644)
	if err := Get(context.Background(), nil, File{URLs: []string{srv.URL}, Size: int64(len(b)), SHA256: sum, Dest: dest}, nil); err != nil {
		t.Fatal(err)
	}
	checkFile(t, dest, b)
}

func TestFallsBackToTheNextURL(t *testing.T) {
	b, sum := blob(t, 1<<20)
	gone := serve(t, nil, func(w http.ResponseWriter, r *http.Request) bool {
		http.NotFound(w, r)
		return true
	})
	good := serve(t, b, nil)
	dest, err := get(t, []string{gone.URL, good.URL}, int64(len(b)), sum)
	if err != nil {
		t.Fatal(err)
	}
	checkFile(t, dest, b)
}

func TestNoURL(t *testing.T) {
	b, sum := blob(t, 1000)
	if _, err := get(t, nil, int64(len(b)), sum); err == nil || errors.Is(err, ErrMismatch) {
		t.Fatalf("Get without URLs = %v", err)
	}
}

func TestMismatch(t *testing.T) {
	b, _ := blob(t, 1<<20)
	_, other := blob(t, 1<<20)
	srv := serve(t, b, nil)
	dest, err := get(t, []string{srv.URL}, int64(len(b)), other)
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("err = %v", err)
	}
	for _, p := range []string{dest, dest + ".part"} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is left behind", p)
		}
	}
	if _, err := get(t, []string{srv.URL}, int64(len(b))+1, other); err == nil {
		t.Error("accepted a file of the wrong size")
	}
}

func TestKeepsACompleteFile(t *testing.T) {
	b, sum := blob(t, 1<<20)
	var calls atomic.Int32
	srv := serve(t, b, func(http.ResponseWriter, *http.Request) bool { calls.Add(1); return false })
	dest := filepath.Join(t.TempDir(), "file")
	os.WriteFile(dest, b, 0o644)
	if err := Get(context.Background(), nil, File{URLs: []string{srv.URL}, Size: int64(len(b)), SHA256: sum, Dest: dest}, nil); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Errorf("%d requests for a file already there", calls.Load())
	}
}

func TestCancelKeepsThePartialFile(t *testing.T) {
	b, sum := blob(t, 2<<20)
	ctx, cancel := context.WithCancel(context.Background())
	srv := serve(t, b, func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Length", "2097152")
		w.WriteHeader(http.StatusOK)
		w.Write(b[:4096])
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		return true
	})
	dest := filepath.Join(t.TempDir(), "file")
	progress := func(done, _ int64) {
		if done > 0 {
			cancel()
		}
	}
	err := Get(ctx, nil, File{URLs: []string{srv.URL}, Size: int64(len(b)), SHA256: sum, Dest: dest}, progress)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if st, err := os.Stat(dest + ".part"); err != nil || st.Size() == 0 {
		t.Errorf("partial file: %v, %v", st, err)
	}
}
