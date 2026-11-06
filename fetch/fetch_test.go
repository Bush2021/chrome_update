package fetch

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func init() {
	backoff = func(int) time.Duration { return time.Millisecond }
	stall = 200 * time.Millisecond
}

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

// A stalled server is left for the next URL, before its headers and after
// some of the body.
func TestStalledServerFallsBack(t *testing.T) {
	b, sum := blob(t, 1<<20)
	silent := serve(t, nil, func(w http.ResponseWriter, r *http.Request) bool {
		<-r.Context().Done()
		return true
	})
	slow := serve(t, nil, func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.WriteHeader(http.StatusOK)
		w.Write(b[:4096])
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		return true
	})
	good := serve(t, b, nil)
	dest, err := get(t, []string{silent.URL, slow.URL, good.URL}, int64(len(b)), sum)
	if err != nil {
		t.Fatal(err)
	}
	checkFile(t, dest, b)
}

// A URL that never sends a byte is not waited on again.
func TestSilentURLIsTriedOnce(t *testing.T) {
	b, sum := blob(t, 1000)
	var calls atomic.Int32
	silent := func(w http.ResponseWriter, r *http.Request) bool {
		calls.Add(1)
		<-r.Context().Done()
		return true
	}
	a, c := serve(t, nil, silent), serve(t, nil, silent)
	if _, err := get(t, []string{a.URL, c.URL}, int64(len(b)), sum); err == nil {
		t.Fatal("got no error")
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("%d requests, want 2", n)
	}
}

// Every URL is tried once before any is tried again.
func TestTriesEveryURLBeforeRetrying(t *testing.T) {
	b, sum := blob(t, 1000)
	var mu sync.Mutex
	var log []string
	var bCalls atomic.Int32
	a := serve(t, b, func(w http.ResponseWriter, r *http.Request) bool {
		mu.Lock()
		log = append(log, "a")
		mu.Unlock()
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return true
	})
	bSrv := serve(t, b, func(w http.ResponseWriter, r *http.Request) bool {
		mu.Lock()
		log = append(log, "b")
		mu.Unlock()
		if bCalls.Add(1) == 1 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	if _, err := get(t, []string{a.URL, bSrv.URL}, int64(len(b)), sum); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(log, ""); got != "abab" {
		t.Errorf("requests went %s, want abab", got)
	}
}

func TestErrorNamesEveryURL(t *testing.T) {
	b, sum := blob(t, 1000)
	gone := serve(t, nil, func(w http.ResponseWriter, r *http.Request) bool { http.NotFound(w, r); return true })
	busy := serve(t, nil, func(w http.ResponseWriter, r *http.Request) bool {
		http.Error(w, "busy", http.StatusBadGateway)
		return true
	})
	_, err := get(t, []string{gone.URL, busy.URL}, int64(len(b)), sum)
	if err == nil || !strings.Contains(err.Error(), gone.URL+": 404") || !strings.Contains(err.Error(), busy.URL+": 502") {
		t.Fatalf("err = %v", err)
	}
}

// Bytes that fail the hash are thrown away, and the next URL starts over.
func TestMismatchFallsBack(t *testing.T) {
	b, sum := blob(t, 1<<20)
	wrong, _ := blob(t, 1<<20)
	bad := serve(t, wrong, nil)
	good := serve(t, b, nil)
	dest, err := get(t, []string{bad.URL, good.URL}, int64(len(b)), sum)
	if err != nil {
		t.Fatal(err)
	}
	checkFile(t, dest, b)
}

// A connection that drops again and again still finishes the file, as long
// as each one brings new bytes.
func TestProgressDoesNotUseUpTheRounds(t *testing.T) {
	b, sum := blob(t, 1<<20)
	const chunk = 64 << 10
	srv := serve(t, b, func(w http.ResponseWriter, r *http.Request) bool {
		var from int
		fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-", &from)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, len(b)-1, len(b)))
		w.Header().Set("Content-Length", strconv.Itoa(len(b)-from))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(b[from:min(from+chunk, len(b))])
		if from+chunk < len(b) {
			panic(http.ErrAbortHandler)
		}
		return true
	})
	dest, err := get(t, []string{srv.URL}, int64(len(b)), sum)
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

// followed runs Get with a Follow that records what each of its runs read.
func followed(ctx context.Context, f File) (reads [][]byte, err error) {
	var mu sync.Mutex
	f.Follow = func(r io.Reader) error {
		b, err := io.ReadAll(r)
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			reads = append(reads, b)
		}
		return err
	}
	err = Get(ctx, nil, f, nil)
	return reads, err
}

func TestFollowReadsWhileTheFileDownloads(t *testing.T) {
	b, sum := blob(t, 1<<20)
	half := len(b) / 2
	got := make(chan struct{})
	srv := serve(t, b, func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.Write(b[:half])
		w.(http.Flusher).Flush()
		select {
		case <-got:
		case <-time.After(10 * time.Second):
			t.Error("the follower did not see the first half before the second was sent")
		}
		w.Write(b[half:])
		return true
	})
	dest := filepath.Join(t.TempDir(), "file")
	var read bytes.Buffer
	err := Get(context.Background(), nil, File{URLs: []string{srv.URL}, Size: int64(len(b)), SHA256: sum, Dest: dest, Follow: func(r io.Reader) error {
		if _, err := io.CopyN(&read, r, int64(half)); err != nil {
			return err
		}
		close(got)
		_, err := io.Copy(&read, r)
		return err
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkFile(t, dest, b)
	if !bytes.Equal(read.Bytes(), b) {
		t.Errorf("the follower read %d bytes of %d", read.Len(), len(b))
	}
}

func TestFollowSurvivesADrop(t *testing.T) {
	b, sum := blob(t, 3<<20)
	var calls atomic.Int32
	srv := serve(t, b, func(w http.ResponseWriter, r *http.Request) bool {
		if calls.Add(1) == 1 {
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			w.WriteHeader(http.StatusOK)
			w.Write(b[:1<<20])
			panic(http.ErrAbortHandler)
		}
		return false
	})
	dest := filepath.Join(t.TempDir(), "file")
	reads, err := followed(context.Background(), File{URLs: []string{srv.URL}, Size: int64(len(b)), SHA256: sum, Dest: dest})
	if err != nil {
		t.Fatal(err)
	}
	checkFile(t, dest, b)
	if len(reads) != 1 || !bytes.Equal(reads[0], b) {
		t.Errorf("%d reads", len(reads))
	}
}

func TestFollowStartsAtAnEarlierRunsBytes(t *testing.T) {
	b, sum := blob(t, 2<<20)
	srv := serve(t, b, nil)
	dest := filepath.Join(t.TempDir(), "file")
	os.WriteFile(dest+".part", b[:777], 0o644)
	reads, err := followed(context.Background(), File{URLs: []string{srv.URL}, Size: int64(len(b)), SHA256: sum, Dest: dest})
	if err != nil {
		t.Fatal(err)
	}
	if len(reads) != 1 || !bytes.Equal(reads[0], b) {
		t.Errorf("%d reads", len(reads))
	}
}

func TestFollowRunsAgainAfterADownloadStartsOver(t *testing.T) {
	b, sum := blob(t, 1<<20)
	srv := serve(t, b, func(w http.ResponseWriter, r *http.Request) bool {
		w.Write(b) // 200 with the whole file, whatever the range
		return true
	})
	dest := filepath.Join(t.TempDir(), "file")
	os.WriteFile(dest+".part", b[:1000], 0o644)
	reads, err := followed(context.Background(), File{URLs: []string{srv.URL}, Size: int64(len(b)), SHA256: sum, Dest: dest})
	if err != nil {
		t.Fatal(err)
	}
	checkFile(t, dest, b)
	if len(reads) != 1 || !bytes.Equal(reads[0], b) {
		t.Errorf("%d complete reads", len(reads))
	}
}

func TestFollowReadsACompleteFile(t *testing.T) {
	b, sum := blob(t, 1<<20)
	dest := filepath.Join(t.TempDir(), "file")
	os.WriteFile(dest, b, 0o644)
	reads, err := followed(context.Background(), File{URLs: []string{"http://unused.invalid"}, Size: int64(len(b)), SHA256: sum, Dest: dest})
	if err != nil {
		t.Fatal(err)
	}
	if len(reads) != 1 || !bytes.Equal(reads[0], b) {
		t.Errorf("%d reads", len(reads))
	}
}

func TestFollowEndsOnAMismatch(t *testing.T) {
	b, _ := blob(t, 1<<20)
	_, other := blob(t, 1<<20)
	srv := serve(t, b, nil)
	dest := filepath.Join(t.TempDir(), "file")
	_, err := followed(context.Background(), File{URLs: []string{srv.URL}, Size: int64(len(b)), SHA256: other, Dest: dest})
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(dest + ".part"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the partial file is left behind: %v", err)
	}
}

func TestAFailedFollowLeavesTheDownloadComplete(t *testing.T) {
	b, sum := blob(t, 1<<20)
	srv := serve(t, b, nil)
	dest := filepath.Join(t.TempDir(), "file")
	broken := errors.New("disk full")
	f := File{URLs: []string{srv.URL}, Size: int64(len(b)), SHA256: sum, Dest: dest, Follow: func(io.Reader) error { return broken }}
	if err := Get(context.Background(), nil, f, nil); !errors.Is(err, broken) {
		t.Fatalf("err = %v", err)
	}
	checkFile(t, dest, b)
}

func TestCancelEndsFollowAndKeepsThePartialFile(t *testing.T) {
	b, sum := blob(t, 2<<20)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := serve(t, b, func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.WriteHeader(http.StatusOK)
		w.Write(b[:4096])
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		return true
	})
	dest := filepath.Join(t.TempDir(), "file")
	followErr := make(chan error, 1)
	err := Get(ctx, nil, File{URLs: []string{srv.URL}, Size: int64(len(b)), SHA256: sum, Dest: dest, Follow: func(r io.Reader) error {
		_, err := io.ReadAll(r)
		followErr <- err
		return err
	}}, func(done, _ int64) {
		if done > 0 {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if err := <-followErr; !errors.Is(err, context.Canceled) {
		t.Errorf("Follow ended with %v", err)
	}
	if st, err := os.Stat(dest + ".part"); err != nil || st.Size() == 0 {
		t.Errorf("partial file: %v, %v", st, err)
	}
}
