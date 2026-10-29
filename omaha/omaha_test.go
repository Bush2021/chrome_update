package omaha

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// testdata holds answers Google's server gave on 28 October 2026, without
// the variations seed: diff-48-x64.txt for x64 156.0.8078.48 with its
// package cached, install-x64.txt for a fresh x64 install.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const (
	pkg74 = "a65959d8f3e34537dc4c8bcabb8ed14414d8d606dc936405460d4111109d2e38"
	pkg48 = "f103730ff086d28c880c0de44e7fc6a7df72ce79c1e83dc6a46151031c490f6b"
)

func TestParsePatchAnswer(t *testing.T) {
	a, err := parse(fixture(t, "diff-48-x64.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != "156.0.8078.74" {
		t.Errorf("version %q", a.Version)
	}
	var kinds []string
	for _, p := range a.Pipelines {
		kinds = append(kinds, p.Kind())
		for _, op := range p.Ops {
			for _, u := range op.URLs {
				if !strings.HasPrefix(u, "https://") {
					t.Errorf("kept %s", u)
				}
			}
		}
	}
	if strings.Join(kinds, ",") != "zucc,puff,xz,full" {
		t.Errorf("kinds %v", kinds)
	}

	p, ok := a.Pick(OpDownload, OpXZ, OpCRX3)
	if !ok || p.Kind() != "xz" {
		t.Fatalf("picked %+v", p)
	}
	dl, _ := p.Download()
	if dl.Size != 189933192 || dl.Out != "e51c98b6a57cc678883fd9d67c0c57d5f251adacd0cd0aeb568b7c15b21b9490" || len(dl.URLs) != 2 {
		t.Errorf("download %+v", dl)
	}
	crx, _ := p.Package()
	if crx.In != pkg74 || crx.Path != "156.0.8078.74_chrome_installer_uncompressed.exe" {
		t.Errorf("package %+v", crx)
	}

	p, ok = a.Pick(OpDownload, OpXZ, OpZucc, OpCRX3)
	if !ok || p.Kind() != "zucc" {
		t.Fatalf("picked %+v", p)
	}
	patch, _ := p.Patch()
	if patch.Previous != pkg48 || patch.Out != pkg74 {
		t.Errorf("patch %+v", patch)
	}

	p, ok = a.Pick(OpDownload, OpCRX3)
	if !ok || p.Kind() != "full" {
		t.Fatalf("picked %+v", p)
	}
}

func TestParseStatuses(t *testing.T) {
	answer := func(app, check string) []byte {
		return []byte(`)]}'` + "\n" + `{"response":{"apps":[{"status":"` + app + `","updatecheck":{"status":"` + check + `"}}]}}`)
	}
	a, err := parse(answer("ok", "noupdate"))
	if err != nil || a.Version != "" || len(a.Pipelines) != 0 {
		t.Errorf("noupdate: %+v, %v", a, err)
	}
	for _, b := range [][]byte{answer("error-unknownApplication", ""), answer("ok", "error-osnotsupported"), answer("ok", "ok"), []byte("<html>")} {
		if _, err := parse(b); err == nil {
			t.Errorf("parsed %s", b)
		} else if !strings.HasPrefix(string(b), "<") && !errors.Is(err, ErrStatus) {
			t.Errorf("%s: %v is not ErrStatus", b, err)
		}
	}
}

func TestRequestBody(t *testing.T) {
	cases := []struct {
		req       Request
		appID, ap string
	}{
		{Request{Channel: Stable, Arch: "x64", Version: "156.0.8078.48"}, "{8a69d345-d564-463c-aff1-a69d9e530f96}", "x64-stable"},
		{Request{Channel: Beta, Arch: "x86"}, "{8a69d345-d564-463c-aff1-a69d9e530f96}", "1.1-beta-arch_x86"},
		{Request{Channel: Dev, Arch: "arm64"}, "{8a69d345-d564-463c-aff1-a69d9e530f96}", "2.0-dev-arch_arm64"},
		{Request{Channel: Canary, Arch: "x64"}, "{4ea16ac7-fd5a-47c3-875b-dbf4a2008c20}", "x64-canary"},
	}
	for _, c := range cases {
		b, err := c.req.body()
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Request struct {
				Updater, Protocol, UpdaterVersion, AcceptFormat string
				Apps                                            []app
			} `json:"request"`
		}
		raw := strings.NewReplacer(`"@updater"`, `"updater"`).Replace(string(b))
		if err := json.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatal(err)
		}
		r := got.Request
		if r.Updater != "updater" || r.Protocol != "4.0" || r.UpdaterVersion == "" || r.AcceptFormat != "crx3,download,run,xz" {
			t.Errorf("%+v", r)
		}
		a := r.Apps[0]
		if a.AppID != c.appID || a.AP != c.ap {
			t.Errorf("%s/%s: app %s ap %s", c.req.Channel, c.req.Arch, a.AppID, a.AP)
		}
		fresh := c.req.Version == ""
		if fresh != (a.Version == "0.0.0.0" && len(a.Data) == 1 && a.UpdateCheck.SameVersionUpdate) {
			t.Errorf("fresh install %v but %+v", fresh, a)
		}
	}
	if _, err := (Request{Channel: "nightly", Arch: "x64"}).body(); err == nil {
		t.Error("accepted an unknown channel")
	}
	if _, err := (Request{Channel: Stable, Arch: "mips"}).body(); err == nil {
		t.Error("accepted an unknown architecture")
	}
	b, _ := Request{Channel: Stable, Arch: "x64", Version: "155.0.8059.85", Cached: []string{pkg48}, Target: "155."}.body()
	for _, want := range []string{`"cached_items":[{"sha256":"` + pkg48 + `"}]`, `"targetversionprefix":"155."`, `"rollback_allowed":true`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("body lacks %s: %s", want, b)
		}
	}
}

func TestCheckAgainstAServer(t *testing.T) {
	answer := fixture(t, "install-x64.txt")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.Header.Get("X-Goog-Update-Updater") != "updater-"+updaterVersion ||
			r.Header.Get("X-Goog-Update-AppId") != "{8a69d345-d564-463c-aff1-a69d9e530f96}" ||
			!strings.Contains(string(b), `"protocol":"4.0"`) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Write(answer)
	}))
	defer srv.Close()
	c := &Client{Endpoint: srv.URL}
	a, err := c.Check(context.Background(), Request{Channel: Stable, Arch: "x64"})
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := a.Pick(OpDownload, OpXZ, OpCRX3); !ok || p.Kind() != "xz" || a.Version != "156.0.8078.74" {
		t.Errorf("%+v", a)
	}
}

func TestCheckLive(t *testing.T) {
	if os.Getenv("CHROME_UPDATE_LIVE") == "" {
		t.Skip("set CHROME_UPDATE_LIVE=1 to ask Google's server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	xz := 0
	for _, ch := range Channels {
		for _, arch := range []string{"x86", "x64", "arm64"} {
			a, err := (&Client{}).Check(ctx, Request{Channel: ch, Arch: arch})
			if err != nil {
				t.Fatalf("%s %s: %v", ch, arch, err)
			}
			p, ok := a.Pick(OpDownload, OpXZ, OpCRX3)
			if !ok {
				t.Errorf("%s %s: no usable pipeline in %+v", ch, arch, a.Pipelines)
				continue
			}
			dl, _ := p.Download()
			t.Logf("%s %s: %s via %s, %d bytes", ch, arch, a.Version, p.Kind(), dl.Size)
			if p.Kind() == "xz" {
				xz++
			}
		}
	}
	// A build in a staged rollout may come as the full package only, as
	// Canary x64 159.0.8129.1 did for a tenth of the requests. With no xz
	// at all, the server no longer takes the request for its updater's.
	if xz == 0 {
		t.Error("no answer offers the xz stream")
	}
}
