// Package omaha asks Google's update server which Chrome build is current
// and how to download it: over protocol 4 for the pipelines Chrome's
// updater runs, or over protocol 3 for links to the full installer, which
// protocol 4 offers only inside a CRX3 package.
//
// Protocol 4 requests name Google's own updater: only such requests get
// the xz stream and the Zucchini and Puffin patches, and any other name
// gets only the full package. The protocol is described in Chromium's
// docs/updater/protocol_4.md.
package omaha

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
)

const (
	Endpoint          = "https://update.googleapis.com/service/update2/json"
	InstallerEndpoint = "https://tools.google.com/service/update2"
)

const (
	updaterName    = "updater"
	updaterVersion = "138.0.7194.0"
	osVersion      = "10.0.26100.1742"
)

type Channel string

const (
	Stable Channel = "stable"
	Beta   Channel = "beta"
	Dev    Channel = "dev"
	Canary Channel = "canary"
)

var Channels = []Channel{Stable, Beta, Dev, Canary}

const (
	appStable = "{8A69D345-D564-463C-AFF1-A69D9E530F96}"
	appCanary = "{4EA16AC7-FD5A-47C3-875B-DBF4A2008C20}"
)

func (c Channel) AppID() string {
	if c == Canary {
		return appCanary
	}
	return appStable
}

// ap returns the "additional parameters" naming the channel and arch.
func (c Channel) ap(arch string) string {
	switch c {
	case Beta:
		return "1.1-beta-arch_" + arch
	case Dev:
		return "2.0-dev-arch_" + arch
	case Canary:
		return arch + "-canary"
	}
	return arch + "-stable"
}

func (c Channel) Valid() bool {
	for _, k := range Channels {
		if c == k {
			return true
		}
	}
	return false
}

const (
	OpDownload = "download"
	OpXZ       = "xz"
	OpZucc     = "zucc"
	OpPuff     = "puff"
	OpCRX3     = "crx3"
)

type Request struct {
	Channel Channel
	Arch    string // "x86", "x64" or "arm64"
	// Version is the installed version, or "" for a fresh install.
	Version string
	// Cached lists the SHA-256 of packages the client keeps, which patches
	// can start from.
	Cached []string
	// Target pins the answer to a version prefix, older ones included.
	Target string
	// Accept lists the operations the client can perform; nil accepts
	// download, xz and crx3. Pipelines that need others are left out.
	Accept []string
	// Background marks a check the user did not ask for.
	Background bool
}

type Op struct {
	Type string `json:"type"`
	Size int64  `json:"size,omitempty"`
	// Out is the SHA-256 of the step's output (download, zucc, puff).
	Out string `json:"out,omitempty"`
	// In is the SHA-256 of the package a crx3 step installs.
	In string `json:"in,omitempty"`
	// Previous is the SHA-256 of the package a patch applies to.
	Previous string   `json:"previous,omitempty"`
	URLs     []string `json:"urls,omitempty"`
	// Path is the installer inside a crx3 package.
	Path string `json:"path,omitempty"`
}

type Pipeline struct {
	ID  string `json:"id"`
	Ops []Op   `json:"ops"`
}

// Kind returns the pipeline's strategy, the second field of its ID:
// "full", "xz", "zucc" or "puff".
func (p Pipeline) Kind() string {
	parts := strings.Split(p.ID, ":")
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}

func (p Pipeline) Download() (Op, bool) { return p.find(OpDownload) }

func (p Pipeline) Package() (Op, bool) { return p.find(OpCRX3) }

func (p Pipeline) Patch() (Op, bool) {
	if op, ok := p.find(OpZucc); ok {
		return op, true
	}
	return p.find(OpPuff)
}

func (p Pipeline) find(typ string) (Op, bool) {
	for _, op := range p.Ops {
		if op.Type == typ {
			return op, true
		}
	}
	return Op{}, false
}

type Answer struct {
	// Version is the build the pipelines install; empty when the client is
	// up to date.
	Version   string
	Pipelines []Pipeline
}

func (a *Answer) Pick(accept ...string) (Pipeline, bool) {
	ok := map[string]bool{}
	for _, t := range accept {
		ok[t] = true
	}
	for _, p := range a.Pipelines {
		usable := len(p.Ops) > 0
		for _, op := range p.Ops {
			if !ok[op.Type] {
				usable = false
				break
			}
		}
		if usable {
			return p, true
		}
	}
	return Pipeline{}, false
}

type Client struct {
	HTTP              *http.Client
	Endpoint          string
	InstallerEndpoint string
}

func uuid() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("{%X-%X-%X-%X-%X}", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

type hash struct {
	SHA256 string `json:"sha256"`
}

type updateCheck struct {
	SameVersionUpdate   bool   `json:"sameversionupdate,omitempty"`
	TargetVersionPrefix string `json:"targetversionprefix,omitempty"`
	RollbackAllowed     bool   `json:"rollback_allowed,omitempty"`
}

type data struct {
	Index string `json:"index"`
	Name  string `json:"name"`
}

type app struct {
	AP            string      `json:"ap"`
	AppID         string      `json:"appid"`
	Enabled       bool        `json:"enabled"`
	InstallSource string      `json:"installsource,omitempty"`
	InstallDate   int         `json:"installdate,omitempty"`
	Version       string      `json:"version"`
	UpdateCheck   updateCheck `json:"updatecheck"`
	CachedItems   []hash      `json:"cached_items,omitempty"`
	Data          []data      `json:"data,omitempty"`
}

type osInfo struct {
	Arch     string `json:"arch"`
	Platform string `json:"platform"`
	Version  string `json:"version"`
}

type request struct {
	OS             string `json:"@os"`
	Updater        string `json:"@updater"`
	AcceptFormat   string `json:"acceptformat"`
	Apps           []app  `json:"apps"`
	Arch           string `json:"arch"`
	Dedup          string `json:"dedup"`
	DomainJoined   bool   `json:"domainjoined"`
	IsMachine      bool   `json:"ismachine"`
	OSInfo         osInfo `json:"os"`
	ProdVersion    string `json:"prodversion"`
	Protocol       string `json:"protocol"`
	RequestID      string `json:"requestid"`
	SessionID      string `json:"sessionid"`
	UpdaterVersion string `json:"updaterversion"`
}

func (r Request) body() ([]byte, error) {
	if !r.Channel.Valid() {
		return nil, fmt.Errorf("unknown channel %q", r.Channel)
	}
	osArch := map[string]string{"x86": "x86", "x64": "x86_64", "arm64": "arm64"}[r.Arch]
	if osArch == "" {
		return nil, fmt.Errorf("unknown architecture %q", r.Arch)
	}
	accept := r.Accept
	if accept == nil {
		accept = []string{OpCRX3, OpDownload, OpXZ}
	}
	// A crx3 step runs the installer inside the package, so the server
	// answers error-inexpressible unless the client accepts "run".
	// Callers unpack that installer themselves instead, with package unpack.
	accept = append(slices.Clone(accept), "run")
	slices.Sort(accept)
	accept = slices.Compact(accept)
	a := app{
		AP:            r.Channel.ap(r.Arch),
		AppID:         strings.ToLower(r.Channel.AppID()),
		Enabled:       true,
		InstallSource: "ondemand",
		Version:       r.Version,
	}
	if r.Background {
		a.InstallSource = ""
	}
	if r.Version == "" {
		a.Version = "0.0.0.0"
		a.InstallSource = "taggedmi"
		a.InstallDate = -1
		a.Data = []data{{Index: "empty", Name: "install"}}
		a.UpdateCheck.SameVersionUpdate = true
	}
	if r.Target != "" {
		a.UpdateCheck.TargetVersionPrefix = r.Target
		a.UpdateCheck.RollbackAllowed = true
	}
	for _, h := range r.Cached {
		a.CachedItems = append(a.CachedItems, hash{SHA256: h})
	}
	return json.Marshal(struct {
		Request request `json:"request"`
	}{request{
		OS:             "win",
		Updater:        updaterName,
		AcceptFormat:   strings.Join(accept, ","),
		Apps:           []app{a},
		Arch:           r.Arch,
		Dedup:          "cr",
		OSInfo:         osInfo{Arch: osArch, Platform: "Windows", Version: osVersion},
		ProdVersion:    updaterVersion,
		Protocol:       "4.0",
		RequestID:      uuid(),
		SessionID:      uuid(),
		UpdaterVersion: updaterVersion,
	}})
}

type response struct {
	Response struct {
		Apps []struct {
			AppID       string `json:"appid"`
			Status      string `json:"status"`
			UpdateCheck struct {
				Status      string `json:"status"`
				NextVersion string `json:"nextversion"`
				Pipelines   []struct {
					ID         string `json:"pipeline_id"`
					Operations []struct {
						Type     string `json:"type"`
						Size     int64  `json:"size"`
						Out      hash   `json:"out"`
						In       hash   `json:"in"`
						Previous hash   `json:"previous"`
						Path     string `json:"path"`
						URLs     []struct {
							URL string `json:"url"`
						} `json:"urls"`
					} `json:"operations"`
				} `json:"pipelines"`
			} `json:"updatecheck"`
		} `json:"apps"`
	} `json:"response"`
}

var ErrStatus = errors.New("update server error")

func (c *Client) Check(ctx context.Context, req Request) (*Answer, error) {
	body, err := req.body()
	if err != nil {
		return nil, err
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = Endpoint
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	interactivity := "fg"
	if req.Background {
		interactivity = "bg"
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("User-Agent", "GoogleUpdater "+updaterVersion)
	hreq.Header.Set("X-Goog-Update-AppId", strings.ToLower(req.Channel.AppID()))
	hreq.Header.Set("X-Goog-Update-Interactivity", interactivity)
	hreq.Header.Set("X-Goog-Update-Updater", updaterName+"-"+updaterVersion)
	raw, err := c.do(hreq)
	if err != nil {
		return nil, err
	}
	return parse(raw)
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %s", ErrStatus, resp.Status)
	}
	return raw, nil
}

func parse(raw []byte) (*Answer, error) {
	// Protocol 4 guards its JSON against being run as a script.
	raw = bytes.TrimPrefix(raw, []byte(")]}'\n"))
	var r response
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("update server answer: %w", err)
	}
	if len(r.Response.Apps) == 0 {
		return nil, fmt.Errorf("%w: no app in the answer", ErrStatus)
	}
	a := r.Response.Apps[0]
	if a.Status != "ok" {
		return nil, fmt.Errorf("%w: app status %q", ErrStatus, a.Status)
	}
	switch a.UpdateCheck.Status {
	case "noupdate":
		return &Answer{}, nil
	case "ok":
	default:
		return nil, fmt.Errorf("%w: %q", ErrStatus, a.UpdateCheck.Status)
	}
	ans := &Answer{Version: a.UpdateCheck.NextVersion}
	for _, p := range a.UpdateCheck.Pipelines {
		pl := Pipeline{ID: p.ID}
		for _, o := range p.Operations {
			op := Op{Type: o.Type, Size: o.Size, Out: o.Out.SHA256, In: o.In.SHA256, Previous: o.Previous.SHA256, Path: o.Path}
			for _, u := range o.URLs {
				if strings.HasPrefix(u.URL, "https://") {
					op.URLs = append(op.URLs, u.URL)
				}
			}
			pl.Ops = append(pl.Ops, op)
		}
		ans.Pipelines = append(ans.Pipelines, pl)
	}
	if ans.Version == "" || len(ans.Pipelines) == 0 {
		return nil, fmt.Errorf("%w: an update without a version or pipelines", ErrStatus)
	}
	return ans, nil
}

// Installer is a build's full installer, as protocol 3 links it.
type Installer struct {
	Version string
	Name    string
	Size    int64
	SHA1    string
	SHA256  string
	// URLs are the server's links in its order, with the http ones that
	// Check drops.
	URLs []string
}

// installRequest asks for a fresh install, as Google Update 1.3.36 does.
const installRequest = `<?xml version="1.0" encoding="UTF-8"?>
<request protocol="3.0" updater="Omaha" updaterversion="1.3.36.372" shell_version="1.3.36.352" ismachine="0" sessionid="{11111111-1111-1111-1111-111111111111}" installsource="taggedmi" requestid="{11111111-1111-1111-1111-111111111111}" dedup="cr" domainjoined="0">
<hw physmemory="16" sse="1" sse2="1" sse3="1" ssse3="1" sse41="1" sse42="1" avx="1"/>
<os platform="win" version="` + osVersion + `" arch="%s"/>
<app version="" appid="%s" ap="%s">
<updatecheck/>
<data name="install" index="empty"/>
</app>
</request>`

func (c *Client) Installer(ctx context.Context, ch Channel, arch string) (*Installer, error) {
	if !ch.Valid() {
		return nil, fmt.Errorf("unknown channel %q", ch)
	}
	switch arch {
	case "x86", "x64", "arm64":
	default:
		return nil, fmt.Errorf("unknown architecture %q", arch)
	}
	endpoint := c.InstallerEndpoint
	if endpoint == "" {
		endpoint = InstallerEndpoint
	}
	body := fmt.Sprintf(installRequest, arch, ch.AppID(), ch.ap(arch))
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	raw, err := c.do(hreq)
	if err != nil {
		return nil, err
	}
	return parseInstaller(raw)
}

type installResponse struct {
	Apps []struct {
		Status      string `xml:"status,attr"`
		UpdateCheck struct {
			Status string `xml:"status,attr"`
			URLs   []struct {
				Codebase string `xml:"codebase,attr"`
			} `xml:"urls>url"`
			Manifest struct {
				Version  string `xml:"version,attr"`
				Packages []struct {
					Name   string `xml:"name,attr"`
					Size   int64  `xml:"size,attr"`
					SHA1   string `xml:"hash,attr"`
					SHA256 string `xml:"hash_sha256,attr"`
				} `xml:"packages>package"`
			} `xml:"manifest"`
		} `xml:"updatecheck"`
	} `xml:"app"`
}

func parseInstaller(raw []byte) (*Installer, error) {
	var r installResponse
	if err := xml.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("update server answer: %w", err)
	}
	if len(r.Apps) == 0 {
		return nil, fmt.Errorf("%w: no app in the answer", ErrStatus)
	}
	a := r.Apps[0]
	if a.Status != "ok" {
		return nil, fmt.Errorf("%w: app status %q", ErrStatus, a.Status)
	}
	if a.UpdateCheck.Status != "ok" {
		return nil, fmt.Errorf("%w: %q", ErrStatus, a.UpdateCheck.Status)
	}
	m := a.UpdateCheck.Manifest
	if m.Version == "" || len(m.Packages) == 0 {
		return nil, fmt.Errorf("%w: an installer without a version or package", ErrStatus)
	}
	p := m.Packages[0]
	sha1, err := base64.StdEncoding.DecodeString(p.SHA1)
	if err != nil {
		return nil, fmt.Errorf("update server answer: SHA-1 %q: %w", p.SHA1, err)
	}
	in := &Installer{Version: m.Version, Name: p.Name, Size: p.Size, SHA1: hex.EncodeToString(sha1), SHA256: p.SHA256}
	for _, u := range a.UpdateCheck.URLs {
		in.URLs = append(in.URLs, u.Codebase+p.Name)
	}
	return in, nil
}
