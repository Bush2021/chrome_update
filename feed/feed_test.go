package feed

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Bush2021/chrome_update/omaha"
)

// The example from DSSE's protocol.md.
func TestPAE(t *testing.T) {
	got := string(pae("http://example.com/HelloWorld", []byte("hello world")))
	if want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"; got != want {
		t.Fatalf("pae = %q, want %q", got, want)
	}
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return p, k
}

func sample() *Feed {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	return &Feed{
		Schema:    Schema,
		Generated: now,
		Expires:   now.Add(7 * 24 * time.Hour),
		Soak:      Soak{PatchHours: 24, MilestoneHours: 168},
		Chrome: []Build{{
			Channel:   omaha.Stable,
			Arch:      "x64",
			Version:   "156.0.8078.74",
			Published: now.Add(-time.Hour),
			Pipelines: []omaha.Pipeline{{ID: "direct_xz", Ops: []omaha.Op{{Type: omaha.OpDownload, Size: 1, Out: "aa", URLs: []string{"https://dl.google.com/x"}}}}},
		}},
		Holds: []Hold{{
			Chrome:     Range{Min: "157"},
			ChromePlus: Range{Max: "1.19.2"},
			Reason:     map[string]string{"en": "Tabs don't close on double-click."},
			FixedBy:    "1.19.3",
		}},
	}
}

func TestSignAndOpen(t *testing.T) {
	pub, priv := newKey(t)
	raw, err := Sign(sample(), priv)
	if err != nil {
		t.Fatal(err)
	}
	f, err := Open(raw, pub)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := f.Build(omaha.Stable, "x64")
	if !ok || b.Version != "156.0.8078.74" || b.Pipelines[0].Ops[0].URLs[0] != "https://dl.google.com/x" {
		t.Fatalf("build = %+v, %v", b, ok)
	}
	if _, ok := f.Build(omaha.Beta, "x64"); ok {
		t.Fatal("found a beta build the feed doesn't list")
	}
	if h := f.Holds[0]; h.FixedBy != "1.19.3" || h.ChromePlus.Max != "1.19.2" {
		t.Fatalf("hold = %+v", h)
	}
}

func TestOpenRefuses(t *testing.T) {
	pub, priv := newKey(t)
	other, _ := newKey(t)
	raw, err := Sign(sample(), priv)
	if err != nil {
		t.Fatal(err)
	}
	edit := func(change func(*envelope)) []byte {
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatal(err)
		}
		change(&env)
		b, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, err := Open(raw, other); !errors.Is(err, ErrSignature) {
		t.Errorf("another key: %v", err)
	}
	if _, err := Open(raw); !errors.Is(err, ErrSignature) {
		t.Errorf("no key: %v", err)
	}
	tampered := edit(func(e *envelope) { e.Payload[len(e.Payload)-2] ^= 1 })
	if _, err := Open(tampered, pub); !errors.Is(err, ErrSignature) {
		t.Errorf("changed payload: %v", err)
	}
	retyped := edit(func(e *envelope) { e.PayloadType = "application/json" })
	if _, err := Open(retyped, pub); err == nil {
		t.Error("opened a feed under another payload type")
	}
	unsigned := edit(func(e *envelope) { e.Signatures = nil })
	if _, err := Open(unsigned, pub); !errors.Is(err, ErrSignature) {
		t.Errorf("no signature: %v", err)
	}

	f := sample()
	f.Schema = 2
	future, err := Sign(f, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(future, pub); err == nil {
		t.Error("opened a feed of a later schema")
	}
}

func TestKeyRotation(t *testing.T) {
	oldPub, oldPriv := newKey(t)
	newPub, newPriv := newKey(t)
	raw, err := Sign(sample(), oldPriv, newPriv)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []ed25519.PublicKey{oldPub, newPub} {
		if _, err := Open(raw, k); err != nil {
			t.Errorf("key %s: %v", KeyID(k), err)
		}
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Signatures) != 2 || env.Signatures[0].KeyID != KeyID(oldPub) || env.Signatures[1].KeyID != KeyID(newPub) {
		t.Fatalf("signatures = %+v", env.Signatures)
	}
}

func TestParseKeys(t *testing.T) {
	if _, err := ParsePublicKey("AAAA"); err == nil {
		t.Error("took a 3-byte public key")
	}
	if _, err := ParsePrivateKey("not base64!"); err == nil {
		t.Error("took a private key that isn't base64")
	}
	_, priv := newKey(t)
	if _, err := ParsePrivateKey(string(priv)); err == nil {
		t.Error("took raw key bytes")
	}
}
