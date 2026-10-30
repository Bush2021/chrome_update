// Package feed is the signed list of Chrome builds, soak periods and
// compatibility holds that chrome_installer's workflow publishes and Pitstop
// reads instead of asking Google's update server.
//
// A feed travels in a DSSE envelope signed with Ed25519, so any mirror can
// serve it. During a key rotation the envelope carries a signature from the
// old key and one from the new.
package feed

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Bush2021/chrome_update/omaha"
)

const (
	Schema      = 1
	PayloadType = "application/vnd.pitstop.feed+json"
)

type Feed struct {
	Schema    int       `json:"schema"`
	Generated time.Time `json:"generated"`
	// Expires bounds how long a client trusts the feed, so a mirror that
	// keeps serving an old one can't hide a newer hold for long.
	Expires time.Time `json:"expires"`
	Soak    Soak      `json:"soak"`
	Chrome  []Build   `json:"chrome"`
	Holds   []Hold    `json:"holds,omitempty"`
}

// Soak is how long a Stable build waits after the workflow first sees it
// before it installs on its own.
type Soak struct {
	PatchHours     int `json:"patchHours"`
	MilestoneHours int `json:"milestoneHours"`
}

type Build struct {
	Channel omaha.Channel `json:"channel"`
	Arch    string        `json:"arch"`
	Version string        `json:"version"`
	// Published is when the workflow first saw this version.
	Published time.Time        `json:"published"`
	Pipelines []omaha.Pipeline `json:"pipelines"`
}

// Range holds the versions from Min to Max, both included. An empty bound
// is open.
type Range struct {
	Min string `json:"min,omitempty"`
	Max string `json:"max,omitempty"`
}

// Hold keeps the Chrome builds in a range from installing on their own on
// an install whose Chrome++ is in a range.
type Hold struct {
	Chrome     Range `json:"chrome"`
	ChromePlus Range `json:"chromePlus"`
	// Reason is keyed by language: "en" and "zh-Hans".
	Reason map[string]string `json:"reason"`
	// FixedBy is the Chrome++ release that works with the held builds.
	FixedBy string `json:"fixedBy,omitempty"`
}

func (f *Feed) Build(channel omaha.Channel, arch string) (Build, bool) {
	for _, b := range f.Chrome {
		if b.Channel == channel && b.Arch == arch {
			return b, true
		}
	}
	return Build{}, false
}

type envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     []byte      `json:"payload"`
	Signatures  []signature `json:"signatures"`
}

type signature struct {
	KeyID string `json:"keyid"`
	Sig   []byte `json:"sig"`
}

// pae is DSSE's pre-authentication encoding. Signing it instead of the
// payload alone binds the payload type into the signature.
func pae(typ string, body []byte) []byte {
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(typ), typ, len(body), body)
}

func Sign(f *Feed, keys ...ed25519.PrivateKey) ([]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("feed: no signing key")
	}
	body, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	env := envelope{PayloadType: PayloadType, Payload: body}
	msg := pae(PayloadType, body)
	for _, k := range keys {
		env.Signatures = append(env.Signatures, signature{
			KeyID: KeyID(k.Public().(ed25519.PublicKey)),
			Sig:   ed25519.Sign(k, msg),
		})
	}
	return json.Marshal(env)
}

var ErrSignature = errors.New("feed: no valid signature")

// Open checks that one of keys signed the envelope and returns its feed.
func Open(raw []byte, keys ...ed25519.PublicKey) (*Feed, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("feed: %w", err)
	}
	if env.PayloadType != PayloadType {
		return nil, fmt.Errorf("feed: payload type %q", env.PayloadType)
	}
	if !signed(env, keys) {
		return nil, ErrSignature
	}
	var f Feed
	if err := json.Unmarshal(env.Payload, &f); err != nil {
		return nil, fmt.Errorf("feed: %w", err)
	}
	if f.Schema != Schema {
		return nil, fmt.Errorf("feed: schema %d, want %d", f.Schema, Schema)
	}
	return &f, nil
}

// signed tries every key against every signature: a key ID is only a hint,
// since nothing signs it.
func signed(env envelope, keys []ed25519.PublicKey) bool {
	msg := pae(env.PayloadType, env.Payload)
	for _, s := range env.Signatures {
		for _, k := range keys {
			if ed25519.Verify(k, msg, s.Sig) {
				return true
			}
		}
	}
	return false
}

// KeyID names a public key: the first 8 bytes of its SHA-256, in hex.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// GenerateKey returns a new key pair in the forms ParsePublicKey and
// ParsePrivateKey read.
func GenerateKey() (public, private string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv.Seed()), nil
}

func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("feed: public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("feed: public key of %d bytes", len(b))
	}
	return ed25519.PublicKey(b), nil
}

// ParsePrivateKey reads a private key's 32-byte seed.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("feed: private key isn't base64")
	}
	if len(b) != ed25519.SeedSize {
		return nil, fmt.Errorf("feed: private key of %d bytes", len(b))
	}
	return ed25519.NewKeyFromSeed(b), nil
}
