package heain

// Models from the registry (Step 4.6e): an app that runs a model asks
// heain-model which version this instance should use (the production
// version, or a canary for a share of instances), downloads the artifact
// from heain-files on this node, checks its sha256, and records that hash
// in its AI reasoning records (Decision.ModelSHA256). Declare in the
// manifest:
//
//	uses:
//	  - {app: heain-model, capabilities: [model.resolve]}
//	  - {app: heain-files, capabilities: [files.read]}

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// The model registry contract.
const (
	ModelApp        = "heain-model"
	ModelResolveCap = "model.resolve"
	ModelResolve    = "/v1/resolve"
	FilesApp        = "heain-files"
	FilesReadCap    = "files.read"
)

// ModelRef is heain-model's answer: which version this instance uses.
type ModelRef struct {
	Model   string `json:"model"`
	Version string `json:"version"`
	State   string `json:"state"` // production | canary
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Runtime string `json:"runtime,omitempty"`
	File    string `json:"file"` // the heain-files id on this node
}

// ModelArtifact is a resolved, downloaded and verified model.
type ModelArtifact struct {
	ModelRef
	Path string // the verified file
}

var safeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// ResolveModel asks heain-model which version of name this instance uses.
func (a *App) ResolveModel(ctx context.Context, name string) (ModelRef, error) {
	var ref ModelRef
	_, err := a.Call(ctx, CallSpec{App: ModelApp, Capability: ModelResolveCap, Method: http.MethodPost, Path: ModelResolve,
		Body: map[string]any{"model": name}, Out: &ref})
	if err != nil {
		return ref, err
	}
	if len(ref.SHA256) != 64 || ref.File == "" || ref.Version == "" {
		return ref, fmt.Errorf("heain-sdk: heain-model gave an incomplete answer for %s", name)
	}
	return ref, nil
}

// Model resolves name, downloads it into dir (default: a "models" folder
// beside the SDK state) unless a verified copy is there, and checks its
// sha256. A file whose hash differs from the registry's is never used.
func (a *App) Model(ctx context.Context, name, dir string) (ModelArtifact, error) {
	ref, err := a.ResolveModel(ctx, name)
	if err != nil {
		return ModelArtifact{}, err
	}
	if dir == "" {
		dir = filepath.Join(a.opts.StateDir, "models")
		if a.opts.StateDir == "" {
			dir = filepath.Join(filepath.Dir(a.opts.Core.KeyFile), "models")
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ModelArtifact{}, err
	}
	path := filepath.Join(dir, safeName.ReplaceAllString(ref.Model+"-"+ref.Version+"-"+ref.SHA256[:16], "_"))
	if ok, _ := fileSHA256(path, ref.SHA256); ok {
		return ModelArtifact{ModelRef: ref, Path: path}, nil
	}
	tmp, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return ModelArtifact{}, err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	var n int64
	for i := 0; ; i++ {
		var ch struct {
			N    int    `json:"n"`
			Last bool   `json:"last"`
			Data string `json:"data_b64"`
		}
		if _, err := a.Call(ctx, CallSpec{App: FilesApp, Capability: FilesReadCap, Method: http.MethodGet,
			Path: "/v1/files/" + url.PathEscape(ref.File) + "/chunks/" + strconv.Itoa(i), Out: &ch}); err != nil {
			tmp.Close()
			return ModelArtifact{}, fmt.Errorf("heain-sdk: model %s chunk %d: %w", name, i, err)
		}
		b, err := base64.StdEncoding.DecodeString(ch.Data)
		if err != nil {
			tmp.Close()
			return ModelArtifact{}, err
		}
		if _, err := io.MultiWriter(tmp, h).Write(b); err != nil {
			tmp.Close()
			return ModelArtifact{}, err
		}
		n += int64(len(b))
		if ch.Last {
			break
		}
		if i > 1<<20 {
			tmp.Close()
			return ModelArtifact{}, errors.New("heain-sdk: too many chunks")
		}
	}
	if err := tmp.Close(); err != nil {
		return ModelArtifact{}, err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != ref.SHA256 || (ref.Size > 0 && n != ref.Size) {
		return ModelArtifact{}, fmt.Errorf("heain-sdk: model %s %s: the download does not match the registry (sha256 %s, %d bytes)", name, ref.Version, got, n)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return ModelArtifact{}, err
	}
	return ModelArtifact{ModelRef: ref, Path: path}, nil
}

func fileSHA256(path, want string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return hex.EncodeToString(h.Sum(nil)) == want, nil
}

// Broadcast is one P7 entry this node received from this app's instances
// elsewhere (core Step 4.6e).
type Broadcast struct {
	Seq         uint64         `json:"seq"`
	DiscoveryID string         `json:"discovery_id"`
	Form        string         `json:"form"` // RAW | DISTILLED | APPLY_RULE | RECEIVED_UPWARD
	Payload     map[string]any `json:"payload"`
	ReceivedAt  string         `json:"received_at"`
}

// Broadcasts reads what this node received of this app's P7 broadcasts,
// after seq (0: from the start of the node's in-memory log), at most limit
// (0: core's default). It returns the entries and the node's last seq.
func (a *App) Broadcasts(ctx context.Context, after uint64, limit int) ([]Broadcast, uint64, error) {
	q := url.Values{"after": {strconv.FormatUint(after, 10)}}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var out struct {
		Broadcasts []Broadcast `json:"broadcasts"`
		LastSeq    uint64      `json:"last_seq"`
	}
	_, err := a.Core.Do(ctx, http.MethodGet, "/v1/app/broadcasts?"+q.Encode(), nil, nil, &out)
	return out.Broadcasts, out.LastSeq, err
}
