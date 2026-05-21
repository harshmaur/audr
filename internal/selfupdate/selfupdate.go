// Package selfupdate downloads, verifies, and installs AUDR release binaries.
package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/harshmaur/audr/internal/updater"
	"github.com/harshmaur/audr/internal/verify"
)

const (
	defaultOwner = "harshmaur"
	defaultRepo  = "audr"
)

// Options controls an update check/install run.
type Options struct {
	CurrentVersion  string
	Version         string // empty or "latest" means GitHub latest stable release
	Owner           string
	Repo            string
	InstallPath     string
	OS              string
	Arch            string
	Client          *http.Client
	APIBaseURL      string // test override; default https://api.github.com
	DownloadBaseURL string // test override; default https://github.com/<owner>/<repo>/releases/download
	TempDir         string
}

// Latest describes the release selected for update.
type Latest struct {
	Version     string
	URL         string
	PublishedAt string
}

// Result is the outcome from Apply.
type Result struct {
	CurrentVersion string
	TargetVersion  string
	InstallPath    string
	Artifact       string
	DownloadedTo   string
	BackupPath     string
	Verify         verify.Result
	Updated        bool
	AlreadyCurrent bool
}

// ResolveLatest returns the latest non-prerelease, non-draft GitHub release.
func ResolveLatest(ctx context.Context, opts Options) (Latest, error) {
	opts = normalize(opts)
	url := strings.TrimRight(opts.APIBaseURL, "/") + fmt.Sprintf("/repos/%s/%s/releases/latest", opts.Owner, opts.Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Latest{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "audr")
	resp, err := opts.Client.Do(req)
	if err != nil {
		return Latest{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Latest{}, errors.New("no published AUDR releases found")
	}
	if resp.StatusCode != http.StatusOK {
		return Latest{}, fmt.Errorf("latest release: HTTP %d", resp.StatusCode)
	}
	var rel struct {
		TagName     string `json:"tag_name"`
		HTMLURL     string `json:"html_url"`
		PublishedAt string `json:"published_at"`
		Draft       bool   `json:"draft"`
		Prerelease  bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return Latest{}, err
	}
	if rel.Draft || rel.Prerelease || rel.TagName == "" {
		return Latest{}, errors.New("latest release is not installable")
	}
	return Latest{Version: rel.TagName, URL: rel.HTMLURL, PublishedAt: rel.PublishedAt}, nil
}

// Check reports the selected target release without installing it.
func Check(ctx context.Context, opts Options) (Latest, bool, error) {
	opts = normalize(opts)
	latest, err := selectedRelease(ctx, opts)
	if err != nil {
		return Latest{}, false, err
	}
	return latest, updater.IsNewer(opts.CurrentVersion, latest.Version), nil
}

// Apply downloads, verifies, extracts, and installs the selected AUDR release.
func Apply(ctx context.Context, opts Options) (Result, error) {
	opts = normalize(opts)
	if opts.InstallPath == "" {
		return Result{}, errors.New("selfupdate: InstallPath is required")
	}
	latest, err := selectedRelease(ctx, opts)
	if err != nil {
		return Result{}, err
	}
	res := Result{CurrentVersion: opts.CurrentVersion, TargetVersion: latest.Version, InstallPath: opts.InstallPath}
	if !updater.IsNewer(opts.CurrentVersion, latest.Version) && (opts.Version == "" || opts.Version == "latest") {
		res.AlreadyCurrent = true
		return res, nil
	}
	artifact, err := artifactName(latest.Version, opts.OS, opts.Arch)
	if err != nil {
		return res, err
	}
	res.Artifact = artifact
	work, err := os.MkdirTemp(opts.TempDir, "audr-update-*")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(work)
	assetBase := strings.TrimRight(opts.DownloadBaseURL, "/") + "/" + latest.Version
	artifactPath := filepath.Join(work, artifact)
	if err := downloadRequired(ctx, opts.Client, assetBase+"/"+artifact, artifactPath); err != nil {
		return res, err
	}
	if err := downloadRequired(ctx, opts.Client, assetBase+"/SHA256SUMS", filepath.Join(work, "SHA256SUMS")); err != nil {
		return res, err
	}
	_ = downloadOptional(ctx, opts.Client, assetBase+"/"+artifact+".sig", artifactPath+".sig")
	_ = downloadOptional(ctx, opts.Client, assetBase+"/"+artifact+".crt", artifactPath+".crt")
	vr, err := verify.Verify(artifactPath, verify.Options{})
	res.Verify = vr
	res.DownloadedTo = artifactPath
	if err != nil {
		return res, err
	}
	if !vr.Pass() {
		return res, errors.New("release artifact verification failed")
	}
	staged, err := extractBinary(artifactPath, work, opts.OS)
	if err != nil {
		return res, err
	}
	backup, err := installBinary(staged, opts.InstallPath)
	res.BackupPath = backup
	if err != nil {
		return res, err
	}
	res.Updated = true
	return res, nil
}

func normalize(opts Options) Options {
	if opts.Owner == "" {
		opts.Owner = defaultOwner
	}
	if opts.Repo == "" {
		opts.Repo = defaultRepo
	}
	if opts.OS == "" {
		opts.OS = runtime.GOOS
	}
	if opts.Arch == "" {
		opts.Arch = runtime.GOARCH
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 30 * time.Second}
	}
	if opts.APIBaseURL == "" {
		opts.APIBaseURL = "https://api.github.com"
	}
	if opts.DownloadBaseURL == "" {
		opts.DownloadBaseURL = fmt.Sprintf("https://github.com/%s/%s/releases/download", opts.Owner, opts.Repo)
	}
	if opts.Version == "" {
		opts.Version = "latest"
	}
	return opts
}

func selectedRelease(ctx context.Context, opts Options) (Latest, error) {
	if opts.Version != "" && opts.Version != "latest" {
		return Latest{Version: opts.Version, URL: strings.TrimRight(opts.DownloadBaseURL, "/") + "/" + opts.Version}, nil
	}
	return ResolveLatest(ctx, opts)
}

func artifactName(version, goos, goarch string) (string, error) {
	arch := goarch
	switch goarch {
	case "amd64", "arm64":
	default:
		return "", fmt.Errorf("unsupported arch: %s", goarch)
	}
	switch goos {
	case "linux", "darwin":
		return fmt.Sprintf("audr-%s-%s-%s.tar.gz", version, goos, arch), nil
	case "windows":
		return fmt.Sprintf("audr-%s-windows-%s.zip", version, arch), nil
	default:
		return "", fmt.Errorf("unsupported OS: %s", goos)
	}
}

func downloadRequired(ctx context.Context, client *http.Client, url, dst string) error {
	if err := download(ctx, client, url, dst); err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	return nil
}

func downloadOptional(ctx context.Context, client *http.Client, url, dst string) error {
	return download(ctx, client, url, dst)
}

func download(ctx context.Context, client *http.Client, url, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "audr")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, io.LimitReader(resp.Body, 200<<20))
	return err
}

func extractBinary(archivePath, work, goos string) (string, error) {
	if goos == "windows" {
		return extractZipBinary(archivePath, work)
	}
	return extractTarBinary(archivePath, work)
}

func extractTarBinary(path, work string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if h.FileInfo().IsDir() || filepath.Base(h.Name) != "audr" {
			continue
		}
		out := filepath.Join(work, "audr.staged")
		of, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
		if err != nil {
			return "", err
		}
		_, copyErr := io.Copy(of, tr)
		closeErr := of.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		return out, nil
	}
	return "", errors.New("audr binary not found in tarball")
}

func extractZipBinary(path, work string) (string, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer zr.Close()
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() || filepath.Base(zf.Name) != "audr.exe" {
			continue
		}
		r, err := zf.Open()
		if err != nil {
			return "", err
		}
		out := filepath.Join(work, "audr.exe.staged")
		of, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
		if err != nil {
			_ = r.Close()
			return "", err
		}
		_, copyErr := io.Copy(of, r)
		closeErr := of.Close()
		_ = r.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		return out, nil
	}
	return "", errors.New("audr.exe not found in zip")
}

func installBinary(staged, target string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return "", err
	}
	backup := target + ".old"
	_ = os.Remove(backup)
	if _, err := os.Stat(target); err == nil {
		if err := os.Rename(target, backup); err != nil {
			return "", fmt.Errorf("backup existing binary: %w", err)
		}
	}
	if err := os.Rename(staged, target); err != nil {
		if _, stErr := os.Stat(backup); stErr == nil {
			_ = os.Rename(backup, target)
		}
		return backup, fmt.Errorf("install new binary: %w", err)
	}
	_ = os.Chmod(target, 0755)
	return backup, nil
}
