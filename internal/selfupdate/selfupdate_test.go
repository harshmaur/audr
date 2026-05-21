package selfupdate

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckReportsNewerLatest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/harshmaur/audr/releases/latest" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name":     "v0.15.0",
			"html_url":     "https://example.invalid/v0.15.0",
			"published_at": "2026-05-21T00:00:00Z",
			"draft":        false,
			"prerelease":   false,
		})
	}))
	defer srv.Close()
	latest, newer, err := Check(context.Background(), Options{CurrentVersion: "v0.14.3", APIBaseURL: srv.URL, Client: srv.Client()})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if latest.Version != "v0.15.0" || !newer {
		t.Fatalf("latest=%+v newer=%v, want v0.15.0 newer", latest, newer)
	}
}

func TestApplyInstallsVerifiedTarball(t *testing.T) {
	tmp := t.TempDir()
	version := "v0.15.0"
	artifact := "audr-v0.15.0-linux-amd64.tar.gz"
	tarball := buildTestTarball(t, tmp, version, "new audr binary")
	sum := sha256Of(t, tarball)
	installPath := filepath.Join(tmp, "bin", "audr")
	if err := os.MkdirAll(filepath.Dir(installPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installPath, []byte("old audr binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Base(r.URL.Path) {
		case artifact:
			http.ServeFile(w, r, tarball)
		case "SHA256SUMS":
			_, _ = w.Write([]byte(sum + "  " + artifact + "\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	res, err := Apply(context.Background(), Options{
		CurrentVersion:  "v0.14.3",
		Version:         version,
		InstallPath:     installPath,
		OS:              "linux",
		Arch:            "amd64",
		DownloadBaseURL: srv.URL,
		Client:          srv.Client(),
		TempDir:         tmp,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Updated || !res.Verify.Pass() {
		t.Fatalf("result=%+v, want updated verified", res)
	}
	got, err := os.ReadFile(installPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new audr binary" {
		t.Fatalf("installed content = %q", got)
	}
	old, err := os.ReadFile(installPath + ".old")
	if err != nil {
		t.Fatal(err)
	}
	if string(old) != "old audr binary" {
		t.Fatalf("backup content = %q", old)
	}
}

func TestApplyRejectsChecksumMismatch(t *testing.T) {
	tmp := t.TempDir()
	version := "v0.15.0"
	artifact := "audr-v0.15.0-linux-amd64.tar.gz"
	tarball := buildTestTarball(t, tmp, version, "new audr binary")
	installPath := filepath.Join(tmp, "audr")
	if err := os.WriteFile(installPath, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Base(r.URL.Path) {
		case artifact:
			http.ServeFile(w, r, tarball)
		case "SHA256SUMS":
			_, _ = w.Write([]byte("0000000000000000000000000000000000000000000000000000000000000000  " + artifact + "\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	_, err := Apply(context.Background(), Options{CurrentVersion: "v0.14.3", Version: version, InstallPath: installPath, OS: "linux", Arch: "amd64", DownloadBaseURL: srv.URL, Client: srv.Client(), TempDir: tmp})
	if err == nil {
		t.Fatal("Apply succeeded with checksum mismatch")
	}
	got, _ := os.ReadFile(installPath)
	if string(got) != "old" {
		t.Fatalf("old binary changed after failed update: %q", got)
	}
}

func buildTestTarball(t *testing.T, dir, version, content string) string {
	t.Helper()
	path := filepath.Join(dir, "audr-"+version+"-linux-amd64.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	name := "audr-" + version + "-linux-amd64/audr"
	body := []byte(content)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func sha256Of(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
