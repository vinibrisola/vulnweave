package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
)

func TestMavenCandidateExistsUsesExactPomAndCaches(t *testing.T) {
	oldBase := mavenCentralBaseURL
	oldClient := httpClient
	t.Cleanup(func() {
		mavenCentralBaseURL = oldBase
		httpClient = oldClient
	})
	t.Setenv("VULNWEAVE_CACHE_DIR", t.TempDir())

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Path != "/org/example/demo/2.25.5/demo-2.25.5.pom" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<project/>"))
	}))
	defer srv.Close()
	mavenCentralBaseURL = srv.URL
	httpClient = srv.Client()

	first, err := candidateExists("Maven", "org.example:demo", "2.25.5")
	if err != nil {
		t.Fatalf("first check failed: %v", err)
	}
	if !first.Exists || first.Status != "confirmed" || first.FromCache {
		t.Fatalf("unexpected first result: %#v", first)
	}

	second, err := candidateExists("Maven", "org.example:demo", "2.25.5")
	if err != nil {
		t.Fatalf("second check failed: %v", err)
	}
	if !second.Exists || second.Status != "confirmed" || !second.FromCache {
		t.Fatalf("unexpected cached result: %#v", second)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected one network request, got %d", got)
	}
}

func TestMavenCandidate429IsInconclusiveAndCached(t *testing.T) {
	oldBase := mavenCentralBaseURL
	oldClient := httpClient
	t.Cleanup(func() {
		mavenCentralBaseURL = oldBase
		httpClient = oldClient
	})
	t.Setenv("VULNWEAVE_CACHE_DIR", t.TempDir())

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Retry-After", "120")
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	mavenCentralBaseURL = srv.URL
	httpClient = srv.Client()

	first, err := candidateExists("Maven", "org.example:demo", "2.25.5")
	if err != nil {
		t.Fatalf("429 must be represented as evidence state, not hard error: %v", err)
	}
	if first.Status != "inconclusive" || first.HTTPStatus != http.StatusTooManyRequests || first.Exists {
		t.Fatalf("429 collapsed into wrong state: %#v", first)
	}
	if first.RetryAfterSeconds < 120 {
		t.Fatalf("Retry-After was not preserved: %#v", first)
	}

	second, err := candidateExists("Maven", "org.example:demo", "2.25.5")
	if err != nil {
		t.Fatalf("cached 429 failed: %v", err)
	}
	if second.Status != "inconclusive" || !second.FromCache {
		t.Fatalf("expected cached inconclusive result: %#v", second)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("repeated validation must not hit Maven Central during cooldown; got %d requests", got)
	}
}

func TestMavenCandidateNotFoundIsDistinctFrom429(t *testing.T) {
	oldBase := mavenCentralBaseURL
	oldClient := httpClient
	t.Cleanup(func() {
		mavenCentralBaseURL = oldBase
		httpClient = oldClient
	})
	t.Setenv("VULNWEAVE_CACHE_DIR", t.TempDir())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	mavenCentralBaseURL = srv.URL
	httpClient = srv.Client()

	got, err := candidateExists("Maven", "org.example:demo", "9.9.9")
	if err != nil {
		t.Fatalf("not-found check failed: %v", err)
	}
	if got.Status != "not_found" || got.Exists || got.HTTPStatus != http.StatusNotFound {
		t.Fatalf("404 must be a definitive not-found state: %#v", got)
	}
}

func TestRepositoryCacheUsesExtensionProvidedDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VULNWEAVE_CACHE_DIR", dir)
	p := repositoryCachePath("Maven", "g:a", "1.0.0")
	if p == "" || len(p) <= len(dir) || p[:len(dir)] != dir {
		t.Fatalf("cache path must live below VULNWEAVE_CACHE_DIR: %q", p)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("temp cache directory disappeared: %v", err)
	}
}
