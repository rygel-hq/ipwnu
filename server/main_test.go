package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func fill(t *testing.T, dir, name string, size int64) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatalf("truncate %s: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
}

func sampleReport() inventoryReport {
	return inventoryReport{
		GeneratedAt:   "2026-09-12T00:00:00Z",
		OS:            map[string]any{"hostname": "test-host"},
		PublicSSHKeys: map[string]string{"id_rsa.pub": "ssh-rsa AAAA"},
	}
}

func TestDirSize(t *testing.T) {
	dir := t.TempDir()
	fill(t, dir, "a.json", 1000)
	fill(t, dir, "b.json", 500)

	got, err := dirSize(dir)
	if err != nil {
		t.Fatalf("dirSize: %v", err)
	}
	if got != 1500 {
		t.Fatalf("dirSize = %d, want 1500", got)
	}
}

func TestStoreSucceedsUnderLimit(t *testing.T) {
	dir := t.TempDir()
	s := &server{cfg: config{dataDir: dir}, logger: testLogger()}

	rec, err := s.store(sampleReport())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if rec.ID == "" {
		t.Fatal("store returned empty id")
	}
}

func TestStoreRejectsWhenDataDirFull(t *testing.T) {
	dir := t.TempDir()
	fill(t, dir, "big.json", maxDataDirBytes-10)

	s := &server{cfg: config{dataDir: dir}, logger: testLogger()}
	_, err := s.store(sampleReport())
	if !errors.Is(err, errDataDirFull) {
		t.Fatalf("store error = %v, want errDataDirFull", err)
	}
}

func TestHandleInventoryReturns507WhenFull(t *testing.T) {
	dir := t.TempDir()
	fill(t, dir, "big.json", maxDataDirBytes)

	s := &server{cfg: config{dataDir: dir, apiKey: "secret"}, logger: testLogger()}
	body, err := json.Marshal(sampleReport())
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/inventory", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "secret")
	w := httptest.NewRecorder()

	s.handleInventory(w, req)

	if w.Code != http.StatusInsufficientStorage {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInsufficientStorage)
	}
}
