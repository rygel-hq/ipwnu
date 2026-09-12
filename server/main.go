// Command inventory-server receives system inventory reports over HTTP and
// records each one as a JSON file on disk.
//
// Endpoints:
//
//	GET  /healthz              liveness probe
//	POST /api/v1/inventory     accept an inventory report (X-API-Key required)
//
// Configuration (environment variables):
//
//	INVENTORY_ADDR       listen address            (default :8080)
//	INVENTORY_API_KEY    shared secret; REQUIRED   (server refuses to start without it)
//	INVENTORY_DATA_DIR   directory for reports     (default ./data)
//	INVENTORY_LOG_FILE   log file path             (default <data dir>/inventory.log)
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	defaultAddr    = ":8080"
	defaultDataDir = "data"
	defaultLogName = "inventory.log"
	maxBodyBytes   = 10 << 20 // 10 MiB
)

type config struct {
	addr    string
	apiKey  string
	dataDir string
	logFile string
}

func loadConfig() (config, error) {
	cfg := config{
		addr:    envOr("INVENTORY_ADDR", defaultAddr),
		apiKey:  strings.TrimSpace(os.Getenv("INVENTORY_API_KEY")),
		dataDir: envOr("INVENTORY_DATA_DIR", defaultDataDir),
	}
	if cfg.apiKey == "" {
		return config{}, errors.New(
			"INVENTORY_API_KEY must be set (refusing to start an unauthenticated endpoint)")
	}
	cfg.logFile = envOr("INVENTORY_LOG_FILE", filepath.Join(cfg.dataDir, defaultLogName))
	return cfg, nil
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

// inventoryReport is the accepted request shape. "os" is a free-form object so
// the collector can add platform-specific fields without breaking the server.
type inventoryReport struct {
	GeneratedAt   string            `json:"generated_at"`
	OS            map[string]any    `json:"os"`
	PublicSSHKeys map[string]string `json:"public_ssh_keys"`
}

func (r inventoryReport) validate() error {
	if len(r.OS) == 0 {
		return errors.New(`missing required "os" object`)
	}
	if hostname, ok := r.OS["hostname"]; ok {
		if _, isString := hostname.(string); !isString {
			return errors.New(`"os.hostname" must be a string`)
		}
	}
	return nil
}

type receipt struct {
	ID         string `json:"id"`
	ReceivedAt string `json:"received_at"`
	StoredPath string `json:"stored_path"`
}

type server struct {
	cfg    config
	logger *slog.Logger
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/api/v1/inventory", s.handleInventory)
	return s.withRecovery(s.withLogging(mux))
}

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "only GET is supported")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "only POST is supported")
		return
	}
	if !s.authorized(r) {
		s.logger.Warn("rejected request: invalid API key", "remote", r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "invalid or missing API key")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var report inventoryReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		var sizeErr *http.MaxBytesError
		if errors.As(err, &sizeErr) {
			writeError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("request body exceeds %d bytes (%d MiB)", maxBodyBytes, maxBodyBytes>>20))
			return
		}
		s.logger.Warn("rejected request: invalid JSON", "remote", r.RemoteAddr, "error", err)
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if err := report.validate(); err != nil {
		s.logger.Warn("rejected request: failed validation", "remote", r.RemoteAddr, "error", err)
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	rec, err := s.store(report)
	if err != nil {
		s.logger.Error("failed to store report", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to store report")
		return
	}

	hostname, _ := report.OS["hostname"].(string)
	s.logger.Info("stored inventory report",
		"id", rec.ID,
		"hostname", hostname,
		"ssh_key_count", len(report.PublicSSHKeys),
		"path", rec.StoredPath,
	)
	writeJSON(w, http.StatusCreated, rec)
}

func (s *server) authorized(r *http.Request) bool {
	provided := r.Header.Get("X-API-Key")
	if provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(s.cfg.apiKey)) == 1
}

func (s *server) store(report inventoryReport) (receipt, error) {
	now := time.Now().UTC()
	hostname, _ := report.OS["hostname"].(string)

	id, err := randomID()
	if err != nil {
		return receipt{}, fmt.Errorf("generate report id: %w", err)
	}
	if err := os.MkdirAll(s.cfg.dataDir, 0o755); err != nil {
		return receipt{}, fmt.Errorf("create data directory: %w", err)
	}

	filename := fmt.Sprintf("%s-%s-%s.json",
		now.Format("20060102T150405Z"), sanitize(hostname), id)
	fullPath := filepath.Join(s.cfg.dataDir, filename)

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return receipt{}, fmt.Errorf("encode report: %w", err)
	}
	if err := writeFileAtomic(fullPath, encoded); err != nil {
		return receipt{}, err
	}

	return receipt{
		ID:         id,
		ReceivedAt: now.Format(time.RFC3339Nano),
		StoredPath: fullPath,
	}, nil
}

func (s *server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

func (s *server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("panic while handling request",
					"panic", recovered, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"failed to encode response"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".inventory-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file to %s: %w", path, err)
	}
	return nil
}

func randomID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func sanitize(value string) string {
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func main() {
	if err := run(); err != nil {
		slog.Error("server stopped with error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	logger, logCloser, err := setupLogger(cfg.logFile)
	if err != nil {
		return err
	}
	defer func() {
		if err := logCloser.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to close log file: %v\n", err)
		}
	}()

	srv := &server{cfg: cfg, logger: logger}

	httpServer := &http.Server{
		Addr:              cfg.addr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.addr, "data_dir", cfg.dataDir)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http server: %w", err)
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received; draining connections")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	}
}

func setupLogger(logFile string) (*slog.Logger, io.Closer, error) {
	if err := os.MkdirAll(filepath.Dir(logFile), 0o755); err != nil {
		return nil, nil, fmt.Errorf("create log directory: %w", err)
	}
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("open log file %s: %w", logFile, err)
	}
	handler := slog.NewTextHandler(io.MultiWriter(os.Stderr, file),
		&slog.HandlerOptions{Level: slog.LevelInfo})
	return slog.New(handler), file, nil
}
