// Package profiling exposes an optional HTTP pprof server and heap auto-dump
// tooling, gated by CS_PROFILING_* environment variables.
//
// Pprof routes are registered only on a dedicated [http.ServeMux] (not via
// `_ "net/http/pprof"`), so handlers are not attached to [http.DefaultServeMux]
// alongside the Prometheus `/metrics` server.
package profiling

import (
	"compress/gzip"
	"context"
	"fmt"
	"net"
	"net/http"
	urlpprof "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	runtimepprof "runtime/pprof"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	envProfilingEnabled            = "CS_PROFILING_ENABLED"
	envProfilingAddr               = "CS_PROFILING_ADDR"
	envHeapDumpDir                 = "CS_PROFILING_HEAP_DUMP_DIR"
	envHeapDumpThresholdMB         = "CS_PROFILING_HEAP_DUMP_THRESHOLD_MB"
	envHeapPollInterval            = "CS_PROFILING_HEAP_POLL_INTERVAL"
	envHeapDumpCooldown            = "CS_PROFILING_HEAP_DUMP_COOLDOWN"
	defaultProfilingAddr           = ":6060"
	defaultHeapThresholdMiB uint64 = 200
	defaultHeapPollInterval        = 30 * time.Second
	defaultHeapCooldown            = 5 * time.Minute
)

func registerPprofHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/cmdline", urlpprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", urlpprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", urlpprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", urlpprof.Trace)
	mux.HandleFunc("/debug/pprof/", urlpprof.Index)
}

type heapConfig struct {
	thresholdBytes uint64
	pollInterval   time.Duration
	cooldown       time.Duration
}

func parseHeapConfig() heapConfig {
	var thresholdMiB uint64 = defaultHeapThresholdMiB
	if v := strings.TrimSpace(os.Getenv(envHeapDumpThresholdMB)); v != "" {
		if parsed, err := strconv.ParseUint(v, 10, 64); err == nil && parsed > 0 {
			thresholdMiB = parsed
		} else if err != nil {
			log.Warningf("heap watcher: invalid %s=%q (using default %d MiB): %v", envHeapDumpThresholdMB, v, defaultHeapThresholdMiB, err)
		}
	}
	thresholdBytes := thresholdMiB * 1024 * 1024

	pollInterval := defaultHeapPollInterval
	if v := strings.TrimSpace(os.Getenv(envHeapPollInterval)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			pollInterval = d
		} else if err != nil {
			log.Warningf("heap watcher: invalid %s=%q (using default %s): %v", envHeapPollInterval, v, defaultHeapPollInterval, err)
		}
	}

	cooldown := defaultHeapCooldown
	if v := strings.TrimSpace(os.Getenv(envHeapDumpCooldown)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cooldown = d
		} else if err != nil {
			log.Warningf("heap watcher: invalid %s=%q (using default %s): %v", envHeapDumpCooldown, v, defaultHeapCooldown, err)
		}
	}

	return heapConfig{
		thresholdBytes: thresholdBytes,
		pollInterval:   pollInterval,
		cooldown:       cooldown,
	}
}

// Start binds a dedicated HTTP server for /debug/pprof/* on addr and runs it in
// a background goroutine. Listen errors are logged and do not stop the
// process. Returns nil after the listener is accepted (or after logging a bind
// failure).
func Start(addr string) error {
	mux := http.NewServeMux()
	registerPprofHandlers(mux)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Errorf("pprof server: failed to listen on %s: %v", addr, err)
		return nil
	}

	startOnListener(ln, mux)
	return nil
}

func startOnListener(ln net.Listener, mux *http.ServeMux) *http.Server {
	log.Infof("pprof server listening on %s (set GODEBUG=gctrace=1 in the environment for GC trace output from the runtime)", ln.Addr().String())

	srv := &http.Server{Handler: mux}
	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			log.Errorf("pprof server: %v", serveErr)
		}
	}()
	return srv
}

// StartPprofServerIfEnabled starts the pprof server when CS_PROFILING_ENABLED is "true".
func StartPprofServerIfEnabled() {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv(envProfilingEnabled)), "true") {
		return
	}
	addr := strings.TrimSpace(os.Getenv(envProfilingAddr))
	if addr == "" {
		addr = defaultProfilingAddr
	}
	_ = Start(addr)
}

// StartHeapWatcher runs a poll loop that writes heap profiles when HeapAlloc crosses
// the configured threshold (subject to cooldown). Reads configuration from the
// environment on each invocation; does nothing when CS_PROFILING_HEAP_DUMP_DIR is empty.
func StartHeapWatcher(ctx context.Context) {
	dir := strings.TrimSpace(os.Getenv(envHeapDumpDir))
	if dir == "" {
		return
	}

	cfg := parseHeapConfig()
	go heapWatcherLoop(ctx, dir, cfg.thresholdBytes, cfg.pollInterval, cfg.cooldown, nil)
}

func heapWatcherLoop(ctx context.Context, dir string, thresholdBytes uint64, pollInterval, cooldown time.Duration, nowFn func() time.Time) {
	if nowFn == nil {
		nowFn = time.Now
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var lastDump time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)

			if ms.HeapAlloc < thresholdBytes {
				continue
			}
			if !lastDump.IsZero() && nowFn().Sub(lastDump) < cooldown {
				continue
			}

			ts := strings.ReplaceAll(nowFn().UTC().Format(time.RFC3339), ":", "-")
			filename := fmt.Sprintf("heap-%s.pb.gz", ts)
			fullPath := filepath.Join(dir, filename)

			if err := writeHeapProfileGZ(fullPath); err != nil {
				log.Errorf("heap watcher: failed to write heap profile to %s: %v", fullPath, err)
				continue
			}

			lastDump = nowFn()
			log.Infof("heap watcher: wrote heap profile to %s (HeapAlloc=%d bytes, threshold=%d bytes)", fullPath, ms.HeapAlloc, thresholdBytes)
		}
	}
}

func writeHeapProfileGZ(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	if err := runtimepprof.WriteHeapProfile(gw); err != nil {
		_ = gw.Close()
		return err
	}
	return gw.Close()
}

// StartHeapWatcherIfEnabled starts the heap watcher when CS_PROFILING_HEAP_DUMP_DIR is non-empty.
func StartHeapWatcherIfEnabled(ctx context.Context) {
	if strings.TrimSpace(os.Getenv(envHeapDumpDir)) == "" {
		return
	}
	StartHeapWatcher(ctx)
}
