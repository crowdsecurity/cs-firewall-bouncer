package profiling

import (
	"compress/gzip"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/pprof/profile"
	"github.com/stretchr/testify/require"
)

func TestWriteHeapProfileGZ_CreatesValidFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "heap.pb.gz")
	require.NoError(t, writeHeapProfileGZ(path))

	_, err := os.Stat(path)
	require.NoError(t, err)

	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	gz, err := gzip.NewReader(f)
	require.NoError(t, err)
	defer gz.Close()

	_, err = profile.Parse(gz)
	require.NoError(t, err)
}

func TestWriteHeapProfileGZ_CreatesIntermediateDirs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "sub", "heap.pb.gz")
	require.NoError(t, writeHeapProfileGZ(path))

	_, err := os.Stat(path)
	require.NoError(t, err)
}

func TestStartPprofServerIfEnabled(t *testing.T) {
	t.Run("does nothing when disabled", func(t *testing.T) {
		t.Setenv(envProfilingEnabled, "")
		t.Setenv(envProfilingAddr, "")

		StartPprofServerIfEnabled()

		ln, err := net.Listen("tcp", "127.0.0.1:6060")
		require.NoError(t, err)
		require.NoError(t, ln.Close())
	})

	t.Run("default listen address", func(t *testing.T) {
		t.Setenv(envProfilingEnabled, "true")
		t.Setenv(envProfilingAddr, "")

		StartPprofServerIfEnabled()

		conn, err := net.DialTimeout("tcp", "127.0.0.1:6060", 2*time.Second)
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	})

	t.Run("custom listen address", func(t *testing.T) {
		free, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := free.Addr().String()
		require.NoError(t, free.Close())

		t.Setenv(envProfilingEnabled, "true")
		t.Setenv(envProfilingAddr, addr)

		StartPprofServerIfEnabled()

		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	})
}

func TestPprofServer_ServesHeapEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	registerPprofHandlers(mux)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := startOnListener(ln, mux)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + ln.Addr().String() + "/debug/pprof/heap")
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestParseHeapConfig_Defaults(t *testing.T) {
	t.Setenv(envHeapDumpThresholdMB, "")
	t.Setenv(envHeapPollInterval, "")
	t.Setenv(envHeapDumpCooldown, "")

	cfg := parseHeapConfig()
	require.Equal(t, defaultHeapThresholdMiB*1024*1024, cfg.thresholdBytes)
	require.Equal(t, defaultHeapPollInterval, cfg.pollInterval)
	require.Equal(t, defaultHeapCooldown, cfg.cooldown)
}

func TestParseHeapConfig_InvalidValuesFallBackToDefaults(t *testing.T) {
	t.Setenv(envHeapDumpThresholdMB, "not-a-number")
	t.Setenv(envHeapPollInterval, "30-smurfs")
	t.Setenv(envHeapDumpCooldown, "5-forever")

	cfg := parseHeapConfig()
	require.Equal(t, defaultHeapThresholdMiB*1024*1024, cfg.thresholdBytes)
	require.Equal(t, defaultHeapPollInterval, cfg.pollInterval)
	require.Equal(t, defaultHeapCooldown, cfg.cooldown)
}

func TestHeapWatcherLoop_DumpsWhenThresholdExceeded(t *testing.T) {
	dir := t.TempDir()
	hold := make([]byte, 4<<20)
	_ = hold

	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()

	fixed := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
	nowFn := func() time.Time { return fixed }

	go heapWatcherLoop(ctx, dir, 1, 10*time.Millisecond, time.Hour, nowFn)

	require.Eventually(t, func() bool {
		entries, err := os.ReadDir(dir)
		return err == nil && len(entries) > 0
	}, 600*time.Millisecond, 20*time.Millisecond, "expected a heap dump file")
}

func TestHeapWatcherLoop_CooldownPreventsRepeatDump(t *testing.T) {
	dir := t.TempDir()
	hold := make([]byte, 4<<20)
	_ = hold

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	t0 := time.Date(2022, 4, 5, 6, 7, 8, 0, time.UTC)
	nowFn := func() time.Time { return t0 }

	go heapWatcherLoop(ctx, dir, 1, 10*time.Millisecond, time.Hour, nowFn)

	require.Eventually(t, func() bool {
		entries, err := os.ReadDir(dir)
		return err == nil && len(entries) >= 1
	}, 250*time.Millisecond, 20*time.Millisecond)

	time.Sleep(100 * time.Millisecond)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestHeapWatcherLoop_ExitsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		heapWatcherLoop(ctx, dir, 1, time.Second, time.Hour, time.Now)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("heap watcher loop did not exit after context cancel")
	}

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestStartHeapWatcherIfEnabled_DoesNothingWithoutDir(t *testing.T) {
	t.Setenv(envHeapDumpDir, "")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	StartHeapWatcherIfEnabled(ctx)
}
