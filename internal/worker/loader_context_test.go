package worker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoaderCancellationPrecedesArtifactAccess(t *testing.T) {
	for _, expired := range []bool{false, true} {
		var ctx context.Context
		var cancel context.CancelFunc
		want := context.Canceled
		if expired {
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			want = context.DeadlineExceeded
		} else {
			ctx, cancel = context.WithCancel(context.Background())
			cancel()
		}
		defer cancel()
		// Neither missing paths nor an invalid key can mask a pre-cancelled load.
		if binary, err := LoadContext(ctx, "missing-worker", "missing-manifest", nil, true); binary != nil || !errors.Is(err, want) {
			t.Fatalf("load did not preserve cancellation: %v %v", binary, err)
		}
		dest := filepath.Join(t.TempDir(), "must-not-create")
		if err := writeNewContext(ctx, dest, []byte("fixture"), 0700); !errors.Is(err, want) {
			t.Fatalf("write cancellation: %v", err)
		}
		if _, err := os.Lstat(dest); !os.IsNotExist(err) {
			t.Fatalf("cancelled write created artifact: %v", err)
		}
		if _, err := snapshotDependencyContext(ctx, "missing-dll", dest, Dependency{}); !errors.Is(err, want) {
			t.Fatalf("dependency cancellation: %v", err)
		}
		if _, err := os.Lstat(dest); !os.IsNotExist(err) {
			t.Fatalf("cancelled dependency created artifact: %v", err)
		}
	}
}

type trackedLoaderReader struct {
	data                  []byte
	reads, largestRequest int
	cancelAfterRead       context.CancelFunc
}

func (r *trackedLoaderReader) Read(p []byte) (int, error) {
	r.reads++
	if len(p) > r.largestRequest {
		r.largestRequest = len(p)
	}
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if r.cancelAfterRead != nil {
		r.cancelAfterRead()
	}
	return n, nil
}

type cancellingLoaderWriter struct {
	buffer bytes.Buffer
	cancel context.CancelFunc
}

func (w *cancellingLoaderWriter) Write(p []byte) (int, error) {
	n, err := w.buffer.Write(p)
	w.cancel()
	return n, err
}

func TestLoaderCopyCancellationStopsAtChunkBoundary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &trackedLoaderReader{data: bytes.Repeat([]byte{0x5a}, 3*loaderChunkBytes)}
	target := &cancellingLoaderWriter{cancel: cancel}
	n, err := copyContext(ctx, target, source)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("copy cancellation lost: %v", err)
	}
	if source.reads != 1 || source.largestRequest > loaderChunkBytes || n <= 0 || n > loaderChunkBytes || int64(target.buffer.Len()) != n {
		t.Fatalf("copy proceeded after cancellation: reads=%d request=%d written=%d retained=%d", source.reads, source.largestRequest, n, target.buffer.Len())
	}
}

func TestLoaderReadCancellationDoesNotPublishReturnedBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &trackedLoaderReader{data: []byte("returned concurrently with cancellation"), cancelAfterRead: cancel}
	var target bytes.Buffer
	n, err := copyContext(ctx, &target, source)
	if !errors.Is(err, context.Canceled) || n != 0 || target.Len() != 0 || source.reads != 1 {
		t.Fatalf("cancelled read bytes published: n=%d buffered=%d reads=%d err=%v", n, target.Len(), source.reads, err)
	}
}

func TestContextReadsRetainSizeTypeAndNoOverwriteBoundaries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")
	data := bytes.Repeat([]byte{0x42}, 2*loaderChunkBytes+17)
	if err := writeNewContext(context.Background(), path, data, 0700); err != nil {
		t.Fatal(err)
	}
	got, err := readLimitedContext(context.Background(), path, int64(len(data)))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("bounded read changed bytes: %v", err)
	}
	if _, err := readLimitedContext(context.Background(), path, int64(len(data)-1)); err == nil {
		t.Fatal("oversized file accepted")
	}
	if _, err := readLimitedContext(context.Background(), dir, 1<<20); err == nil {
		t.Fatal("directory accepted as executable bytes")
	}
	if err := writeNewContext(context.Background(), path, []byte("replacement"), 0700); !os.IsExist(err) {
		t.Fatalf("overwrite not rejected: %v", err)
	}
	got, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("retained bytes overwritten")
	}
}
