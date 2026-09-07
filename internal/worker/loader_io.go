package worker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"

	"github.com/harishappana/gpu-inspector/internal/privatefs"
)

const loaderChunkBytes = 64 << 10

// contextReader checks cancellation around each bounded read. An individual
// filesystem syscall can still block in the OS; this does not claim to interrupt
// a kernel wait, but never starts another read/write after observing cancellation.
type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > loaderChunkBytes {
		p = p[:loaderChunkBytes]
	}
	n, err := r.source.Read(p)
	if cancelled := r.ctx.Err(); cancelled != nil {
		return 0, cancelled
	}
	return n, err
}

func copyContext(ctx context.Context, target io.Writer, source io.Reader) (int64, error) {
	n, err := io.Copy(target, contextReader{ctx: ctx, source: source})
	if cancelled := ctx.Err(); cancelled != nil {
		return n, cancelled
	}
	return n, err
}

func readLimitedContext(ctx context.Context, path string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("expected regular file")
	}
	if info.Size() > limit {
		return nil, errors.New("file exceeds size limit")
	}
	data, err := io.ReadAll(contextReader{ctx: ctx, source: io.LimitReader(f, limit+1)})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds size limit")
	}
	return data, nil
}

func writeNewContext(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := privatefs.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = copyContext(ctx, f, bytes.NewReader(data))
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, ctx.Err(), f.Close())
}
