//go:build !linux && !darwin

package scan

import "errors"

type targetLock struct{}

func acquireLock(root, uuid string) (*targetLock, error) {
	return nil, errors.New("target locks unsupported on this platform")
}
func (l *targetLock) close() error { return nil }
