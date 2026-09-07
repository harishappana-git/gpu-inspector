package worker

import "time"

// ParseRequest validates retained output and its successful request echo. It
// does not launch a process or establish that instrumentation actually ran.
func ParseRequest(data []byte, request Request, elapsed time.Duration) (Result, error) {
	r, err := Parse(data, request.Device.UUID, request.Method, elapsed)
	if err != nil {
		return r, err
	}
	return r, r.validateRequest(request)
}
