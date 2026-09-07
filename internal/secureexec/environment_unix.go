//go:build !windows

package secureexec

func childEnvironment() []string {
	return []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
}
