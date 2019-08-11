package dnsutil

import (
	"path"
	"strings"
)

// ToPath converts a DNS name into a path.
func ToPath(s string) string {
	l := strings.Split(s, ".")
	for left, right := 0, len(l)-1; left < right; left, right = left+1, right-1 {
		l[left], l[right] = l[right], l[left]
	}
	return path.Join(l...)
}
