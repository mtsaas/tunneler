// Package testutil contains assertions shared by the sharing tests.
package testutil

import (
	"testing"
	"time"
)

func NoError(t testing.TB, err error) {
	t.Helper()
	Require(t, err == nil, "%v", err)
}

func Require(t testing.TB, condition bool, message string, args ...any) {
	t.Helper()
	if !condition {
		t.Fatalf(message, args...)
	}
}

func Receive[T any](t testing.TB, ch <-chan T, timeout time.Duration, message string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(timeout):
		t.Fatal(message)
	}
	var zero T
	return zero
}
