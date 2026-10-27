package intruder

// ptr is the int-pointer helper intruder's tests share (it lived in limit_test.go before the limiter
// moved to internal/ratelimit).
func ptr(i int) *int { return &i }
