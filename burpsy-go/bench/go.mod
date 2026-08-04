// The measurement harnesses live in their own module on purpose.
//
// They import modernc.org/sqlite directly, which in the main module is an
// indirect dependency pulled in by internal/persist. Keeping them here means
// `go mod tidy` in the parent does not promote it to a direct requirement, and
// `go build ./...` in the parent does not build throwaway code.
module github.com/burpsy-go/burpsy/bench

go 1.25.0

require (
	github.com/burpsy-go/burpsy v0.0.0
	go.uber.org/zap v1.26.0
	modernc.org/sqlite v1.55.0
)

replace github.com/burpsy-go/burpsy => ..
