package intruder

import "github.com/burpsy-go/burpsy/internal/ratelimit"

// The limiter moved to internal/ratelimit (burpsy-react-ui-misplaced-primitives): the crawler and
// the resource pools imported this whole attack engine for it. These aliases keep intruder's own
// callers and the console compiling unchanged for one round; new code imports internal/ratelimit.
type (
	RateLimit      = ratelimit.RateLimit
	DelayVariation = ratelimit.DelayVariation
	AutoThrottle   = ratelimit.AutoThrottle
	Permit         = ratelimit.Permit
	RateLimiter    = ratelimit.RateLimiter
)

const (
	MIN_THROTTLED_RPS = ratelimit.MIN_THROTTLED_RPS
	MAX_WAIT          = ratelimit.MAX_WAIT
	MaxGroupPace      = ratelimit.MaxGroupPace

	variationSeedStream = ratelimit.VariationSeedStream
)

var (
	NewRateLimit        = ratelimit.NewRateLimit
	Unthrottled         = ratelimit.Unthrottled
	DefaultRateLimit    = ratelimit.DefaultRateLimit
	DefaultAutoThrottle = ratelimit.DefaultAutoThrottle
	NewRateLimiter      = ratelimit.NewRateLimiter
)
