package core

import (
	"reflect"
	"testing"
	"time"
)

// The distinction the type exists for: a fast exchange and an untimed one are not the same value.
//
// With the old `DurationMs uint64` they were: a 400 µs exchange and an exchange nobody timed both
// stored 0, so no reader and no test could tell them apart.
func TestASubMillisecondDurationIsNotAnUnmeasuredOne(t *testing.T) {
	fast := MeasuredDuration(400 * time.Microsecond)
	none := UnmeasuredDuration()

	if fast == none {
		t.Fatal("a measured 400µs and an unmeasured duration are the same value")
	}
	if !fast.Measured {
		t.Error("a measured duration does not report itself as measured")
	}
	if none.Measured {
		t.Error("an unmeasured duration reports itself as measured")
	}
	// Both still round to zero milliseconds, which is exactly why Millis must never be used to decide
	// whether an exchange was timed.
	if fast.Millis() != 0 || none.Millis() != 0 {
		t.Fatalf("millis: fast=%d none=%d; both are expected to round to 0, which is the trap this type "+
			"exists to keep out of the *representation*", fast.Millis(), none.Millis())
	}
	if fast.Micros() != 400 {
		t.Errorf("micros = %d, want 400", fast.Micros())
	}
	if none.Micros() != 0 {
		t.Errorf("an unmeasured duration reports %d microseconds, want 0", none.Micros())
	}
	if fast.Duration() != 400*time.Microsecond {
		t.Errorf("Duration() = %s, want 400µs", fast.Duration())
	}
	// Rendered for an operator, "unmeasured" must not read as an instantaneous exchange.
	if none.String() != "unmeasured" {
		t.Errorf("unmeasured renders as %q", none.String())
	}
	if fast.String() == none.String() {
		t.Errorf("both render as %q", fast.String())
	}
}

// A measured zero is still a measurement, and the zero *value* is the unmeasured one. This is the
// property internal/proxy/parity_test.go's rulePopulated now depends on: a non-zero field means a
// producer timed the exchange, whatever the machine's speed.
func TestTheZeroValueIsUnmeasuredAndAMeasuredZeroIsNot(t *testing.T) {
	var zero ExchangeDuration
	if zero.Measured {
		t.Fatal("the zero value claims to be a measurement, so a producer that forgets to set the field " +
			"would silently claim an instantaneous exchange")
	}
	if zero != UnmeasuredDuration() {
		t.Fatal("the zero value and UnmeasuredDuration() differ")
	}
	if !reflect.ValueOf(zero).IsZero() {
		t.Fatal("the unmeasured value is not the reflect zero value, so a presence check cannot use it")
	}

	measuredZero := MeasuredDuration(0)
	if !measuredZero.Measured {
		t.Fatal("MeasuredDuration(0) is not measured; a genuinely sub-microsecond exchange must still count " +
			"as timed")
	}
	if reflect.ValueOf(measuredZero).IsZero() {
		t.Fatal("a measured zero looks like the zero value, so a presence check would call a timed " +
			"exchange untimed")
	}
}

// A clock that goes backwards is clamped, not turned into "unmeasured": the measurement happened, and
// its result is nonsense rather than absent.
func TestANegativeDurationClampsButStaysMeasured(t *testing.T) {
	d := MeasuredDuration(-5 * time.Millisecond)
	if !d.Measured {
		t.Fatal("a negative measurement was reported as no measurement at all")
	}
	if d.Us != 0 {
		t.Fatalf("Us = %d, want 0 after clamping", d.Us)
	}
}

// MeasuredMicros is the storage-side constructor, and it agrees with the time.Duration one.
func TestMeasuredMicrosMatchesMeasuredDuration(t *testing.T) {
	if got, want := MeasuredMicros(1500), MeasuredDuration(1500*time.Microsecond); got != want {
		t.Fatalf("MeasuredMicros(1500) = %+v, MeasuredDuration(1.5ms) = %+v", got, want)
	}
	if got := MeasuredMicros(1500).Millis(); got != 1 {
		t.Fatalf("1500µs is %d ms, want 1 (truncated)", got)
	}
}
