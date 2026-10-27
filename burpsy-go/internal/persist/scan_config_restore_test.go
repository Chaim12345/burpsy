package persist

import (
	"reflect"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/scanner"
)

// launchLike is a base with default-on switches set, standing in for NewActiveScanner's defaults
// without depending on their exact list.
func launchLike() scanner.ScanConfig {
	return scanner.ScanConfig{
		MaxConcurrency:       8,
		CheckXss:             true,
		CheckXXE:             true,
		CheckPassiveAnalysis: true,
		OnlyRows:             []string{"base-row"},
	}
}

// burpsy-react-ui-scanconfig-persist-format: keys the saved document does not carry keep base's
// value; keys it does carry win, including an explicit false over a default-on base.
func TestLoadScanConfigDecodesOntoBase(t *testing.T) {
	st := newTestStore(t)
	if err := st.setSetting("scanconfig.overrides", `{"MaxConcurrency":3,"CheckSqli":true,"CheckXss":false}`); err != nil {
		t.Fatal(err)
	}
	got, err := st.LoadScanConfig(launchLike())
	if err != nil || got == nil {
		t.Fatalf("LoadScanConfig = %v, %v", got, err)
	}
	if !got.CheckXXE || !got.CheckPassiveAnalysis {
		t.Errorf("default-on switches absent from the document came back off: CheckXXE=%v CheckPassiveAnalysis=%v", got.CheckXXE, got.CheckPassiveAnalysis)
	}
	if got.CheckXss {
		t.Error("CheckXss: the document saved false, the default-on base must not override it")
	}
	if !got.CheckSqli || got.MaxConcurrency != 3 {
		t.Errorf("saved values lost: CheckSqli=%v MaxConcurrency=%d", got.CheckSqli, got.MaxConcurrency)
	}
	if strings.Join(got.OnlyRows, "|") != "base-row" {
		t.Errorf("OnlyRows = %v, want base's [base-row]: the document does not mention it", got.OnlyRows)
	}
}

// A key the struct no longer has (a field renamed or removed since the project was saved) must not
// fail the load, and the renamed field keeps base's value rather than reading as zero.
func TestLoadScanConfigIgnoresRenamedAndUnknownKeys(t *testing.T) {
	st := newTestStore(t)
	doc := `{"CheckXXEOld":false,"CheckSomethingRemoved":true,"Nested":{"x":[1,2]},"CheckSqli":true}`
	if err := st.setSetting("scanconfig.overrides", doc); err != nil {
		t.Fatal(err)
	}
	got, err := st.LoadScanConfig(launchLike())
	if err != nil {
		t.Fatalf("an unknown key failed the whole load: %v", err)
	}
	if got == nil || !got.CheckXXE || !got.CheckSqli {
		t.Fatalf("got %+v; want CheckXXE kept from base and CheckSqli from the document", got)
	}
}

// A document that does not decode is an error and yields nil — never a half-applied config.
func TestLoadScanConfigRejectsUndecodableDocument(t *testing.T) {
	for name, doc := range map[string]string{
		"malformed":  `{"CheckSqli":tr`,
		"wrong type": `{"CheckSqli":true,"CheckXXE":"yes"}`,
	} {
		t.Run(name, func(t *testing.T) {
			st := newTestStore(t)
			if err := st.setSetting("scanconfig.overrides", doc); err != nil {
				t.Fatal(err)
			}
			got, err := st.LoadScanConfig(launchLike())
			if err == nil || got != nil {
				t.Fatalf("LoadScanConfig = %+v, %v; want nil and an error", got, err)
			}
		})
	}
}

// Nothing saved is nil, nil: the caller keeps base.
func TestLoadScanConfigAbsentIsNil(t *testing.T) {
	got, err := newTestStore(t).LoadScanConfig(launchLike())
	if err != nil || got != nil {
		t.Fatalf("LoadScanConfig on a fresh store = %+v, %v; want nil, nil", got, err)
	}
}

// The current format still round-trips: what SaveScanConfig wrote is what comes back, whatever the
// base, because every json-visible field is present in the document.
func TestScanConfigSaveLoadRoundTrip(t *testing.T) {
	st := newTestStore(t)
	saved := scanner.ScanConfig{
		MaxConcurrency:      5,
		CheckSqli:           true,
		CustomPayloads:      []string{"a", "b"},
		IssueTypes:          []uint32{7},
		OnlyRows:            []string{"r"},
		CheckRaceConditions: true,
	}
	if err := st.SaveScanConfig(saved); err != nil {
		t.Fatal(err)
	}
	got, err := st.LoadScanConfig(launchLike())
	if err != nil || got == nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*got, saved) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", *got, saved)
	}
}

// Decoding a JSON array into a non-nil slice appends into its backing array. Loading must not write
// through to the caller's base.
func TestLoadScanConfigDoesNotWriteThroughBase(t *testing.T) {
	st := newTestStore(t)
	if err := st.setSetting("scanconfig.overrides", `{"only_rows":["saved"]}`); err != nil {
		t.Fatal(err)
	}
	base := launchLike()
	base.OnlyRows = make([]string, 1, 4)
	base.OnlyRows[0] = "base-row"
	got, err := st.LoadScanConfig(base)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	if base.OnlyRows[0] != "base-row" {
		t.Fatalf("loading rewrote the caller's base: base.OnlyRows = %v", base.OnlyRows)
	}
	if strings.Join(got.OnlyRows, "|") != "saved" {
		t.Fatalf("got.OnlyRows = %v, want [saved]", got.OnlyRows)
	}
}

// Every reference-typed, json-visible ScanConfig field must come out of unaliasScanConfig with its
// own storage. A new slice field that is not added there fails here instead of silently aliasing.
func TestUnaliasScanConfigCoversEverySliceField(t *testing.T) {
	var base scanner.ScanConfig
	bv := reflect.ValueOf(&base).Elem()
	typ := bv.Type()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Tag.Get("json") == "-" {
			continue // never stored, so never decoded into
		}
		switch f.Type.Kind() {
		case reflect.Slice:
			bv.Field(i).Set(reflect.MakeSlice(f.Type, 1, 4))
		case reflect.Map, reflect.Pointer, reflect.Interface:
			t.Errorf("ScanConfig.%s is a %s; unaliasScanConfig only knows how to copy slices", f.Name, f.Type.Kind())
		}
	}
	out := reflect.ValueOf(unaliasScanConfig(base))
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Tag.Get("json") == "-" || f.Type.Kind() != reflect.Slice {
			continue
		}
		if out.Field(i).Pointer() == bv.Field(i).Pointer() {
			t.Errorf("ScanConfig.%s still shares base's backing array; add it to unaliasScanConfig", f.Name)
		}
	}
}
