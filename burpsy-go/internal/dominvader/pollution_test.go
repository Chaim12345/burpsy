package dominvader

import (
	"context"
	"fmt"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dop251/goja"
)

// The boundary is the materialised page script, not private helper functions.
// A sink marker without a proven polluted prototype is not a gadget finding.
func TestPollutionInstrumentationRequiresPrototypeProofBeforeReportingAGadget(t *testing.T) {
	for _, polluted := range []bool{false, true} {
		dir, err := Materialise(t.TempDir(), Config{Canary: "operator", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		script, err := os.ReadFile(filepath.Join(dir, "pollution.js"))
		if err != nil {
			t.Fatal(err)
		}
		vm := goja.New()
		_, err = vm.RunString(`var hits=[], listeners={}; var window=this; var location={href:'https://test/a'};
var document={readyState:'complete',addEventListener:function(n,f){listeners[n]=f;},dispatchEvent:function(e){hits.push(JSON.parse(e.detail));}};
function CustomEvent(n,o){this.detail=o.detail;} function Element(){};
Object.defineProperty(Element.prototype,'innerHTML',{configurable:true,set:function(v){this.value=v;}});
var __burpsyDI_probe={marker:'freshMarker',proof:'proofProperty',property:'html',technique:'query-bracket'};`)
		if err != nil {
			t.Fatal(err)
		}
		if polluted {
			_, err = vm.RunString(`Object.prototype.proofProperty='freshMarker'; Object.prototype.html='freshMarker';`)
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err = vm.RunString(string(script)); err != nil {
			t.Fatal(err)
		}
		if _, err = vm.RunString(`var e=new Element();e.innerHTML='freshMarker';`); err != nil {
			t.Fatal(err)
		}
		var got []map[string]any
		if err := vm.ExportTo(vm.Get("hits"), &got); err != nil {
			t.Fatal(err)
		}
		if !polluted && len(got) != 0 {
			t.Fatalf("unproven marker became a finding: %#v", got)
		}
		if polluted && (len(got) != 2 || got[0]["kind"] != "pollution-source" || got[1]["kind"] != "pollution-gadget") {
			t.Fatalf("source and gadget not distinguished: %#v", got)
		}
	}
}

type fixtureGate struct{ origin string }

func (g fixtureGate) AllowURL(u *url.URL) error {
	if u.Scheme+"://"+u.Host != g.origin {
		return fmt.Errorf("outside origin")
	}
	return nil
}
func (g fixtureGate) AllowAuthority(host string, port uint16, tls bool) error { return nil }

func TestPollutionScanRunsTheActualPageParserAndReportsSourceSeparateFromGadget(t *testing.T) {
	b, err := domexec.NewBrowser(context.Background(), domexec.Options{Timeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/safe" {
			fmt.Fprint(w, `<body>safe`)
			return
		}
		fmt.Fprint(w, `<body><script>
var params=new URLSearchParams(location.search);
params.forEach(function(v,k){var m=/^__proto__\[([^\]]+)\]$/.exec(k);if(m) Object.prototype[m[1]]=v;});
var settings={};if(settings.html)document.body.innerHTML=settings.html;
</script>`)
	}))
	defer srv.Close()
	p := PollutionConfig{Enabled: true, Target: srv.URL + "/vulnerable", Query: true, Properties: []string{"html"}}
	out, err := Scan(context.Background(), b, p, fixtureGate{srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Errors) != 0 {
		t.Fatalf("probe errors: %v", out.Errors)
	}
	var source, gadget bool
	for _, h := range out.Hits {
		source = source || h.Kind == "pollution-source"
		gadget = gadget || h.Kind == "pollution-gadget"
		if h.Probe == "" || h.Limitations == "" {
			t.Fatal("missing proof identity/limits")
		}
	}
	if !source || !gadget {
		t.Fatalf("page parser/gadget not observed: %+v", out)
	}
	p.Target = srv.URL + "/safe"
	quiet, err := Scan(context.Background(), b, p, fixtureGate{srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(quiet.Hits) != 0 || len(quiet.Errors) != 0 {
		t.Fatalf("safe control not quiet: %+v", quiet)
	}
}

func TestPollutionScanExercisesHashJSONAndNestedInputsWithoutLeakingBetweenProbes(t *testing.T) {
	b, err := domexec.NewBrowser(context.Background(), domexec.Options{Timeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<body><script>
function merge(to,from){Object.keys(from).forEach(function(k){var v=from[k];if(v&&typeof v==='object'){if(!to[k])to[k]={};merge(to[k],v);}else to[k]=v;});}
var params=new URLSearchParams(location.hash.slice(1));
params.forEach(function(v,k){var m=/^__proto__\[([^\]]+)\]$/.exec(k)||/^__proto__\.([^.]+)$/.exec(k);if(m)Object.prototype[m[1]]=v;var n=/^constructor\[prototype\]\[([^\]]+)\]$/.exec(k);if(n)Object.prototype[n[1]]=v;});
merge({},JSON.parse('{"app":true}'));
var settings={};if(settings.html)document.body.innerHTML=settings.html;
</script>`)
	}))
	defer srv.Close()
	out, err := Scan(context.Background(), b, PollutionConfig{Enabled: true, Target: srv.URL, Hash: true, JSON: true, Nested: true, Properties: []string{"html"}}, fixtureGate{srv.URL})
	if err != nil || len(out.Errors) != 0 {
		t.Fatalf("scan %v %+v", err, out)
	}
	observed := map[string]bool{}
	markers := map[string]bool{}
	for _, h := range out.Hits {
		if h.Kind == "pollution-gadget" {
			observed[h.Technique] = true
			markers[h.Probe] = true
		}
	}
	for _, technique := range []string{"hash-bracket", "hash-dot", "hash-constructor", "json"} {
		if !observed[technique] {
			t.Errorf("technique %s did not produce actual gadget evidence", technique)
		}
	}
	if len(markers) != 4 {
		t.Fatalf("probe canaries are not unique per technique: %v", markers)
	}
}
