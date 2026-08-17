package domexec

// Live proof for the sinks added to close catalog rows whose family previously had none.
// Each test drives a real page through a real browser: an uninstrumented sink observes
// nothing, which would read as "no DOM vulnerability" on every page that uses it.

import (
	"context"
	"strings"
	"testing"
)

// observeSink loads html with the canary in location.hash and returns the observations at sink.
func observeSink(t *testing.T, html string, sink SinkKind) []Observation {
	t.Helper()
	b := newTestBrowser(t)
	url := servePage(t, html)
	obs, err := b.ObserveTaint(context.Background(), url+"#bsycanary", SourceLocationHash, "bsycanary")
	if err != nil {
		t.Fatalf("ObserveTaint: %v", err)
	}
	return ObservationsForSink(obs, sink)
}

func TestAHashSourceReachingDocumentEvaluateIsObservedAtTheXPathSink(t *testing.T) {
	t.Parallel()
	hits := observeSink(t, `<html><body><script>
		try { document.evaluate("//user[@name='" + location.hash.slice(1) + "']", document, null, 0, null); } catch (e) {}
	</script></body></html>`, SinkXPathEvaluate)
	if len(hits) == 0 {
		t.Fatal("document.evaluate received tainted data and was not observed; the Client-side XPath injection rows depend on this sink")
	}
	if !strings.Contains(hits[0].Argument, "bsycanary") {
		t.Errorf("observation lost the canary: %+v", hits[0])
	}
}

func TestAHashSourceReachingJSONParseIsObservedAtTheJSONSink(t *testing.T) {
	t.Parallel()
	hits := observeSink(t, `<html><body><script>
		try { JSON.parse('{"v":"' + location.hash.slice(1) + '"}'); } catch (e) {}
	</script></body></html>`, SinkJSONParse)
	if len(hits) == 0 {
		t.Fatal("JSON.parse received tainted data and was not observed")
	}
}

func TestAHashSourceAssignedToAnAnchorHrefIsObservedAtTheLinkSink(t *testing.T) {
	t.Parallel()
	hits := observeSink(t, `<html><body><a id="a">x</a><script>
		document.getElementById('a').href = location.hash.slice(1);
	</script></body></html>`, SinkAnchorHref)
	if len(hits) == 0 {
		t.Fatal("an anchor href built from tainted data was not observed; the Link manipulation rows depend on this sink")
	}
}

func TestAHashSourceUsedAsARegExpPatternIsObservedAtTheDoSSink(t *testing.T) {
	t.Parallel()
	hits := observeSink(t, `<html><body><script>
		try { new RegExp(location.hash.slice(1)); } catch (e) {}
	</script></body></html>`, SinkRegExpCtor)
	if len(hits) == 0 {
		t.Fatal("a RegExp built from tainted data was not observed; the Denial of service rows depend on this sink")
	}
}

func TestAWriteToObjectPrototypeIsObservedAtThePollutionSink(t *testing.T) {
	t.Parallel()
	hits := observeSink(t, `<html><body><script>
		try { Object.defineProperty(Object.prototype, location.hash.slice(1), {value: 1}); } catch (e) {}
	</script></body></html>`, SinkPrototypePollution)
	if len(hits) == 0 {
		t.Fatal("a write to Object.prototype was not observed; Client-side prototype pollution depends on this sink")
	}
}

// The negative case that keeps the new sinks honest: a page that never touches a source must
// produce no observation at any of them, or every page using JSON.parse would look vulnerable.
func TestAPageUsingTheNewSinksWithoutTaintYieldsNoObservations(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	url := servePage(t, `<html><body><a id="a">x</a><script>
		JSON.parse('{"v":"static"}');
		document.getElementById('a').href = "/local";
		try { document.evaluate("//x", document, null, 0, null); } catch (e) {}
		new RegExp("^static$");
	</script></body></html>`)
	obs, err := b.ObserveTaint(context.Background(), url+"#bsycanary", SourceLocationHash, "bsycanary")
	if err != nil {
		t.Fatalf("ObserveTaint: %v", err)
	}
	for _, sink := range []SinkKind{SinkJSONParse, SinkAnchorHref, SinkXPathEvaluate, SinkRegExpCtor} {
		if hits := ObservationsForSink(obs, sink); len(hits) != 0 {
			t.Errorf("%s reported %d observations on a page with no tainted flow", sink, len(hits))
		}
	}
}

// Instrumentation must call through: a wrapper that swallowed the call would observe nothing on
// any real page, and would do so silently.
func TestTheNewSinksStillCallThroughSoThePageKeepsWorking(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	url := servePage(t, `<html><body><div id="out"></div><script>
		var parsed = JSON.parse('{"v":"' + location.hash.slice(1) + '"}');
		var re = new RegExp(location.hash.slice(1));
		document.getElementById('out').textContent =
			parsed.v + "|" + (re.test("bsycanary") ? "matched" : "no") ;
	</script></body></html>`)
	if _, err := b.ObserveTaint(context.Background(), url+"#bsycanary", SourceLocationHash, "bsycanary"); err != nil {
		t.Fatalf("ObserveTaint: %v", err)
	}
	dom, err := b.RenderedDOM(context.Background(), url+"#bsycanary")
	if err != nil {
		t.Fatalf("RenderedDOM: %v", err)
	}
	if !strings.Contains(dom, "bsycanary|matched") {
		t.Fatalf("wrapped JSON.parse or RegExp did not call through; rendered DOM: %s", dom)
	}
}

func TestEveryNewSinkHasAStringAndATagMapping(t *testing.T) {
	for _, sink := range []SinkKind{
		SinkWebSQL, SinkXPathEvaluate, SinkJSONParse, SinkAnchorHref,
		SinkRegExpCtor, SinkFileRead, SinkPrototypePollution,
	} {
		if s := sink.String(); s == "" || strings.HasPrefix(s, "SinkKind(") {
			t.Errorf("sink %d has no name: %q", int(sink), s)
		}
		var mapped bool
		for _, v := range sinkTags {
			if v == sink {
				mapped = true
			}
		}
		// SinkFileRead and SinkWebSQL share tags with their own JS records; every new sink
		// must be reachable from a tag or it can never be decoded.
		if !mapped {
			t.Errorf("sink %s has no entry in sinkTags and can never be decoded", sink)
		}
	}
}
