package scanner

import (
	"testing"
	"time"
)

// serve-index's directory listing (Juice Shop /ftp, /support/logs): a jQuery-style $ whose el.each calls $ again from inside
// a function literal that $ itself defines. Walking that literal again from inside its own scope used to re-parent its cached
// scope onto its own chain, and lookup then looped forever on the cycle, holding the proxy's client socket open.
const serveIndexListing = `<!DOCTYPE html><html><head><title>listing directory /support/logs</title><script>
      function $(id){
        var el = 'string' == typeof id
          ? document.getElementById(id)
          : id;

        el.on = function(event, fn){
          if ('content loaded' == event) {
            event = window.attachEvent ? "load" : "DOMContentLoaded";
          }
          el.addEventListener
            ? el.addEventListener(event, fn, false)
            : el.attachEvent("on" + event, fn);
        };

        el.all = function(selector){
          return $(el.querySelectorAll(selector));
        };

        el.each = function(fn){
          for (var i = 0, len = el.length; i < len; ++i) {
            fn($(el[i]), i);
          }
        };

        el.getClasses = function(){
          return this.getAttribute('class').split(/\s+/);
        };

        el.addClass = function(name){
          var classes = this.getAttribute('class');
          el.setAttribute('class', classes
            ? classes + ' ' + name
            : name);
        };

        el.removeClass = function(name){
          var classes = this.getClasses().filter(function(curr){
            return curr != name;
          });
          this.setAttribute('class', classes.join(' '));
        };

        return el;
      }

      function search() {
        var str = $('search').value.toLowerCase();
        var links = $('files').all('a');

        links.each(function(link){
          var text = link.textContent.toLowerCase();

          if ('..' == text) return;
          if (str.length && ~text.indexOf(str)) {
            link.addClass('highlight');
          } else {
            link.removeClass('highlight');
          }
        });
      }

      $(window).on('content loaded', function(){
        $('search').on('keyup', search);
      });
    </script></head>
<body><input id="search" type="text"><ul id="files"><li><a href="/support/logs/access.log">access.log</a></li></ul></body></html>`

func TestAnalyzeDOMDocumentSelfReentrantClosureTerminates(t *testing.T) {
	done := make(chan DOMAnalysis, 1)
	go func() { done <- AnalyzeDOMDocument([]byte(serveIndexListing), "text/html; charset=utf-8", DOMBudget{}) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("AnalyzeDOMDocument did not finish within 10s on a self-re-entrant closure (scope parent cycle)")
	}
}
