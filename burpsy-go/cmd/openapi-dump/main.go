// openapi-dump prints the console's OpenAPI 3.1 document on stdout (burpsy-react-ui-pg5a).
//
// The document is generated from the web package's own route manifest and schema table, so this is
// the same bytes GET /api/openapi.json serves; the UI's typed-client generator (ui's
// scripts/gen-api-types.mjs) runs this rather than booting a server.
package main

import (
	"fmt"
	"os"

	"github.com/burpsy-go/burpsy/internal/web"
)

func main() {
	raw, err := web.OpenAPIJSON()
	if err != nil {
		fmt.Fprintln(os.Stderr, "openapi-dump:", err)
		os.Exit(1)
	}
	fmt.Println(string(raw))
}
