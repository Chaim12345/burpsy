package web

import (
	"reflect"
	"testing"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// A Fixed row with no endpoint applies everywhere; one naming an endpoint applies to that endpoint
// only; a dynamic row is not a skip at all (burpsy-react-ui-8yjj).
func TestFixedParametersScopeEachRowToItsEndpoint(t *testing.T) {
	got := fixedParameters(apiScanReq{Parameters: []apiScanParamOverride{
		{Name: "api_key", Mode: "fixed"},
		{Endpoint: "GET /users/{id}", Name: "token", Mode: "fixed"},
		{Endpoint: "POST /orders", Name: "note", Mode: "dynamic"},
	}})
	if !reflect.DeepEqual(got.names, []string{"api_key"}) {
		t.Errorf("run-wide names = %v", got.names)
	}
	if want := []bcheck.ParameterAt{{Method: "GET", Template: "/users/{id}", Name: "token"}}; !reflect.DeepEqual(got.at, want) {
		t.Errorf("scoped = %v, want %v", got.at, want)
	}
}
