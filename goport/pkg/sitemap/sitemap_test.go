package sitemap

import (
	"testing"

	"burpsy-go/pkg/store"
)

func TestSitemapFolding(t *testing.T) {
	ts := store.NewTrafficStore()
	s := NewSitemap(ts)

	ts.AddExchange(store.Exchange{
		Host: "example.com",
		Path: "/v1/api/users",
	})
	ts.AddExchange(store.Exchange{
		Host: "example.com",
		Path: "/v1/api/orders",
	})

	tree := s.GetTree().(*Node)

	hostNode := tree.Children["example.com"]
	if hostNode == nil {
		t.Fatalf("host node not found")
	}

	v1Node := hostNode.Children["v1"]
	if v1Node == nil {
		t.Fatalf("v1 node not found")
	}

	apiNode := v1Node.Children["api"]
	if apiNode == nil {
		t.Fatalf("api node not found")
	}

	usersNode := apiNode.Children["users"]
	if usersNode == nil {
		t.Fatalf("users node not found")
	}

	if len(usersNode.Exchange) != 1 {
		t.Errorf("expected 1 exchange reference, got %d", len(usersNode.Exchange))
	}
}
