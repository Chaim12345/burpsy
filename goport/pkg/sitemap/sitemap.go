package sitemap

import (
	"strings"
	"sync"

	"burpsy-go/pkg/store"
)

type Node struct {
	Name     string           `json:"name"`
	Children map[string]*Node `json:"children"`
	Exchange []uint64         `json:"exchange,omitempty"`
}

type Sitemap struct {
	Store *store.TrafficStore
	mu    sync.Mutex
}

func NewSitemap(ts *store.TrafficStore) *Sitemap {
	return &Sitemap{Store: ts}
}

func (s *Sitemap) GetTree() interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	exchanges := s.Store.Exchanges(0, 100000)
	root := &Node{
		Name:     "Sitemap",
		Children: make(map[string]*Node),
	}

	for _, ex := range exchanges {
		hostNode, ok := root.Children[ex.Host]
		if !ok {
			hostNode = &Node{
				Name:     ex.Host,
				Children: make(map[string]*Node),
			}
			root.Children[ex.Host] = hostNode
		}

		// Split path and traverse
		trimmedPath := strings.Trim(ex.Path, "/")
		var parts []string
		if trimmedPath != "" {
			parts = strings.Split(trimmedPath, "/")
		}

		current := hostNode
		for _, part := range parts {
			child, ok := current.Children[part]
			if !ok {
				child = &Node{
					Name:     part,
					Children: make(map[string]*Node),
				}
				current.Children[part] = child
			}
			current = child
		}

		current.Exchange = append(current.Exchange, ex.ID)
	}

	return root
}
