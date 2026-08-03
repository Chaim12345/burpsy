package models

import (
	"time"
)

// Message represents an HTTP request/response pair
type Message struct {
	ID              string            `json:"id"`
	URL             string            `json:"url"`
	Method          string            `json:"method"`
	StatusCode      int               `json:"status_code"`
	RequestHeaders  map[string]string `json:"request_headers"`
	ResponseHeaders map[string]string `json:"response_headers"`
	RequestBody     string            `json:"request_body"`
	ResponseBody    string            `json:"response_body"`
	Timestamp       time.Time         `json:"timestamp"`
	Source          string            `json:"source"` // proxy, scanner, intruder, etc.
	Tags            []string          `json:"tags"`
	Notes           string            `json:"notes"`
}

// Request represents an HTTP request
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Host    string
	Path    string
	Query   map[string]string
}

// Response represents an HTTP response
type Response struct {
	StatusCode int
	Status     string
	Headers    map[string]string
	Body       []byte
	Version    string
}

// TrafficFilter represents filtering criteria for traffic
type TrafficFilter struct {
	URLPattern      string
	Method          string
	StatusCode      *int
	Source          string
	Tags            []string
	HasRequestBody  bool
	HasResponseBody bool
	TimeFrom        time.Time
	TimeTo          time.Time
}

// Stats represents proxy statistics
type Stats struct {
	TotalRequests       int64         `json:"total_requests"`
	TotalResponses      int64         `json:"total_responses"`
	ActiveConnections   int64         `json:"active_connections"`
	RequestsPerSecond   float64       `json:"requests_per_second"`
	AverageResponseTime time.Duration `json:"average_response_time"`
}
