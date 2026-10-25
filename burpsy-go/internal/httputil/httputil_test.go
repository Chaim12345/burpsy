package httputil

import "testing"

func TestEnsureConnectionClose(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "inserts when no Connection header",
			in:   "GET /ftp/ HTTP/1.1\r\nHost: example\r\n\r\n",
			want: "GET /ftp/ HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n",
		},
		{
			name: "replaces keep-alive",
			in:   "GET / HTTP/1.1\r\nHost: example\r\nConnection: keep-alive\r\n\r\n",
			want: "GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n",
		},
		{
			name: "replaces case-insensitively and keeps the body",
			in:   "POST / HTTP/1.1\r\ncOnNeCtIoN: Keep-Alive\r\nContent-Length: 4\r\n\r\nbody",
			want: "POST / HTTP/1.1\r\nConnection: close\r\nContent-Length: 4\r\n\r\nbody",
		},
		{
			name: "collapses duplicate Connection lines",
			in:   "GET / HTTP/1.1\r\nConnection: keep-alive\r\nConnection: upgrade\r\n\r\n",
			want: "GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
		},
		{
			name: "unterminated head returned unchanged",
			in:   "GET / HTTP/1.1\r\nHost: example",
			want: "GET / HTTP/1.1\r\nHost: example",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EnsureConnectionClose([]byte(tc.in)); string(got) != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
