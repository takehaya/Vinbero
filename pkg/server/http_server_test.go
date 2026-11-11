package server

import (
	"io"
	"net"
	"net/http"
	"testing"
)

// The RPC server answers HTTP/1.1 and HTTP/2 without TLS (prior knowledge).
func TestHTTPServerServesHTTP1AndCleartextHTTP2(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/proto", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	})
	srv := newHTTPServer(ln.Addr().String(), mux)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	for _, tc := range []struct {
		name string
		set  func(*http.Protocols)
		want string
	}{
		{"HTTP/1.1", func(p *http.Protocols) { p.SetHTTP1(true) }, "HTTP/1.1"},
		{"h2c prior knowledge", func(p *http.Protocols) { p.SetUnencryptedHTTP2(true) }, "HTTP/2.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			protocols := new(http.Protocols)
			tc.set(protocols)
			client := &http.Client{Transport: &http.Transport{Protocols: protocols}}
			resp, err := client.Get("http://" + ln.Addr().String() + "/proto")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)
			if string(body) != tc.want {
				t.Errorf("server saw %q, want %q", body, tc.want)
			}
		})
	}
}
