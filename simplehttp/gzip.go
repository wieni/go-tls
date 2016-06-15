package simplehttp

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
)

var gzipable = map[string]bool{
	"text/html":              true,
	"text/plain":             true,
	"text/css":               true,
	"text/javascript":        true,
	"application/json":       true,
	"application/javascript": true,
}

// AddGzipableContentType adds or overrides a content-type that will be
// considered gzipable.
// Not thread safe!
func AddGzipableContentType(contentType string) {
	gzipable[contentType] = true
}

// gzipWriter will only gzip if the given response writer has a content-type
// header that is in gzipable and the request has an accept-encoding: gzip header.
type gzipWriter struct {
	sync.Mutex
	http.ResponseWriter
	r       *http.Request
	written bool
	gz      io.WriteCloser
}

func (gz *gzipWriter) WriteHeader(status int) {
	gz.Write(nil)
	gz.ResponseWriter.WriteHeader(status)
}

func (gz *gzipWriter) Write(b []byte) (int, error) {
	gz.Lock()
	defer gz.Unlock()
	if !gz.written &&
		strings.Contains(gz.r.Header.Get("Accept-Encoding"), "gzip") {
		if _, ok := gzipable[gz.Header().Get("Content-Type")]; ok {
			gz.gz = gzip.NewWriter(gz.ResponseWriter)
			gz.Header().Set("Content-Encoding", "gzip")
		}
	}
	gz.written = true

	if b == nil {
		return 0, nil
	}

	if gz.gz != nil {
		return gz.gz.Write(b)
	}

	return gz.ResponseWriter.Write(b)
}

// Close the writer (i.e. finish the gzip stream if there is one)
func (gz *gzipWriter) Close() error {
	gz.Lock()
	defer gz.Unlock()
	if gz.gz != nil {
		return gz.gz.Close()
	}

	// http.ResponseWriter is not an io.WriteCloser
	return nil
}
