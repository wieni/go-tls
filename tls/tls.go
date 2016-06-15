package tls

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/wieni/go-tls/simplehttp"
)

// Server is the tls version of simplehttp.
type Server struct {
	*simplehttp.Server
	log         *log.Logger
	cert        *tls.Certificate
	redirServer *http.Server
}

// New returns a new Server with the given router.
func New(router simplehttp.Router, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.New(ioutil.Discard, "", 0)
	}

	s := &Server{log: logger}

	base := &http.Server{}
	base.TLSConfig = &tls.Config{GetCertificate: s.getCert}
	s.Server = simplehttp.FromHTTPServer(base, router, logger)

	s.SetStrictTransportSecurity(23652000)

	return s
}

// RedirectHTTP enables an http server that redirects incoming requests to their
// tls counterpart and returns the ServeMux.
func (s *Server) RedirectHTTP(addr string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.FromHTTP)
	s.redirServer = &http.Server{Handler: mux, Addr: addr}

	return mux
}

// SetStrictTransportSecurity sets the Strict-Transport-Security header
// if maxAge == 0 disable it.
func (s *Server) SetStrictTransportSecurity(maxAge int) {
	if maxAge == 0 {
		s.RemoveHeader("Strict-Transport-Security")
		return
	}

	s.SetHeader("Strict-Transport-Security", fmt.Sprintf("max-age=%d", maxAge))
}

// FromHTTP implements the func passed to http.ServeMux.HandleFunc()
// it will redirect to the https equivalent, supposedly this server.
func (s *Server) FromHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.Split(r.Host, ":")[0]

	u := &url.URL{
		Scheme:   "https",
		Opaque:   r.URL.Opaque,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
		Fragment: r.URL.Fragment,
		Host:     host,
		Path:     r.URL.Path,
		User:     r.URL.User,
	}

	http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
}

// Start listening on the given address
func (s *Server) Start(addr string) error {
	errc := make(chan error, 1)

	if s.redirServer != nil {
		go func() {
			errc <- s.redirServer.ListenAndServe()
		}()
	}

	go func() {
		errc <- s.Server.Start(addr, true)
	}()

	for {
		select {
		case err := <-errc:
			return err
		}
	}
}

// SetCert updates the tls Certificate
func (s *Server) SetCert(cert *tls.Certificate) {
	s.cert = cert
}

// SetCertFromACME is a convenience method that logs the error.
func (s *Server) SetCertFromACME(cert *tls.Certificate, err error) {
	if err != nil {
		s.log.Printf("ACME FAILED! %s", err.Error())
		return
	}

	s.cert = cert
}

func (s *Server) getCert(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.cert, nil
}