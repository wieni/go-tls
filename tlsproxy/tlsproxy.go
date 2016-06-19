package tlsproxy

import (
	"crypto/rsa"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/wieni/go-tls/simplehttp"
	"github.com/wieni/go-tls/tls"
)

// Domains maps host names to their proxied destination.
type Domains map[string]string

// Add a domain.
func (d Domains) Add(from, to string) {
	d[from] = to
}

// Proxy is a tls proxy server.
type Proxy struct {
	*tls.Server
	prox map[string]simplehttp.HandleFunc
}

func (p *Proxy) router(r *http.Request, l *log.Logger) (simplehttp.HandleFunc, int) {
	if prox, ok := p.prox[r.Host]; ok {
		return prox, 0
	}

	return nil, 0
}

// New tls server that proxies requests to the given url.
func New(domains Domains, logger *log.Logger) (*Proxy, error) {
	funcs := make(map[string]simplehttp.HandleFunc, len(domains))
	for from, to := range domains {
		tourl, err := url.Parse(to)
		if err != nil {
			return nil, err
		}

		prox := httputil.NewSingleHostReverseProxy(tourl)
		funcs[from] = func(
			w http.ResponseWriter,
			r *http.Request,
			l *log.Logger,
		) (errStatus int, err error) {
			prox.ServeHTTP(w, r)
			return
		}
	}

	prox := &Proxy{prox: funcs}
	prox.Server = tls.New(prox.router, logger)
	prox.DisableGzip()

	return prox, nil
}

// StartCertified starts the tls server and manages its acme tls certificate.
func (p *Proxy) StartCertified(
	tlsAddr,
	httpAddr,
	acmeDir string,
	contact []string,
	refreshTimeout time.Duration,
	accountKey *rsa.PrivateKey,
	tlsKey *rsa.PrivateKey,
	cacheFile string,
) error {
	domains := make([]string, 0, len(p.prox))
	for domain := range p.prox {
		domains = append(domains, domain)
	}

	return p.Server.StartCertified(
		tlsAddr,
		httpAddr,
		acmeDir,
		domains,
		contact,
		refreshTimeout,
		accountKey,
		tlsKey,
		cacheFile,
	)
}
