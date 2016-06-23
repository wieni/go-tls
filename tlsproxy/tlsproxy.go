package tlsproxy

import (
	"crypto/rsa"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/wieni/go-tls/simplehttp"
	"github.com/wieni/go-tls/tls"
)

const minPings = 3

type backend struct {
	uri                 *url.URL
	healthCheck         time.Duration
	adjustedHealthCheck time.Duration
	pings               int
	prox                simplehttp.HandleFunc
}

type pool struct {
	sync.Mutex
	last   int
	pool   []*backend
	stopCh chan bool
}

func (p *pool) get() simplehttp.HandleFunc {
	ln := len(p.pool)
	if ln == 0 {
		return nil
	} else if ln == 1 {
		return p.pool[0].prox
	}

	p.last++
	if p.last >= ln {
		p.last = 0
	}

	offset := p.last
	for i := 0; i < ln; i++ {
		if offset+i >= ln {
			offset = -i
		}

		if p.pool[offset+i].pings >= minPings {
			return p.pool[offset+i].prox
		}
	}

	return nil
}

func (p *pool) stopHealthCheck() {
	p.Lock()
	defer p.Unlock()
	if p.stopCh != nil {
		p.stopCh <- true
	}
}

func (p *pool) healthCheck(l *log.Logger) {
	p.Lock()
	if p.stopCh != nil {
		return
	}
	p.stopCh = make(chan bool, 1)
	p.Unlock()

	if len(p.pool) < 2 {
		return
	}

	var wg sync.WaitGroup
	for _, b := range p.pool {
		if b.healthCheck == 0 {
			continue
		}

		wg.Add(1)
		go func(b *backend) {
			for {
				select {
				case <-p.stopCh:
					p.stopCh <- true
					wg.Done()
					return
				case <-time.After(b.adjustedHealthCheck):
					conn, err := net.DialTimeout("tcp", b.uri.Host, 2*time.Second)
					if conn != nil {
						conn.Close()
					}

					if err != nil {
						l.Printf("Backend failed: %s %s", b.uri.Host, err)
						b.adjustedHealthCheck = b.healthCheck / 2
						b.pings = 0
						continue
					}

					b.pings++
					if b.pings > 100 {
						if b.adjustedHealthCheck < time.Second*120 {
							b.adjustedHealthCheck *= 2
						}

						b.pings = minPings
					}
				}
			}
		}(b)
	}

	wg.Wait()

	p.Lock()
	defer p.Unlock()
	close(p.stopCh)
	p.stopCh = nil
}

// Hosts maps host names to their proxied backends.
type Hosts map[string]*pool

func (h Hosts) healthCheck(l *log.Logger) {
	for _, p := range h {
		go func(p *pool) {
			p.healthCheck(l)
		}(p)
	}
}

func (h Hosts) stopHealthCheck() {
	for _, p := range h {
		p.stopHealthCheck()
	}
}

// Slice returns a list of hostnames
func (h Hosts) Slice() []string {
	domains := make([]string, 0, len(h))
	for domain := range h {
		domains = append(domains, domain)
	}

	return domains
}

// Add a host.
func (h Hosts) Add(host string, uri *url.URL, healthCheckInterval time.Duration) {
	if _, ok := h[host]; !ok {
		h[host] = &pool{pool: make([]*backend, 0)}
	}

	if !strings.Contains(uri.Host, ":") {
		switch uri.Scheme {
		case "":
			fallthrough
		case "http":
			uri.Host += ":80"
		case "https":
			uri.Host += ":443"
		}
	}

	h[host].pool = append(
		h[host].pool,
		&backend{
			uri:                 uri,
			healthCheck:         healthCheckInterval,
			adjustedHealthCheck: healthCheckInterval,
			pings:               minPings,
		},
	)

}

// Proxy is a tls proxy server.
type Proxy struct {
	*tls.Server
	hosts Hosts
	log   *log.Logger
}

func (p *Proxy) router(r *http.Request, l *log.Logger) (simplehttp.HandleFunc, int) {
	if prox, ok := p.hosts[r.Host]; ok {
		return prox.get(), 0
	}

	return nil, 0
}

// New tls server that proxies requests to the given url.
func New(hosts Hosts, logger *log.Logger) (*Proxy, error) {
	for _, backends := range hosts {
		for _, backend := range backends.pool {
			prox := httputil.NewSingleHostReverseProxy(backend.uri)
			backend.prox = func(
				w http.ResponseWriter,
				r *http.Request,
				l *log.Logger,
			) (errStatus int, err error) {
				prox.ServeHTTP(w, r)
				return
			}
		}
	}

	prox := &Proxy{hosts: hosts, log: logger}
	prox.Server = tls.New(prox.router, logger)
	prox.DisableGzip()

	return prox, nil
}

// Start listening on the given address
func (p *Proxy) Start(addr string) error {
	p.hosts.healthCheck(p.log)
	return p.Server.Start(addr)
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
	p.hosts.healthCheck(p.log)
	return p.Server.StartCertified(
		tlsAddr,
		httpAddr,
		acmeDir,
		p.hosts.Slice(),
		contact,
		refreshTimeout,
		accountKey,
		tlsKey,
		cacheFile,
	)
}
