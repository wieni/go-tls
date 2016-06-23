package tlsproxy

import (
	"crypto/rsa"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wieni/go-tls/simplehttp"
	"github.com/wieni/go-tls/tls"
)

const minPings = 3

type transport struct {
	http.RoundTripper
	index int
	p     *pool
}

func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := t.RoundTripper.RoundTrip(r)
	if err != nil {
		return res, err
	}

	if t.p.cookie != "" {
		c, _ := r.Cookie(t.p.cookie)
		set := c == nil
		if !set {
			server, err := strconv.Atoi(c.Value)
			set = err != nil || server < 0 ||
				server >= len(t.p.pool) || !t.p.pool[server].isAvailable()
		}

		if set {
			res.Header.Add(
				"Set-Cookie",
				(&http.Cookie{Name: t.p.cookie, Value: strconv.Itoa(t.index)}).String(),
			)

			res.Header.Set("Cache-Control", "nocache")
		}
	}

	return res, nil
}

type backend struct {
	uri                 *url.URL
	healthCheck         time.Duration
	adjustedHealthCheck time.Duration
	pings               int
	prox                simplehttp.HandleFunc
}

func (b *backend) isAvailable() bool {
	return b.pings >= minPings
}

type pool struct {
	sync.Mutex
	cookie string
	last   int
	pool   []*backend
	stopCh chan bool
}

func (p *pool) get(r *http.Request) simplehttp.HandleFunc {
	ln := len(p.pool)
	if ln == 0 {
		return nil
	} else if ln == 1 {
		return p.pool[0].prox
	}

	cookie := -1
	if p.cookie != "" {
		c, _ := r.Cookie(p.cookie)
		if c != nil {
			if val, err := strconv.Atoi(c.Value); err == nil {
				cookie = val
			}
		}
	}

	if cookie >= 0 && cookie < ln && p.pool[cookie].isAvailable() {
		return p.pool[cookie].prox
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

		if p.pool[offset+i].isAvailable() {
			return p.pool[offset+i].prox
		}
	}

	return nil
}

func (p *pool) createHandler(index int, target *url.URL) simplehttp.HandleFunc {
	prox := httputil.NewSingleHostReverseProxy(target)
	prox.Transport = &transport{http.DefaultTransport, index, p}

	return func(
		w http.ResponseWriter,
		r *http.Request,
		l *log.Logger,
	) (errStatus int, err error) {
		prox.ServeHTTP(w, r)
		return
	}
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
func (h Hosts) Add(
	host string,
	uri *url.URL,
	cookie string,
	healthCheckInterval time.Duration,
) {
	if _, ok := h[host]; !ok {
		h[host] = &pool{pool: make([]*backend, 0), cookie: cookie}
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
	if pool, ok := p.hosts[r.Host]; ok {
		return pool.get(r), 0
	}

	return nil, 0
}

// New tls server that proxies requests to the given url.
func New(hosts Hosts, logger *log.Logger) *Proxy {
	for _, backends := range hosts {
		for i, backend := range backends.pool {
			backend.prox = backends.createHandler(i, backend.uri)
		}
	}

	prox := &Proxy{hosts: hosts, log: logger}
	prox.Server = tls.New(prox.router, logger)
	prox.DisableGzip()

	return prox
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
