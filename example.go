package main

import (
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/wieni/go-tls/acme"
	"github.com/wieni/go-tls/simplehttp"
	"github.com/wieni/go-tls/tls"
)

func mustRSA(paths []string) *rsa.PrivateKey {
	key, err := acme.LoadOrGenerateRSAKey(
		paths,
		2*1024,
	)

	if err != nil {
		panic(err)
	}

	return key
}

func handleAll(w http.ResponseWriter, r *http.Request, l *log.Logger) (status int, err error) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "hello world!")
	return
}

func router(r *http.Request, l *log.Logger) (handler simplehttp.HandleFunc, status int) {
	if r.Method == "GET" || r.Method == "HEAD" {
		handler = handleAll
		return
	}

	status = http.StatusMethodNotAllowed
	return
}

func main() {
	go func() {
		// pprof
		http.ListenAndServe(":6060", nil)
	}()

	httpLogger := log.New(os.Stderr, "http|", log.LstdFlags)
	acmeLogger := log.New(os.Stderr, "acme|", log.LstdFlags)
	tlsServer := tls.New(router, httpLogger)
	mux := tlsServer.RedirectHTTP(":8080")

	accountKey := mustRSA([]string{"account_rsa_key"})
	tlsKey := mustRSA([]string{"tls_rsa_key"})
	go func() {
		err := acme.Certify(
			acmeLogger,
			"https://acme-staging.api.letsencrypt.org/directory",
			//"https://acme-v01.api.letsencrypt.org/directory",
			[]string{"www.my-site.com", "my-site.com"},
			[]string{"mailto:my-email@my-site.com"},
			time.Hour*24*60,
			accountKey,
			tlsKey,
			mux,
			"cert",
			tlsServer.SetCertFromACME,
		)
		if err != nil {
			acmeLogger.Println(err)
		}
	}()

	httpLogger.Println(tlsServer.Start(":8081"))
}
