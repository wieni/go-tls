package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/wieni/go-tls/acme"
	"github.com/wieni/go-tls/tlsproxy"
)

type proxy struct {
	Cookie   string         `json:"cookie"`
	Backends map[string]int `json:"backends"`
}

type config struct {
	AccountKey string            `yaml:"account_keyfile"`
	CertKey    string            `yaml:"certificate_keyfile"`
	TLSAddr    string            `yaml:"tls"`
	HTTPAddr   string            `yaml:"http"`
	ACMEDir    string            `yaml:"acme_directory"`
	ACMEMailTo string            `yaml:"acme_mailto"`
	CertCache  string            `yaml:"certificate_cachefile"`
	Proxy      map[string]*proxy `yaml:"proxy"`
}

func mustRSA(path string) *rsa.PrivateKey {
	key, err := acme.LoadOrGenerateRSAKey(
		[]string{path},
		2*1024,
	)

	if err != nil {
		log.Fatal(err)
	}

	return key
}

func loadCfg(path string) (*config, error) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &config{}
	err = yaml.Unmarshal(raw, cfg)

	return cfg, err
}

func relativeTo(from, to string) string {
	if path.IsAbs(to) {
		return to
	}

	return path.Join(from, to)
}

func main() {
	cfgFile := flag.String("config", "proxy.yml", "path to yaml config file")
	flag.Parse()

	cfgDir := path.Dir(*cfgFile)
	cfg, err := loadCfg(*cfgFile)
	if err != nil {
		log.Fatal(err)
	}

	errors := []string{}
	if cfg.ACMEDir == "" {
		errors = append(errors, "Please enter the 'acme_directory'")
	}

	if cfg.CertCache == "" {
		errors = append(errors, "Please enter the 'certificate_cachefile'")
	}

	if cfg.AccountKey == "" {
		errors = append(errors, "Please enter the 'account_keyfile'")
	}

	if cfg.CertKey == "" {
		errors = append(errors, "Please enter the 'certificate_keyfile'")
	}

	if cfg.TLSAddr == "" {
		errors = append(errors, "Please enter the 'tls' address")
	}

	if cfg.HTTPAddr == "" {
		errors = append(errors, "Please enter the 'http' address")
	}

	if cfg.ACMEMailTo == "" {
		errors = append(errors, "Please enter the 'acme_mailto' email address")
	}

	if cfg.Proxy == nil || len(cfg.Proxy) == 0 {
		errors = append(errors, "'proxy' can not be empty")
	}

	for name, proxy := range cfg.Proxy {
		if proxy == nil || proxy.Backends == nil || len(proxy.Backends) == 0 {
			errors = append(errors, fmt.Sprintf("'proxy' %s has no 'backends'", name))
		}
	}

	if len(errors) != 0 {
		log.Fatal("\n" + strings.Join(errors, "\n"))
	}

	accountKey := mustRSA(relativeTo(cfgDir, cfg.AccountKey))
	certKey := mustRSA(relativeTo(cfgDir, cfg.CertKey))

	httpLogger := log.New(os.Stderr, "http|", log.LstdFlags)
	hosts := make(tlsproxy.Hosts)
	for host, items := range cfg.Proxy {
		cookie := items.Cookie
		for backend, interval := range items.Backends {
			if !strings.HasPrefix(backend, "//") &&
				!strings.Contains(backend, "://") {
				backend = "//" + backend
			}

			uri, err := url.Parse(backend)
			if err != nil {
				log.Fatal(err)
			}

			hosts.Add(host, uri, cookie, time.Second*time.Duration(interval))
		}
	}

	prox := tlsproxy.New(hosts, httpLogger)
	httpLogger.Println(
		prox.StartCertified(
			cfg.TLSAddr,
			cfg.HTTPAddr,
			cfg.ACMEDir,
			[]string{"mailto:" + cfg.ACMEMailTo},
			time.Hour*24*60,
			accountKey,
			certKey,
			relativeTo(cfgDir, cfg.CertCache),
		),
	)
}
