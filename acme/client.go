package acme

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v1"
)

var errNotPKIXCert = errors.New("not a pkix certificate")

// Client wraps acme api calls
type Client struct {
	m          sync.RWMutex
	thumbprint string
	signer     jose.Signer
	nonce      string
	dir        string
	endpoints  *directory
	challenges []*Challenge
}

// NewClient returns a new acme Client.
func NewClient(dirURL string, accountKey *rsa.PrivateKey) (*Client, error) {
	dirURL = strings.TrimRight(dirURL, "/")
	signer, err := jose.NewSigner(jose.RS256, accountKey)
	if err != nil {
		return nil, err
	}

	thumb, err := (&jose.JsonWebKey{
		Key:       accountKey.Public().(*rsa.PublicKey),
		Algorithm: "RSA",
	}).Thumbprint(crypto.SHA256)

	if err != nil {
		return nil, err
	}

	var m sync.RWMutex
	return &Client{
		m:          m,
		thumbprint: base64.RawURLEncoding.EncodeToString(thumb),
		signer:     signer,
		dir:        dirURL,
		challenges: make([]*Challenge, 0),
	}, nil
}

// Nonce returns the last nonce, exported to implement jose.NonceSource
func (c *Client) Nonce() (string, error) {
	return c.nonce, nil
}

func (c *Client) setNonce(n string) {
	c.nonce = n
}

func (c *Client) resetNonce() {
	c.nonce = ""
	c.endpoints = nil
}

// Handle attaches a http handle func to the given mux in order to complete
// simpleHTTP challenges.
func (c *Client) Handle(mux *http.ServeMux) {
	mux.HandleFunc(
		"/.well-known/acme-challenge/",
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Println("(todo remove)   RECEIVED REQ:", r.URL.Path)
			if len(c.challenges) == 0 {
				http.NotFound(w, r)
				return
			}

			uparts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			if len(uparts) != 3 {
				http.NotFound(w, r)
				return
			}

			c.m.RLock()
			defer c.m.RUnlock()
			for _, ch := range c.challenges {
				if uparts[2] != ch.token {
					continue
				}

				if err := ch.Write(w); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				return
			}

			http.NotFound(w, r)
		},
	)
}

func (c *Client) removeChallenge(challenge *Challenge) {
	c.m.Lock()
	defer c.m.Unlock()
	index := -1
	for i, ch := range c.challenges {
		if ch == challenge {
			index = i
		}
	}
	if index == -1 {
		return
	}

	c.challenges[index] = c.challenges[len(c.challenges)-1]
	c.challenges[len(c.challenges)-1] = nil
	c.challenges = c.challenges[:len(c.challenges)-1]
}

func (c *Client) marshal(msg interface{}) (string, error) {
	r, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}

	return c.sign(r)
}

func (c *Client) getDir(force bool) error {
	if !force && c.endpoints != nil {
		return nil
	}

	resp, err := http.Get(c.dir)
	if err != nil {
		return err
	}

	d := json.NewDecoder(resp.Body)
	defer resp.Body.Close()

	dir := &directory{}
	if d.Decode(dir); err != nil {
		return err
	}

	c.endpoints = dir
	c.setNonce(resp.Header.Get("Replay-Nonce"))
	return nil
}

func (c *Client) der2ocsp(derCerts [][]byte, derKey []byte) (*ocspCertificate, error) {
	if len(derCerts) == 0 {
		return nil, errors.New("No certificate given")
	}

	derCert := derCerts[0]

	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: derKey}),
	)

	if err != nil {
		return nil, err
	}

	// Ignoring error as tls.X509KeyPair already validated the cert.
	pair.Leaf, _ = x509.ParseCertificate(derCert)
	if len(derCerts) == 1 {
		intermediates, err := c.fetchIntermediates(pair.Leaf)
		if err == errNotPKIXCert {
			err = nil
		}

		if err != nil {
			return nil, err
		}

		if len(intermediates) == 0 {
			return nil, errors.New("No intermediate certificate could be found/fetched")
		}

		derCerts = append(derCerts, intermediates...)
	}

	for i := 1; i < len(derCerts); i++ {
		derCert = derCerts[i]
		pair.Certificate = append(
			pair.Certificate,
			derCert,
		)
	}

	rawIssuer := derCerts[1]
	issuer, err := x509.ParseCertificate(rawIssuer)
	if err != nil {
		return nil, err
	}

	return &ocspCertificate{&pair, issuer}, nil
}

func (c *Client) fetchIntermediates(cert *x509.Certificate) (ints [][]byte, err error) {
	ints = make([][]byte, 0)
	if len(cert.IssuingCertificateURL) == 0 {
		return
	}

	for {
		cert, err = c.fetchIntermediate(cert)
		if err != nil {
			break
		}

		// Probably the root cert
		if len(cert.IssuingCertificateURL) == 0 {
			break
		}

		ints = append(ints, cert.Raw)
	}

	return
}

func (c *Client) fetchIntermediate(cert *x509.Certificate) (*x509.Certificate, error) {
	if len(cert.IssuingCertificateURL) == 0 {
		return nil, errors.New("No issuing certificate url")
	}

	resp, err := c.getWithResponse(
		cert.IssuingCertificateURL[0],
		"application/pkix-cert",
	)

	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	if resp.Header.Get("Content-Type") != "application/pkix-cert" {
		return nil, errNotPKIXCert
	}

	der, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

func (c *Client) post(url string, msg interface{}, response response) (int, error) {
	resp, err := c.postWithResponse(url, msg)
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		if resp != nil {
			return resp.StatusCode, err
		}

		return 0, err
	}

	if response != nil {
		d := json.NewDecoder(resp.Body)
		if d.Decode(response); err != nil {
			return resp.StatusCode, err
		}

		for i := range resp.Header {
			for j := range resp.Header[i] {
				response.setHeader(i, resp.Header[i][j])
			}
		}
	}

	return resp.StatusCode, nil
}

func (c *Client) postWithResponse(url string, msg interface{}) (*http.Response, error) {
	signed, err := c.marshal(msg)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(signed))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return resp, err
	}

	c.setNonce(resp.Header.Get("Replay-Nonce"))
	return resp, err
}

func (c *Client) getWithResponse(url string, accept string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return resp, err
	}

	c.setNonce(resp.Header.Get("Replay-Nonce"))
	return resp, err
}

func (c *Client) get(url string, response response) (int, error) {
	resp, err := c.getWithResponse(url, "")
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		if resp != nil {
			return resp.StatusCode, err
		}

		return 0, err
	}

	if response != nil {
		d := json.NewDecoder(resp.Body)
		if d.Decode(response); err != nil {
			return resp.StatusCode, err
		}

		for i := range resp.Header {
			for j := range resp.Header[i] {
				response.setHeader(i, resp.Header[i][j])
			}
		}
	}

	return resp.StatusCode, nil
}

func (c *Client) sign(msg []byte) (string, error) {
	c.signer.SetNonceSource(c)
	r, err := c.signer.Sign(msg)
	if err != nil {
		return "", err
	}

	return r.FullSerialize(), nil
}

// Register tries to create a new acme account.
// If an account already exist or was successfully created,
// no error will be returned.
func (c *Client) Register(contact []string) error {
	req := &registration{"new-reg", contact, ""}
	resp := &registrationResponse{}
	if err := c.getDir(false); err != nil {
		return err
	}

	status, err := c.post(c.endpoints.NewReg, req, resp)
	if err != nil {
		return err
	}

	if status == 201 {
		if resp.Agreement != "" {
			req.Resource = "reg"
			req.Agreement = resp.Agreement
			_, err = c.post(resp.Location, req, resp)
			if err != nil {
				return err
			}
		}

		return nil
	}

	if status == 409 {
		return nil
	}

	return fmt.Errorf("Failed to register with json: %+v", resp)
}

// Authorize sends an authorize request and returns a simpleHTTP challenge,
// which can be Created and Polled.
func (c *Client) Authorize(domain string) (*Challenge, error) {
	req := &authorization{
		"new-authz",
		authIdentifier{Type: "dns", Value: domain},
	}

	resp := &authorizationResponse{}
	if err := c.getDir(false); err != nil {
		return nil, err
	}

	status, err := c.post(c.endpoints.NewAuthz, req, resp)
	if err != nil {
		return nil, err
	}

	if status != 201 {
		return nil, fmt.Errorf("Failed to create auth request with json: %+v", resp)
	}

	for _, i := range resp.Challenges {
		if i.Type == "http-01" {
			ch := &Challenge{
				challengeURI: i.URI,
				authzURI:     resp.Location,
				token:        i.Token,
				challenge: challenge{
					Resource: "challenge",
					Type:     "simpleHttp",
					KeyAuthorization: fmt.Sprintf(
						"%s.%s",
						i.Token,
						c.thumbprint,
					),
				},
				c: c,
			}

			c.m.Lock()
			defer c.m.Unlock()
			c.challenges = append(c.challenges, ch)

			return ch, nil
		}
	}

	return nil, fmt.Errorf("No supported challenges found in: %+v", resp)
}

// Cert creates/renews a certificate by sending a Certificate Signing Request.
func (c *Client) Cert(csr []byte) (certificate []byte, err error) {
	if err := c.getDir(false); err != nil {
		return nil, err
	}

	csrBase64 := base64.RawURLEncoding.EncodeToString(csr)
	req := &cert{"new-cert", csrBase64}
	resp, err := c.postWithResponse(c.endpoints.NewCert, req)
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	var location string
	for {
		certificate, err = ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != 201 && resp.StatusCode != 202 {
			return nil, fmt.Errorf("Invalid http status code: %d: %s", resp.StatusCode, string(certificate))
		}

		if len(certificate) != 0 {
			return certificate, nil
		}

		if location == "" {
			location = resp.Header.Get("Location")
			if location == "" {
				return nil, fmt.Errorf("No certificate location provided")
			}
		}

		_retry := resp.Header.Get("Retry-After")
		retry, rerr := strconv.Atoi(_retry)
		if rerr != nil || retry < 1 {
			retry = 2
		}

		time.Sleep(time.Duration(retry) * time.Second)
		resp, err = c.getWithResponse(location, "")
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}

			break
		}
	}

	return certificate, err
}
