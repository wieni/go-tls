package acme

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net/http"

	"golang.org/x/crypto/ocsp"
)

type ocspCertificate struct {
	*tls.Certificate
	issuer *x509.Certificate
}

func (o *ocspCertificate) update() error {
	if o.Leaf == nil || o.issuer == nil {
		return errors.New("Empty issuer/leaf certficate")
	}

	ocsp, err := getOCSPStaple(o.Leaf, o.issuer)
	if err != nil {
		return err
	}

	o.OCSPStaple = ocsp
	return nil
}

func getOCSPStaple(cert, issuer *x509.Certificate) ([]byte, error) {
	if len(cert.OCSPServer) == 0 {
		return nil, errors.New("No OCSP server in certificate")
	}

	b, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(b)

	resp, err := http.Post(cert.OCSPServer[0], "text/ocsp", r)
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if _, err := ocsp.ParseResponse(raw, issuer); err != nil {
		return nil, err
	}

	return raw, nil
}
