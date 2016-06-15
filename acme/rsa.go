package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path"
	"strings"
)

// GenerateRSAKey generates and saves rsa private key.
// Creating necessary dirs!
func GenerateRSAKey(filepath string, bits int) (*rsa.PrivateKey, error) {
	dirname := path.Dir(filepath)

	if err := os.MkdirAll(dirname, 0755); err != nil {
		return nil, err
	}

	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	marsh := x509.MarshalPKCS1PrivateKey(priv)
	err = ioutil.WriteFile(filepath, marsh, 0600)

	return priv, err
}

// LoadOrGenerateRSAKey loads the first file that exists
// in paths as an rsa private key.
// If none were found a new key will be generated and saved to the first
// filepath in paths.
func LoadOrGenerateRSAKey(paths []string, bits int) (*rsa.PrivateKey, error) {
	if len(paths) == 0 {
		return nil, errors.New("paths can not be empty")
	}

	for i := range paths {
		f, err := os.Open(paths[i])
		if err != nil {
			continue
		}

		defer f.Close()
		raw, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, err
		}

		return x509.ParsePKCS1PrivateKey(raw)
	}

	return GenerateRSAKey(paths[0], bits)
}

// GenerateCSR returns a Certificate Signing Request
func GenerateCSR(priv *rsa.PrivateKey, main string, san []string) ([]byte, error) {
	tpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: main},
		DNSNames: san,
	}

	return x509.CreateCertificateRequest(rand.Reader, tpl, priv)
}

// FormatCSR returns a base64 encoded representation of the given csr bytes
// as openssl does.
func FormatCSR(csr []byte) string {
	csrBase64 := base64.StdEncoding.EncodeToString(csr)

	wrap := 64
	ln := int(math.Ceil(float64(len(csrBase64)) / float64(wrap)))
	split := make([]string, ln)
	for i := 0; i < len(split); i++ {
		if i == ln-1 {
			split[i] = csrBase64[i*wrap:]
			break
		}

		split[i] = csrBase64[i*wrap : (i+1)*wrap]
	}
	return fmt.Sprintf(
		"-----BEGIN CERTIFICATE REQUEST-----\n%s\n-----END CERTIFICATE REQUEST-----",
		strings.Join(split, "\n"),
	)
}
