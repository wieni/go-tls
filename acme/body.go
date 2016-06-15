package acme

import (
	"strconv"
	"strings"
)

type directory struct {
	NewReg   string `json:"new-reg"`
	NewAuthz string `json:"new-authz"`
	NewCert  string `json:"new-cert"`
}

type registration struct {
	Resource  string   `json:"resource"`
	Contact   []string `json:"contact"`
	Agreement string   `json:"agreement,omitempty"`
}

type authIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type authorization struct {
	Resource   string         `json:"resource"`
	Identifier authIdentifier `json:"identifier"`
}

type challenge struct {
	Resource         string `json:"resource"`
	Type             string `json:"type"`
	KeyAuthorization string `json:"keyAuthorization"`
}

type cert struct {
	Resource string `json:"resource"`
	CSR      string `json:"csr"`
}

type response interface {
	setHeader(key, value string)
}

type errResponse struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

type registrationResponse struct {
	errResponse
	ID        int    `json:"id"` // only populated on 201
	Agreement string `json:"-"`  // from Link header
	Location  string `json:"-"`  // from Location header
}

func (r *registrationResponse) setHeader(key, value string) {
	if key == "Location" {
		r.Location = value
	}

	if key == "Link" {
		s := strings.Split(strings.TrimSpace(value), ";")
		if len(s) != 2 {
			return
		}

		uri := strings.Trim(s[0], "<>")
		if s[1] == "rel=\"terms-of-service\"" {
			r.Agreement = uri
		}
	}

}

type authChallenge struct {
	Type      string `json:"type"`
	Status    string `json:"status"`
	Validated string `json:"validated"`
	URI       string `json:"uri"`
	Token     string `json:"token"`
}

type authorizationResponse struct {
	errResponse
	Status       string          `json:"status"`
	Identifier   authIdentifier  `json:"identifier"`
	Challenges   []authChallenge `json:"challenges"`
	Combinations [][]int         `json:"combinations"`
	Location     string          `json:"-"` // from Location header
	RetryAfter   int             `json:"-"` // from Retry-After header

}

func (a *authorizationResponse) setHeader(key, value string) {
	if key == "Location" {
		a.Location = value
	}

	if key == "Retry-After" {
		a.RetryAfter, _ = strconv.Atoi(value)
	}
}
