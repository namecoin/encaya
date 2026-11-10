//go:build !encaya_pi
// +build !encaya_pi

package handlers

import (
	"net/http"

	"github.com/miekg/dns"
)

func (s *Handlers) lookupPi(req *http.Request, domain string) (tlsa *dns.TLSA, err error) {
	// No DNS records matched. Return no cert.
	return nil, nil
}
