//go:build !encaya_pi
// +build !encaya_pi

package server

import (
	"net/http"

	"github.com/miekg/dns"
)

func (s *Server) lookupPi(req *http.Request, domain string) (tlsa *dns.TLSA, err error) {
	// No DNS records matched. Return no cert.
	return nil, nil
}
