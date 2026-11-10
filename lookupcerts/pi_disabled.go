//go:build !encaya_pi
// +build !encaya_pi

package lookupcerts

import (
	"github.com/miekg/dns"
)

func (s *Lookup) lookupPi(domain, piDigits string) (tlsa *dns.TLSA, err error) {
	// No DNS records matched. Return no cert.
	return nil, nil
}
