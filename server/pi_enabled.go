//go:build encaya_pi
// +build encaya_pi

package server

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/ferhatelmas/pi"
	"github.com/miekg/dns"
)

var piPriv interface{}

func (s *Server) loadPiKey() {
	piPrivPath := s.cfg.cpath("pi_key.pem")

	piPrivPem, err := os.ReadFile(piPrivPath)
	if err != nil {
		log.Fatalef(err, "Unable to read %s", piPrivPath)
	}

	piPrivBlock, _ := pem.Decode(piPrivPem)
	//nolint:staticcheck // SA5011 Unreachable if nil due to log.Fatal
	if piPrivBlock == nil {
		log.Fatalef(err, "Unable to decode %s", piPrivPath)
	}

	//nolint:staticcheck // SA5011 Unreachable if nil due to log.Fatal
	piPrivBytes := piPrivBlock.Bytes

	piPriv, err = x509.ParsePKCS8PrivateKey(piPrivBytes)
	if err != nil {
		log.Fatalef(err, "Unable to parse %s", piPrivPath)
	}
}

func (s *Server) lookupPi(req *http.Request, domain string) (tlsa *dns.TLSA, err error) {
	// Pi meta-domains are of the form INTEGER.pi.x--nmc.bit
	metaSuffix := ".pi.x--nmc.bit"
	if !strings.HasSuffix(domain, metaSuffix) {
		return nil, nil
	}

	digitCountStr := strings.TrimSuffix(domain, metaSuffix)

	digitCount, err := strconv.ParseInt(digitCountStr, 10, 0)
	if err != nil {
		return nil, nil
	}

	purportedDigits := req.FormValue("pidigits")

	actualDigits := pi.Digits(digitCount)

	if purportedDigits != actualDigits {
		return nil, nil
	}

	// Check has passed, now we just return a pubkey. For now we always use the
	// same key because using a separate key would be more effort and this is
	// just a debug thing.

	if piPriv == nil {
		s.loadPiKey()
	}

	pub := &piPriv.(*ecdsa.PrivateKey).PublicKey

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pubHex := hex.EncodeToString(pubBytes)

	return &dns.TLSA{
		Hdr: dns.RR_Header{Name: "", Rrtype: dns.TypeTLSA, Class: dns.ClassINET,
			Ttl: 600},
		Usage:        2,
		Selector:     1,
		MatchingType: 0,
		Certificate:  strings.ToUpper(pubHex),
	}, nil
}
