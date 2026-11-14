package lookupcerts

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hlandau/xlog"
	"github.com/miekg/dns"

	"github.com/namecoin/encaya/verifystapled"
	"github.com/namecoin/ncdns/tlshook"
	"github.com/namecoin/ncrpcclient"
	"github.com/namecoin/qlib"
	"github.com/namecoin/safetlsa"
)

var log, logPublic = xlog.New("encaya.lookupcerts")

var Log = logPublic

type cachedCert struct {
	expiration time.Time
	certDer    []byte
}

type Lookup struct {
	configDir  string
	rootCert   []byte
	tldCert    []byte
	tldPriv    interface{}

	useNcdnsCache bool
	dnsAddress string
	dnsPort    int
	namecoin   *ncrpcclient.Client

	// These caches don't yet support stream isolation; see
	// https://github.com/namecoin/encaya/issues/8
	domainCertCache      map[string][]cachedCert
	domainCertCacheMutex sync.RWMutex
}

func New(dnsAddress string, dnsPort int, configDir string, rootCert []byte, rootKey interface{},
	namecoinConn *ncrpcclient.Client, useNcdnsCache bool) (*Lookup, error) {
	h := &Lookup{}

	h.configDir = configDir
	h.rootCert = rootCert

	h.useNcdnsCache = useNcdnsCache
	h.dnsAddress = dnsAddress
	h.dnsPort = dnsPort
	h.namecoin = namecoinConn

	var err error
	h.tldCert, h.tldPriv, err = safetlsa.GenerateTLDCA("bit", rootCert, rootKey)
	if err != nil {
		return nil, err
	}

	h.domainCertCache = map[string][]cachedCert{}
	return h, nil
}

func (s *Lookup) getCachedDomainCerts(commonName string) ([][]byte, bool) {
	needRefresh := true
	results := [][]byte{}

	s.domainCertCacheMutex.RLock()
	for _, cert := range s.domainCertCache[commonName] {
		if time.Until(cert.expiration) > safetlsa.ValidityShortTerm()/2 {
			needRefresh = false
		}

		results = append(results, cert.certDer)
	}
	s.domainCertCacheMutex.RUnlock()

	return results, needRefresh
}

func (s *Lookup) cacheDomainCert(commonName string, certDer []byte) {
	cert := cachedCert{
		expiration: time.Now().Add(safetlsa.ValidityShortTerm()),
		certDer:    certDer,
	}

	s.domainCertCacheMutex.Lock()
	if s.domainCertCache[commonName] == nil {
		s.domainCertCache[commonName] = []cachedCert{cert}
	} else {
		s.domainCertCache[commonName] = append(s.domainCertCache[commonName], cert)
	}
	s.domainCertCacheMutex.Unlock()
}

func (s *Lookup) popCachedDomainCertLater(commonName string) {
	time.Sleep(safetlsa.ValidityShortTerm())

	s.domainCertCacheMutex.Lock()
	if s.domainCertCache[commonName] != nil {
		if len(s.domainCertCache[commonName]) > 1 {
			s.domainCertCache[commonName] = s.domainCertCache[commonName][1:]
		} else {
			delete(s.domainCertCache, commonName)
		}
	}
	s.domainCertCacheMutex.Unlock()
}

func (s *Lookup) lookupBlockchainMessage(domain, pubB64, sigs, notAfter string) (tlsa *dns.TLSA, err error) {
	log.Debugf("querying for pubkey via off-chain message: %s", domain)

	stapledData := &verifystapled.StapledData{
		MessageHeader: "Namecoin X.509 Stapled Certification: ",
		PubType: "x509pub",

		Domain: domain,

		PubBase64: pubB64,
		SigsJSON: sigs,

		NotAfter: notAfter,
	}

	ok, err := stapledData.Verify(s.namecoin)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	// At this point, signature check has passed.

	// We use RawURLEncoding because it results in compact, readable URL's.
	pubBytes, err := base64.RawURLEncoding.DecodeString(stapledData.PubBase64)
	if err != nil {
		log.Debugf("stapled public key is invalid base64: %s", domain)
		return nil, nil
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

func fillInTLSAPreimage(tlsa *dns.TLSA, pubSHA256, pubBytes []byte) *dns.TLSA {
	// DANE-TA, public key; unspecified hash
	if tlsa.Usage == 2 && tlsa.Selector == 1 {
		switch tlsa.MatchingType {
		case 0: // Not hashed
			tlsaPubBytes, err := hex.DecodeString(tlsa.Certificate)
			if err != nil {
				// TLSA record is malformed
				return nil
			}

			// TODO: Special-case empty stapled pubkey. We should remove this
			// special-case once stapled pubkeys are used everywhere.
			if len(pubBytes) > 0 && !bytes.Equal(pubBytes, tlsaPubBytes) {
				// TLSA record doesn't match requested public key preimage
				return nil
			}

			tlsaPubSHA256 := sha256.Sum256(tlsaPubBytes)
			// TODO: Special-case empty stapled pubkey. We should remove this
			// special-case once stapled pubkeys are used everywhere.
			//if !bytes.Equal(pubSHA256, tlsaPubSHA256[:]) {
			if len(pubSHA256) > 0 && !bytes.Equal(pubSHA256, tlsaPubSHA256[:]) {
				// TLSA record doesn't match requested public key hash
				return nil
			}
		case 1: // SHA-256
			tlsaPubSHA256, err := hex.DecodeString(tlsa.Certificate)
			if err != nil {
				// TLSA record is malformed
				return nil
			}

			pubBytesSHA256 := sha256.Sum256(pubBytes)
			if !bytes.Equal(pubBytesSHA256[:], tlsaPubSHA256) {
				return nil
			}

			// Fill in verified preimage into TLSA record
			tlsa.MatchingType = 0
			tlsa.Certificate = hex.EncodeToString(pubBytes)
		case 2: // SHA-512
			tlsaPubSHA512, err := hex.DecodeString(tlsa.Certificate)
			if err != nil {
				// TLSA record is malformed
				return nil
			}

			pubBytesSHA512 := sha512.Sum512(pubBytes)
			if !bytes.Equal(pubBytesSHA512[:], tlsaPubSHA512) {
				return nil
			}

			// Fill in verified preimage into TLSA record
			tlsa.MatchingType = 0
			tlsa.Certificate = hex.EncodeToString(pubBytes)
		}
	} else {
		// TLSA record isn't in the Namecoin CA form
		return nil
	}

	return tlsa
}

func (s *Lookup) lookupDNS(domain, pubSHA256Hex, pubBase64 string) (tlsa *dns.TLSA, err error) {
	log.Debugf("querying for pubkey via DNS: %s", domain)

	qparams := qlib.DefaultParams()
	qparams.Port = s.dnsPort
	qparams.Ad = true
	qparams.Fallback = true
	qparams.Tcp = true // Workaround for https://github.com/miekg/exdns/issues/19

	args := []string{}
	// Set the custom DNS server if requested
	if s.dnsAddress != "" {
		args = append(args, "@"+s.dnsAddress)
	}
	// Set qtype to TLSA
	args = append(args, "TLSA")
	// Set qname to all protocols and all ports of requested hostname
	args = append(args, "*."+domain)

	result, err := qparams.Do(args)
	if err != nil {
		// A DNS error occurred.
		log.Debuge(err, "qlib error")
		return nil, fmt.Errorf("qlib error: %w", err)
	}

	if result.ResponseMsg == nil {
		// A DNS error occurred (nil response).
		return nil, fmt.Errorf("qlib error: nil response")
	}

	dnsResponse := result.ResponseMsg
	if dnsResponse.Rcode != dns.RcodeSuccess && dnsResponse.Rcode != dns.RcodeNameError {
		// A DNS error occurred (return code wasn't Success or NXDOMAIN).
		return nil, fmt.Errorf("qlib error: return code not Success or NXDOMAIN")
	}

	if dnsResponse.Rcode == dns.RcodeNameError {
		// Wildcard subdomain doesn't exist.
		// That means the domain doesn't use Namecoin-form DANE.
		// Return no cert.
		log.Debugf("wildcard subdomain doesn't exist: %s", domain)
		return nil, nil
	}

	if !dnsResponse.AuthenticatedData && !dnsResponse.Authoritative {
		// For security reasons, we only trust records that are
		// authenticated (e.g. server is Unbound and has verified
		// DNSSEC sigs) or authoritative (e.g. server is ncdns and is
		// the owner of the requested zone).  If neither is the case,
		// then return no cert.
		log.Debugf("DNS record not authenticated and not authoritative: %s", domain)
		return nil, nil
	}

	pubSHA256, err := hex.DecodeString(pubSHA256Hex)
	if err != nil {
		// Requested public key hash is malformed.
		log.Debugf("stapled public key hash is invalid hex: %s", domain)
		return nil, nil
	}

	// We use RawURLEncoding because it results in compact, readable URL's.
	pubBytes, err := base64.RawURLEncoding.DecodeString(pubBase64)
	if err != nil {
		// Requested public key is malformed.
		log.Debugf("stapled public key is invalid base64: %s", domain)
		return nil, nil
	}

	for _, rr := range dnsResponse.Answer {
		tlsa, ok := rr.(*dns.TLSA)
		if !ok {
			// Record isn't a TLSA record
			continue
		}

		tlsaFilled := fillInTLSAPreimage(tlsa, pubSHA256, pubBytes)
		if tlsaFilled != nil {
			return tlsaFilled, nil
		}
	}

	// No DNS records matched. Return no cert.
	return nil, nil
}

func (s *Lookup) lookupNcdnsCache(domain, pubSHA256Hex, pubBase64 string) (tlsa *dns.TLSA, err error) {
	log.Debugf("querying for pubkey via ncdns PKI cache: %s", domain)

	tlsaRecords, err := tlshook.GetTLSARecords(domain)
	if err != nil {
		return nil, fmt.Errorf("tlshook TLSA error: %w", err)
	}

	pubSHA256, err := hex.DecodeString(pubSHA256Hex)
	if err != nil {
		// Requested public key hash is malformed.
		log.Debugf("stapled public key hash is invalid hex: %s", domain)
		return nil, nil
	}

	// We use RawURLEncoding because it results in compact, readable URL's.
	pubBytes, err := base64.RawURLEncoding.DecodeString(pubBase64)
	if err != nil {
		// Requested public key is malformed.
		log.Debugf("stapled public key is invalid base64: %s", domain)
		return nil, nil
	}

	for _, tlsa := range tlsaRecords {
		tlsaFilled := fillInTLSAPreimage(tlsa, pubSHA256, pubBytes)
		if tlsaFilled != nil {
			return tlsaFilled, nil
		}
	}

	// No DNS records matched. Return no cert.
	return nil, nil
}

func (s *Lookup) LookupCert(commonName, pubSHA256, pubB64, sigs, notAfter, piDigits string) (certDer []byte, shortTerm bool, err error) {
	if commonName == "Namecoin Root CA" {
		return s.rootCert, false, nil
	}

	if commonName == ".bit TLD CA" {
		return s.tldCert, false, nil
	}

	domain := strings.TrimSuffix(commonName, " Domain AIA Parent CA")

	if strings.Contains(domain, " ") {
		// CommonNames that contain a space are usually CA's.  We
		// already stripped the suffixes of Namecoin-formatted CA's, so
		// if a space remains, just return no cert.
		return nil, false, nil
	}

	tlsa, err := s.lookupPi(domain, piDigits)
	if err != nil {
		return nil, false, err
	}

	if s.useNcdnsCache {
		// Only use ncdns cache to avoid fingerprinting risk; does not work for standalone Encaya; does not support blockchain messages yet
		if tlsa == nil {
			tlsa, err = s.lookupNcdnsCache(domain, pubSHA256, pubB64)
			if err != nil {
				return nil, false, err
			}
		}
	} else {
		// Generate network traffic with standalone Encaya; vulnerable to fingerprinting
		if tlsa == nil {
			tlsa, err = s.lookupBlockchainMessage(domain, pubB64, sigs, notAfter)
			if err != nil {
				return nil, false, err
			}
		}

		if tlsa == nil {
			tlsa, err = s.lookupDNS(domain, pubSHA256, pubB64)
			if err != nil {
				return nil, false, err
			}
		}
	}

	if tlsa == nil {
		return nil, false, nil
	}

	stapled := map[string]string{}

	stapledKeys := []string{"notafter", "pidigits", "pubb64", "sigs"}
	stapledValues := []string{notAfter, piDigits, pubB64, sigs}
	for i, stapledKey := range stapledKeys {
		stapledValue := stapledValues[i]
		if stapledValue != "" {
			stapled[stapledKey] = stapledValue
		}
	}

	if len(stapled) == 0 {
		stapled = nil
	}

	safeCert, err := safetlsa.GetCertFromTLSA(domain, tlsa, s.tldCert, s.tldPriv, stapled)
	if err != nil {
		return nil, false, err
	}

	// Success.  Send the cert as a response.
	return safeCert, true, nil
}

func (s *Lookup) LookupCerts(commonName, pubSHA256, pubB64, sigs, notAfter, piDigits string) ([][]byte, error) {
	resultCerts := [][]byte{}

	cachedCerts, needRefresh := s.getCachedDomainCerts(commonName)
	if needRefresh {
		requestedCert, _, err := s.LookupCert(commonName, pubSHA256, pubB64, sigs, notAfter, piDigits)
		if err != nil {
			return nil, err
		}

		if requestedCert != nil {
			resultCerts = append(resultCerts, requestedCert)

			// Sometimes an ncp11 query depends on a cache entry from a previous
			// query, so these cache writes must be done synchronously (not on a
			// goroutine).
			s.cacheDomainCert(commonName, requestedCert)

			if commonName != "Namecoin Root CA" && commonName != ".bit TLD CA" {
				// Cache Domain AIA Parent CA under the TLD CA's CommonName too, since
				// ncp11 queries by Issuer, not just Subject.
				s.cacheDomainCert(".bit TLD CA", requestedCert)
			}
		}
	}

	resultCerts = append(resultCerts, cachedCerts...)

	if commonName == "Namecoin Root CA" {
		// Return the TLD CA too, since ncp11 queries by Issuer, not just
		// Subject.
		resultCerts = append(resultCerts, s.tldCert)
	}

	go s.popCachedDomainCertLater(commonName)
	go s.popCachedDomainCertLater(".bit TLD CA")

	return resultCerts, nil
}

func (s *Lookup) isRevokedNcdnsCache(commonName, subjectHashHex, serialHashHex string) (bool, error) {
	subjectHashBytes, err := hex.DecodeString(subjectHashHex)
	if err != nil {
		return false, fmt.Errorf("subject hash not valid hex")
	}

	serialHashBytes, err := hex.DecodeString(serialHashHex)
	if err != nil {
		return false, fmt.Errorf("serial hash not valid hex")
	}

	return tlshook.IsRevoked(commonName, subjectHashBytes, serialHashBytes)
}

func (s *Lookup) IsRevoked(commonName, subjectHashHex, serialHashHex string) (bool, error) {
	if s.useNcdnsCache {
		// Only use ncdns cache to avoid fingerprinting risk; does not work for standalone Encaya
		return s.isRevokedNcdnsCache(commonName, subjectHashHex, serialHashHex)
	}

	return false, fmt.Errorf("revocation check requires ncdns PKI cache")
}
