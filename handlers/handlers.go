package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hlandau/xlog"
	"github.com/miekg/dns"

	"github.com/namecoin/crosssign"
	"github.com/namecoin/encaya/verifystapled"
	"github.com/namecoin/ncrpcclient"
	"github.com/namecoin/qlib"
	"github.com/namecoin/safetlsa"
)

var log, logPublic = xlog.New("encaya.handlers")

var Log = logPublic

type cachedCert struct {
	expiration time.Time
	certDer    []byte
}

type Handlers struct {
	dnsAddress string
	dnsPort    int
	configDir  string
	rootCert   []byte
	rootPriv   interface{}
	tldCert    []byte
	tldPriv    interface{}
	namecoin   *ncrpcclient.Client

	// These caches don't yet support stream isolation; see
	// https://github.com/namecoin/encaya/issues/8
	domainCertCache        map[string][]cachedCert
	domainCertCacheMutex   sync.RWMutex
	negativeCertCache      map[string][]cachedCert
	negativeCertCacheMutex sync.RWMutex
	originalCertCache      map[string][]cachedCert
	originalCertCacheMutex sync.RWMutex
}

func New(dnsAddress string, dnsPort int, configDir string, rootCert []byte, rootKey interface{},
	namecoinConn *ncrpcclient.Client) (*Handlers, error) {
	h := &Handlers{}
	h.dnsAddress = dnsAddress
	h.dnsPort = dnsPort
	h.configDir = configDir
	h.rootCert = rootCert
	h.rootPriv = rootKey
	h.namecoin = namecoinConn
	var err error
	h.tldCert, h.tldPriv, err = safetlsa.GenerateTLDCA("bit", h.rootCert, h.rootPriv)
	if err != nil {
		return nil, err
	}

	h.domainCertCache = map[string][]cachedCert{}
	h.negativeCertCache = map[string][]cachedCert{}
	h.originalCertCache = map[string][]cachedCert{}
	return h, nil
}

func (s *Handlers) getCachedDomainCerts(commonName string) ([][]byte, bool) {
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

func (s *Handlers) cacheDomainCert(commonName string, certDer []byte) {
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

func (s *Handlers) popCachedDomainCertLater(commonName string) {
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

func (s *Handlers) getCachedNegativeCerts(commonName string) ([][]byte, bool) {
	needRefresh := true
	results := [][]byte{}

	s.negativeCertCacheMutex.RLock()
	for _, cert := range s.negativeCertCache[commonName] {
		// Negative certs don't expire
		needRefresh = false

		results = append(results, cert.certDer)

		// We only need 1 negative cert
		break
	}
	s.negativeCertCacheMutex.RUnlock()

	return results, needRefresh
}

func (s *Handlers) cacheNegativeCert(commonName string, certDer []byte) {
	cert := cachedCert{
		expiration: time.Now().Add(safetlsa.ValidityShortTerm()),
		certDer:    certDer,
	}

	s.negativeCertCacheMutex.Lock()
	if s.negativeCertCache[commonName] == nil {
		s.negativeCertCache[commonName] = []cachedCert{cert}
	} else {
		s.negativeCertCache[commonName] = append(s.negativeCertCache[commonName], cert)
	}
	s.negativeCertCacheMutex.Unlock()
}

func (s *Handlers) getCachedOriginalFromSerial(serial string) ([][]byte, bool) {
	needRefresh := true
	results := [][]byte{}

	s.originalCertCacheMutex.RLock()
	for _, cert := range s.originalCertCache[serial] {
		// Original certs don't expire
		needRefresh = false

		results = append(results, cert.certDer)

		// We only need 1 original cert
		break
	}
	s.originalCertCacheMutex.RUnlock()

	return results, needRefresh
}

func (s *Handlers) cacheOriginalFromSerial(serial string, certDer []byte) {
	cert := cachedCert{
		expiration: time.Now().Add(safetlsa.ValidityShortTerm()),
		certDer:    certDer,
	}

	s.originalCertCacheMutex.Lock()
	if s.originalCertCache[serial] == nil {
		s.originalCertCache[serial] = []cachedCert{cert}
	} else {
		s.originalCertCache[serial] = append(s.originalCertCache[serial], cert)
	}
	s.originalCertCacheMutex.Unlock()
}

func (s *Handlers) IndexHandler(writer http.ResponseWriter, req *http.Request) {
	indexMessage := `<!DOCTYPE html>
<html>
	<head>
		<title>Namecoin Encaya</title>
	</head>
	<body>
		<h1>Namecoin Encaya</h1>
		<p>Welcome to Namecoin Encaya!  If you can see this message, Encaya is 
		running.  If you want to use this Encaya instance on another device, 
		you can install the Encaya Root CA from one of the below links:</p>
		<ul>
			<li><a href="/aia?domain=Namecoin%20Root%20CA">DER format</a></li>
			<li><a href="/lookup?domain=Namecoin%20Root%20CA">PEM format</a></li>
		</ul>
	</body>
</html>`

	_, err := io.WriteString(writer, indexMessage)
	if err != nil {
		log.Debuge(err, "write error")
	}
}

func (s *Handlers) lookupBlockchainMessage(req *http.Request, domain string) (tlsa *dns.TLSA, err error) {
	log.Debugf("querying for pubkey via off-chain message: %s", domain)

	stapledData := &verifystapled.StapledData{
		MessageHeader: "Namecoin X.509 Stapled Certification: ",
		PubType: "x509pub",

		Domain: domain,

		PubBase64: req.FormValue("pubb64"),
		SigsJSON: req.FormValue("sigs"),

		NotAfter: req.FormValue("notafter"),
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

func (s *Handlers) lookupDNS(req *http.Request, domain string) (tlsa *dns.TLSA, err error) {
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

	pubSHA256Hex := req.FormValue("pubsha256")

	pubSHA256, err := hex.DecodeString(pubSHA256Hex)
	if err != nil {
		// Requested public key hash is malformed.
		log.Debugf("stapled public key hash is invalid hex: %s", domain)
		return nil, nil
	}

	pubBase64 := req.FormValue("pubb64")

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

		// CA not in user's trust store; public key; unspecified hash
		if tlsa.Usage == 2 && tlsa.Selector == 1 {
			if tlsa.MatchingType == 0 { // Not hashed
				tlsaPubBytes, err := hex.DecodeString(tlsa.Certificate)
				if err != nil {
					// TLSA record is malformed
					continue
				}

				// TODO: Special-case empty stapled pubkey. We should remove this
				// special-case once stapled pubkeys are used everywhere.
				if len(pubBytes) > 0 && !bytes.Equal(pubBytes, tlsaPubBytes) {
					// TLSA record doesn't match requested public key preimage
					continue
				}

				tlsaPubSHA256 := sha256.Sum256(tlsaPubBytes)
				// TODO: Special-case empty stapled pubkey. We should remove this
				// special-case once stapled pubkeys are used everywhere.
				//if !bytes.Equal(pubSHA256, tlsaPubSHA256[:]) {
				if len(pubSHA256) > 0 && !bytes.Equal(pubSHA256, tlsaPubSHA256[:]) {
					// TLSA record doesn't match requested public key hash
					continue
				}
			} else if tlsa.MatchingType == 1 { // SHA-256
				tlsaPubSHA256, err := hex.DecodeString(tlsa.Certificate)
				if err != nil {
					// TLSA record is malformed
					continue
				}

				pubBytesSHA256 := sha256.Sum256(pubBytes)
				if !bytes.Equal(pubBytesSHA256[:], tlsaPubSHA256) {
					continue
				}

				// Fill in verified preimage into TLSA record
				tlsa.MatchingType = 0
				tlsa.Certificate = hex.EncodeToString(pubBytes)
			} else if tlsa.MatchingType == 2 { // SHA-512
				tlsaPubSHA512, err := hex.DecodeString(tlsa.Certificate)
				if err != nil {
					// TLSA record is malformed
					continue
				}

				pubBytesSHA512 := sha512.Sum512(pubBytes)
				if !bytes.Equal(pubBytesSHA512[:], tlsaPubSHA512) {
					continue
				}

				// Fill in verified preimage into TLSA record
				tlsa.MatchingType = 0
				tlsa.Certificate = hex.EncodeToString(pubBytes)
			}
		} else {
			// TLSA record isn't in the Namecoin CA form
			continue
		}

		return tlsa, nil
	}

	// No DNS records matched. Return no cert.
	return nil, nil
}

func (s *Handlers) lookupCert(req *http.Request) (certDer []byte, shortTerm bool, err error) {
	commonName := req.FormValue("domain")

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

	tlsa, err := s.lookupPi(req, domain)
	if err != nil {
		return nil, false, err
	}

	if tlsa == nil {
		tlsa, err = s.lookupBlockchainMessage(req, domain)
		if err != nil {
			return nil, false, err
		}
	}

	if tlsa == nil {
		tlsa, err = s.lookupDNS(req, domain)
		if err != nil {
			return nil, false, err
		}
	}

	if tlsa == nil {
		return nil, false, nil
	}

	stapled := map[string]string{}

	stapledKeys := []string{"notafter", "pidigits", "pubb64", "sigs"}
	for _, stapledKey := range stapledKeys {
		stapledValue := req.FormValue(stapledKey)
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

func (s *Handlers) writePemBundle(writer http.ResponseWriter, certs [][]byte) {
	for _, cert := range certs {
		certPemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		})

		certPem := string(certPemBytes)

		_, err := io.WriteString(writer, certPem + "\n\n")
		if err != nil {
			log.Debuge(err, "write error")
		}
	}
}

func (s *Handlers) LookupHandler(writer http.ResponseWriter, req *http.Request) {
	writer.Header().Set("Content-Type", "application/x-pem-file")

	commonName := req.FormValue("domain")

	log.Debugf("PEM lookup: %s", commonName)

	resultCerts := [][]byte{}

	cachedCerts, needRefresh := s.getCachedDomainCerts(commonName)
	if needRefresh {
		requestedCert, _, err := s.lookupCert(req)
		if err != nil {
			log.Debuge(err, "cert lookup error")
			writer.WriteHeader(http.StatusInternalServerError)
			return
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

	s.writePemBundle(writer, resultCerts)
}

func (s *Handlers) AIAHandler(writer http.ResponseWriter, req *http.Request) {
	writer.Header().Set("Content-Type", "application/pkix-cert")

	commonName := req.FormValue("domain")

	log.Debugf("DER lookup: %s", commonName)

	requestedCert, shortTerm, err := s.lookupCert(req)
	if err != nil {
		log.Debuge(err, "cert lookup error")
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	if requestedCert == nil {
		// Cert not found.
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	if shortTerm {
		// Set short-term caching duration of half the cert validity
		maxAge := safetlsa.ValidityShortTerm() / 2
		maxAgeSeconds := int(maxAge / time.Second)
		maxAgeStr := strconv.Itoa(maxAgeSeconds)
		writer.Header().Set("Cache-Control", "max-age="+maxAgeStr)
	}

	//nolint:gosec // G705: The response body is a DER certificate, not HTML.
	_, err = writer.Write(requestedCert)
	if err != nil {
		log.Debuge(err, "write error")
	}
}

func (s *Handlers) GetNewNegativeCAHandler(writer http.ResponseWriter, req *http.Request) {
	restrictCert, restrictPriv, err := safetlsa.GenerateTLDExclusionCA("bit", s.rootCert, s.rootPriv)
	if err != nil {
		log.Debuge(err, "Error generating TLD exclusion CA")
	}

	restrictCertPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: restrictCert,
	})
	restrictCertPemString := string(restrictCertPem)

	restrictPrivBytes, err := x509.MarshalECPrivateKey(restrictPriv.(*ecdsa.PrivateKey))
	if err != nil {
		log.Debuge(err, "Unable to marshal ECDSA private key")
	}

	restrictPrivPem := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: restrictPrivBytes,
	})
	restrictPrivPemString := string(restrictPrivPem)

	_, err = io.WriteString(writer, restrictCertPemString)
	if err != nil {
		log.Debuge(err, "write error")
	}

	_, err = io.WriteString(writer, "\n\n")
	if err != nil {
		log.Debuge(err, "write error")
	}

	_, err = io.WriteString(writer, restrictPrivPemString)
	if err != nil {
		log.Debuge(err, "write error")
	}
}

func (s *Handlers) CrossSignCAHandler(writer http.ResponseWriter, req *http.Request) {
	var err error

	toSignPEM := req.FormValue("to-sign")
	signerCertPEM := req.FormValue("signer-cert")
	signerKeyPEM := req.FormValue("signer-key")

	cacheKeyArray := sha256.Sum256([]byte(toSignPEM + "\n\n" + signerCertPEM + "\n\n" + signerKeyPEM + "\n\n"))
	cacheKey := hex.EncodeToString(cacheKeyArray[:])

	cacheResults, needRefresh := s.getCachedNegativeCerts(cacheKey)
	if !needRefresh {
		s.writePemBundle(writer, cacheResults)

		return
	}

	toSignBlock, _ := pem.Decode([]byte(toSignPEM))
	signerCertBlock, _ := pem.Decode([]byte(signerCertPEM))
	signerKeyBlock, _ := pem.Decode([]byte(signerKeyPEM))

	signerKey, err := x509.ParseECPrivateKey(signerKeyBlock.Bytes)
	if err != nil {
		log.Debuge(err, "Unable to parse ECDSA private key")

		return
	}

	resultBytes, err := crosssign.CrossSign(toSignBlock.Bytes, signerCertBlock.Bytes, signerKey)
	if err != nil {
		log.Debuge(err, "Unable to cross-sign")

		return
	}

	resultPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: resultBytes,
	})
	resultPEMString := string(resultPEM)

	resultParsed, err := x509.ParseCertificate(resultBytes)
	if err != nil {
		log.Debuge(err, "Unable to extract serial number from cross-signed CA")
	}

	_, err = io.WriteString(writer, resultPEMString)
	if err != nil {
		log.Debuge(err, "write error")
	}

	s.cacheNegativeCert(cacheKey, resultBytes)
	s.cacheOriginalFromSerial(resultParsed.SerialNumber.String(), toSignBlock.Bytes)
}

func (s *Handlers) OriginalFromSerialHandler(writer http.ResponseWriter, req *http.Request) {
	serial := req.FormValue("serial")

	cacheResults, needRefresh := s.getCachedOriginalFromSerial(serial)
	if !needRefresh {
		s.writePemBundle(writer, cacheResults)
	}
}
