package handlers

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/hlandau/xlog"

	"github.com/namecoin/crosssign"
	"github.com/namecoin/encaya/lookupcerts"
	"github.com/namecoin/ncrpcclient"
	"github.com/namecoin/safetlsa"
)

var log, logPublic = xlog.New("encaya.handlers")

var Log = logPublic

type cachedCert struct {
	expiration time.Time
	certDer    []byte
}

type Handlers struct {
	rootCert []byte
	rootPriv interface{}
	lookup   *lookupcerts.Lookup

	// These caches don't yet support stream isolation; see
	// https://github.com/namecoin/encaya/issues/8
	negativeCertCache      map[string][]cachedCert
	negativeCertCacheMutex sync.RWMutex
	originalCertCache      map[string][]cachedCert
	originalCertCacheMutex sync.RWMutex
}

func New(dnsAddress string, dnsPort int, configDir string, rootCert []byte, rootKey interface{},
	namecoinConn *ncrpcclient.Client, useNcdnsCache bool) (*Handlers, error) {
	h := &Handlers{}
	h.rootCert = rootCert
	h.rootPriv = rootKey
	var err error
	h.lookup, err = lookupcerts.New(dnsAddress, dnsPort, configDir, rootCert, rootKey, namecoinConn, useNcdnsCache)
	if err != nil {
		return nil, err
	}

	h.negativeCertCache = map[string][]cachedCert{}
	h.originalCertCache = map[string][]cachedCert{}
	return h, nil
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

	resultCerts, err := s.lookup.LookupCerts(commonName, req.FormValue("pubsha256"), req.FormValue("pubb64"),
		req.FormValue("sigs"), req.FormValue("notafter"), req.FormValue("pidigits"))
	if err != nil {
		log.Debuge(err, "cert lookup error")
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.writePemBundle(writer, resultCerts)
}

func (s *Handlers) AIAHandler(writer http.ResponseWriter, req *http.Request) {
	writer.Header().Set("Content-Type", "application/pkix-cert")

	commonName := req.FormValue("domain")

	log.Debugf("DER lookup: %s", commonName)

	requestedCert, shortTerm, err := s.lookup.LookupCert(commonName, req.FormValue("pubsha256"), req.FormValue("pubb64"),
		req.FormValue("sigs"), req.FormValue("notafter"), req.FormValue("pidigits"))
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

func (s *Handlers) RevokedHandler(writer http.ResponseWriter, req *http.Request) {
	writer.Header().Set("Content-Type", "application/json")

	commonName := req.FormValue("domain")
	serialHex := req.FormValue("serhex")

	log.Debugf("Revocation lookup: %s, serial %s", commonName, serialHex)

	revoked, err := s.lookup.IsRevoked(commonName, serialHex)
	if err != nil {
		log.Debuge(err, "revocation lookup error")
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	revokedObject := map[string]bool {
		"revoked": revoked,
	}

	revokedJSON, err := json.Marshal(revokedObject)
	if err != nil {
		log.Debuge(err, "revocation marshal error")
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = writer.Write(revokedJSON)
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
