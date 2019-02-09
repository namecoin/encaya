package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/namecoin/crosssign"
	"github.com/namecoin/qlib"
	"github.com/namecoin/safetlsa"
)

type cachedCert struct {
	expiration time.Time
	certPem string
}

var (
	rootCert []byte
	rootPriv interface{}
	rootCertPem []byte
	rootCertPemString string
	tldCert []byte
	tldPriv interface{}
	tldCertPem []byte
	tldCertPemString string
	domainCertCache map[string][]cachedCert // TODO: stream isolation
	domainCertCacheMutex sync.RWMutex
	negativeCertCache map[string][]cachedCert // TODO: stream isolation
	negativeCertCacheMutex sync.RWMutex
	originalCertCache map[string][]cachedCert // TODO: stream isolation
	originalCertCacheMutex sync.RWMutex
)

func getCachedDomainCerts(commonName string) (string, bool) {
	needRefresh := true
	results := ""

	domainCertCacheMutex.RLock()
	for _, cert := range domainCertCache[commonName] {
		if time.Until(cert.expiration) > 1 * time.Minute {
			needRefresh = false
		}

		results = results + cert.certPem + "\n\n"
	}
	domainCertCacheMutex.RUnlock()

	return results, needRefresh
}

func cacheDomainCert(commonName, certPem string) {
	cert := cachedCert{
		expiration: time.Now().Add(2 * time.Minute),
		certPem: certPem,
	}

	domainCertCacheMutex.Lock()
	if domainCertCache[commonName] == nil {
		domainCertCache[commonName] = []cachedCert{cert}
	} else {
		domainCertCache[commonName] = append(domainCertCache[commonName], cert)
	}
	domainCertCacheMutex.Unlock()
}

func popCachedDomainCertLater(commonName string) {
	time.Sleep(2 * time.Minute)

	domainCertCacheMutex.Lock()
	if domainCertCache[commonName] != nil {
		if len(domainCertCache[commonName]) > 1 {
			domainCertCache[commonName] = domainCertCache[commonName][1:]
		} else {
			delete(domainCertCache, commonName)
		}
	}
	domainCertCacheMutex.Unlock()
}

func getCachedNegativeCerts(commonName string) (string, bool) {
	needRefresh := true
	results := ""

	negativeCertCacheMutex.RLock()
	for _, cert := range negativeCertCache[commonName] {
		// Negative certs don't expire
		needRefresh = false

		results = results + cert.certPem + "\n\n"

		// We only need 1 negative cert
		break
	}
	negativeCertCacheMutex.RUnlock()

	return results, needRefresh
}

func cacheNegativeCert(commonName, certPem string) {
	cert := cachedCert{
		expiration: time.Now().Add(2 * time.Minute),
		certPem: certPem,
	}

	negativeCertCacheMutex.Lock()
	if negativeCertCache[commonName] == nil {
		negativeCertCache[commonName] = []cachedCert{cert}
	} else {
		negativeCertCache[commonName] = append(negativeCertCache[commonName], cert)
	}
	negativeCertCacheMutex.Unlock()
}

func getCachedOriginalFromSerial(serial string) (string, bool) {
	needRefresh := true
	results := ""

	originalCertCacheMutex.RLock()
	for _, cert := range originalCertCache[serial] {
		// Original certs don't expire
		needRefresh = false

		results = results + cert.certPem + "\n\n"

		// We only need 1 original cert
		break
	}
	originalCertCacheMutex.RUnlock()

	return results, needRefresh
}

func cacheOriginalFromSerial(serial, certPem string) {
	cert := cachedCert{
		expiration: time.Now().Add(2 * time.Minute),
		certPem: certPem,
	}

	originalCertCacheMutex.Lock()
	if originalCertCache[serial] == nil {
		originalCertCache[serial] = []cachedCert{cert}
	} else {
		originalCertCache[serial] = append(originalCertCache[serial], cert)
	}
	originalCertCacheMutex.Unlock()
}

func lookupHandler(w http.ResponseWriter, req *http.Request) {
	domain := req.FormValue("domain")

	if domain == "Namecoin Root CA" {
		io.WriteString(w, rootCertPemString)

		return
	}

	if domain == ".bit TLD CA" {
		io.WriteString(w, tldCertPemString)

		return
	}

	cacheResults, needRefresh := getCachedDomainCerts(domain)
	if !needRefresh {
		io.WriteString(w, cacheResults)
		return
	}

	domain = strings.TrimSuffix(domain, " Domain CA")

	if strings.Contains(domain, " ") {
		// CommonNames that contain a space are usually CA's.  We
		// already stripped the suffixes of Namecoin-formatted CA's, so
		// if a space remains, just return.
		return
	}

	qparams := qlib.DefaultParams()
	qparams.Ad = true
	qparams.Fallback = true
	qparams.Tcp = true // Workaround for https://github.com/miekg/exdns/issues/19
	result, err := qparams.Do([]string{"TLSA", "_443._tcp." + domain})
	if err != nil {
		// A DNS error occurred.
		log.Printf("qlib error: %s", err)
		w.WriteHeader(500)
		return
	}
	if result.ResponseMsg == nil {
		// A DNS error occurred (nil response).
		w.WriteHeader(500)
		return
	}
	dnsResponse := result.ResponseMsg
	if dnsResponse.MsgHdr.Rcode != dns.RcodeSuccess && dnsResponse.MsgHdr.Rcode != dns.RcodeNameError {
		// A DNS error occurred (return code wasn't Success or NXDOMAIN).
		w.WriteHeader(500)
		return
	}
	if dnsResponse.MsgHdr.Rcode == dns.RcodeNameError {
		// TCP port 443 subdomain doesn't exist.
		// That means the domain doesn't use DANE.
		// Return an empty cert list
		return
	}
	if dnsResponse.MsgHdr.AuthenticatedData == false && dnsResponse.MsgHdr.Authoritative == false {
		// For security reasons, we only trust records that are
		// authenticated (e.g. server is Unbound and has verified
		// DNSSEC sigs) or authoritative (e.g. server is ncdns and is
		// the owner of the requested zone).  If neither is the case,
		// then return an empty cert list.
		return
	}
	for _, rr := range dnsResponse.Answer {
		tlsa, ok := rr.(*dns.TLSA)
		if !ok {
			// Record isn't a TLSA record
			continue
		}

		safeCert, err := safetlsa.GetCertFromTLSA(domain, tlsa, tldCert, tldPriv)
		if err != nil {
			// TODO: quiet this warning
			log.Printf("GetCertFromTLSA: %s", err)
			continue
		}

		safeCertPemBytes := pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE",
			Bytes: safeCert,
		})

		safeCertPem := string(safeCertPemBytes)

		io.WriteString(w, cacheResults + "\n\n" + safeCertPem)

		go cacheDomainCert(domain, safeCertPem)
		go popCachedDomainCertLater(domain)
	}
}

func getNewNegativeCAHandler(w http.ResponseWriter, req *http.Request) {
	restrictCert, restrictPriv, err := safetlsa.GenerateTLDExclusionCA("bit", rootCert, rootPriv)
	if err != nil {
		log.Print(err)
	}

	restrictCertPem := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE",
		Bytes: restrictCert,
	})
	restrictCertPemString := string(restrictCertPem)

	restrictPrivBytes, err := x509.MarshalECPrivateKey(restrictPriv.(*ecdsa.PrivateKey))
	if err != nil {
		log.Printf("Unable to marshal ECDSA private key: %v", err)
	}

	restrictPrivPem := pem.EncodeToMemory(&pem.Block{
		Type: "EC PRIVATE KEY",
		Bytes: restrictPrivBytes,
	})
	restrictPrivPemString := string(restrictPrivPem)

	io.WriteString(w, restrictCertPemString)
	io.WriteString(w, "\n\n")
	io.WriteString(w, restrictPrivPemString)
}

func crossSignCAHandler(w http.ResponseWriter, req *http.Request) {
	toSignPEM := req.FormValue("to-sign")
	signerCertPEM := req.FormValue("signer-cert")
	signerKeyPEM := req.FormValue("signer-key")

	cacheKeyArray := sha256.Sum256([]byte(toSignPEM + "\n\n" + signerCertPEM + "\n\n" + signerKeyPEM + "\n\n"))
	cacheKey := hex.EncodeToString(cacheKeyArray[:])

	cacheResults, needRefresh := getCachedNegativeCerts(cacheKey)
	if !needRefresh {
		io.WriteString(w, cacheResults)
		return
	}

	// TODO: check for trailing data and for incorrect block type
	toSignBlock, _ := pem.Decode([]byte(toSignPEM))
	signerCertBlock, _ := pem.Decode([]byte(signerCertPEM))
	signerKeyBlock, _ := pem.Decode([]byte(signerKeyPEM))

	// TODO: support non-EC keys
	signerKey, err := x509.ParseECPrivateKey(signerKeyBlock.Bytes)
	if err != nil {
		log.Printf("Unable to parse ECDSA private key: %v", err)
		return
	}

	resultBytes, err := crosssign.CrossSign(toSignBlock.Bytes, signerCertBlock.Bytes, signerKey)
	if err != nil {
		log.Printf("Unable to cross-sign: %v", err)
		return
	}

	resultPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE",
		Bytes: resultBytes,
	})
	resultPEMString := string(resultPEM)

	resultParsed, err := x509.ParseCertificate(resultBytes)
	if err != nil {
		log.Printf("Unable to extract serial number from cross-signed CA: %s", err)
	}

	io.WriteString(w, resultPEMString)

	cacheNegativeCert(cacheKey, resultPEMString)
	cacheOriginalFromSerial(resultParsed.SerialNumber.String(), toSignPEM)
}

func originalFromSerialHandler(w http.ResponseWriter, req *http.Request) {
	serial := req.FormValue("serial")

	cacheResults, needRefresh := getCachedOriginalFromSerial(serial)
	if !needRefresh {
		io.WriteString(w, cacheResults)
	}
}

func main() {
	var err error

	rootCert, rootPriv, err = safetlsa.GenerateRootCA("Namecoin")
	if err != nil {
		log.Fatal(err)
	}

	rootCertPem = pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE",
		Bytes: rootCert,
	})
	rootCertPemString = string(rootCertPem)

	tldCert, tldPriv, err = safetlsa.GenerateTLDCA("bit", rootCert, rootPriv)
	if err != nil {
		log.Fatal(err)
	}

	tldCertPem = pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE",
		Bytes: tldCert,
	})
	tldCertPemString = string(tldCertPem)

	// TODO: find a way to delete the root private key again, without impacting the exclusion CA generator.
	//rootPriv = nil

	domainCertCache = map[string][]cachedCert{}
	negativeCertCache = map[string][]cachedCert{}
	originalCertCache = map[string][]cachedCert{}

	http.HandleFunc("/lookup", lookupHandler)
	http.HandleFunc("/get-new-negative-ca", getNewNegativeCAHandler)
	http.HandleFunc("/cross-sign-ca", crossSignCAHandler)
	http.HandleFunc("/original-from-serial", originalFromSerialHandler)
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}
