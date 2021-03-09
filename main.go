package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/hlandau/easyconfig.v1"
	"gopkg.in/hlandau/easyconfig.v1/cflag"

	"github.com/namecoin/crosssign"
	"github.com/namecoin/qlib"
	"github.com/namecoin/safetlsa"
)

type cachedCert struct {
	expiration time.Time
	certPem    string
}

var (
	rootCert          []byte
	rootPriv          interface{}
	rootCertPem       []byte
	rootCertPemString string
	rootPrivPem       []byte
	tldCert           []byte
	tldPriv           interface{}
	tldCertPem        []byte
	tldCertPemString  string
	// These caches don't yet support stream isolation; see
	// https://github.com/namecoin/encaya/issues/8
	domainCertCache        map[string][]cachedCert
	domainCertCacheMutex   sync.RWMutex
	negativeCertCache      map[string][]cachedCert
	negativeCertCacheMutex sync.RWMutex
	originalCertCache      map[string][]cachedCert
	originalCertCacheMutex sync.RWMutex
)

var (
	flagGroup      = cflag.NewGroup(nil, "encaya")
	dnsAddressFlag = cflag.String(flagGroup, "nameserver", "", "Use this "+
		"DNS server for DNS lookups.  (If left empty, the system "+
		"resolver will be used.)")
	dnsPortFlag = cflag.Int(flagGroup, "port", 53, "Use this port for "+
		"DNS lookups.")
	listenIP = cflag.String(flagGroup, "listen-ip", "127.127.127.127",
		"Listen on this IP address.")
	listenHTTPS = cflag.Bool(flagGroup, "listen-https", false,
		"Listen on HTTPS (RFC 5280 Sec. 8 says you SHOULD NOT do this)")
	generateCerts = cflag.Bool(flagGroup, "generate-certs", false,
		"Generate certificates and exit")
)

func getCachedDomainCerts(commonName string) (string, bool) {
	needRefresh := true
	results := ""

	domainCertCacheMutex.RLock()
	for _, cert := range domainCertCache[commonName] {
		if time.Until(cert.expiration) > 1*time.Minute {
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
		certPem:    certPem,
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
		certPem:    certPem,
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
		certPem:    certPem,
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
	var err error

	domain := req.FormValue("domain")

	if domain == "Namecoin Root CA" {
		_, err = io.WriteString(w, rootCertPemString)
		if err != nil {
			log.Printf("write error: %s", err)
		}

		return
	}

	if domain == ".bit TLD CA" {
		_, err = io.WriteString(w, tldCertPemString)
		if err != nil {
			log.Printf("write error: %s", err)
		}

		return
	}

	cacheResults, needRefresh := getCachedDomainCerts(domain)
	if !needRefresh {
		_, err = io.WriteString(w, cacheResults)
		if err != nil {
			log.Printf("write error: %s", err)
		}

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
	qparams.Port = dnsPortFlag.Value()
	qparams.Ad = true
	qparams.Fallback = true
	qparams.Tcp = true // Workaround for https://github.com/miekg/exdns/issues/19

	args := []string{}
	// Set the custom DNS server if requested
	if dnsAddressFlag.Value() != "" {
		args = append(args, "@"+dnsAddressFlag.Value())
	}
	// Set qtype to TLSA
	args = append(args, "TLSA")
	// Set qname to all protocols and all ports of requested hostname
	args = append(args, "*."+domain)

	result, err := qparams.Do(args)
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
		// Wildcard subdomain doesn't exist.
		// That means the domain doesn't use Namecoin-form DANE.
		// Return an empty cert list
		return
	}

	if !dnsResponse.MsgHdr.AuthenticatedData && !dnsResponse.MsgHdr.Authoritative {
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
			continue
		}

		safeCertPemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: safeCert,
		})

		safeCertPem := string(safeCertPemBytes)

		_, err = io.WriteString(w, cacheResults+"\n\n"+safeCertPem)
		if err != nil {
			log.Printf("write error: %s", err)
		}

		go cacheDomainCert(domain, safeCertPem)
		go popCachedDomainCertLater(domain)
	}
}

func aiaHandler(w http.ResponseWriter, req *http.Request) {
	var err error

	w.Header().Set("Content-Type", "application/pkix-cert")

	domain := req.FormValue("domain")

	if domain == "Namecoin Root CA" {
		_, err = io.WriteString(w, string(rootCert))
		if err != nil {
			log.Printf("write error: %s", err)
		}

		return
	}

	if domain == ".bit TLD CA" {
		_, err = io.WriteString(w, string(tldCert))
		if err != nil {
			log.Printf("write error: %s", err)
		}

		return
	}

	domain = strings.TrimSuffix(domain, " Domain AIA Parent CA")

	if strings.Contains(domain, " ") {
		// CommonNames that contain a space are usually CA's.  We
		// already stripped the suffixes of Namecoin-formatted CA's, so
		// if a space remains, just return.
		w.WriteHeader(404)
		return
	}

	qparams := qlib.DefaultParams()
	qparams.Port = dnsPortFlag.Value()
	qparams.Ad = true
	qparams.Fallback = true
	qparams.Tcp = true // Workaround for https://github.com/miekg/exdns/issues/19

	args := []string{}
	// Set the custom DNS server if requested
	if dnsAddressFlag.Value() != "" {
		args = append(args, "@"+dnsAddressFlag.Value())
	}
	// Set qtype to TLSA
	args = append(args, "TLSA")
	// Set qname to all protocols and all ports of requested hostname
	args = append(args, "*."+domain)

	result, err := qparams.Do(args)
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
		// Wildcard subdomain doesn't exist.
		// That means the domain doesn't use Namecoin-form DANE.
		// Return an empty cert list
		w.WriteHeader(404)
		return
	}

	if !dnsResponse.MsgHdr.AuthenticatedData && !dnsResponse.MsgHdr.Authoritative {
		// For security reasons, we only trust records that are
		// authenticated (e.g. server is Unbound and has verified
		// DNSSEC sigs) or authoritative (e.g. server is ncdns and is
		// the owner of the requested zone).  If neither is the case,
		// then return an empty cert list.
		w.WriteHeader(404)
		return
	}

	pubSHA256Hex := req.FormValue("pubsha256")

	pubSHA256, err := hex.DecodeString(pubSHA256Hex)
	if err != nil {
		// Requested public key hash is malformed.
		w.WriteHeader(404)
		return
	}

	for _, rr := range dnsResponse.Answer {
		tlsa, ok := rr.(*dns.TLSA)
		if !ok {
			// Record isn't a TLSA record
			continue
		}

		// CA not in user's trust store; public key; not hashed
		if tlsa.Usage == 2 && tlsa.Selector == 1 && tlsa.MatchingType == 0 {
			tlsaPubBytes, err := hex.DecodeString(tlsa.Certificate)
			if err != nil {
				// TLSA record is malformed
				continue
			}

			tlsaPubSHA256 := sha256.Sum256(tlsaPubBytes)
			if !bytes.Equal(pubSHA256, tlsaPubSHA256[:]) {
				// TLSA record doesn't match requested public key hash
				continue
			}
		} else {
			// TLSA record isn't in the Namecoin CA form
			continue
		}

		safeCert, err := safetlsa.GetCertFromTLSA(domain, tlsa, tldCert, tldPriv)
		if err != nil {
			continue
		}

		_, err = io.WriteString(w, string(safeCert))
		if err != nil {
			log.Printf("write error: %s", err)
		}

		break
	}
}

func getNewNegativeCAHandler(w http.ResponseWriter, req *http.Request) {
	restrictCert, restrictPriv, err := safetlsa.GenerateTLDExclusionCA("bit", rootCert, rootPriv)
	if err != nil {
		log.Print(err)
	}

	restrictCertPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: restrictCert,
	})
	restrictCertPemString := string(restrictCertPem)

	restrictPrivBytes, err := x509.MarshalECPrivateKey(restrictPriv.(*ecdsa.PrivateKey))
	if err != nil {
		log.Printf("Unable to marshal ECDSA private key: %v", err)
	}

	restrictPrivPem := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: restrictPrivBytes,
	})
	restrictPrivPemString := string(restrictPrivPem)

	_, err = io.WriteString(w, restrictCertPemString)
	if err != nil {
		log.Printf("write error: %s", err)
	}

	_, err = io.WriteString(w, "\n\n")
	if err != nil {
		log.Printf("write error: %s", err)
	}

	_, err = io.WriteString(w, restrictPrivPemString)
	if err != nil {
		log.Printf("write error: %s", err)
	}
}

func crossSignCAHandler(w http.ResponseWriter, req *http.Request) {
	var err error

	toSignPEM := req.FormValue("to-sign")
	signerCertPEM := req.FormValue("signer-cert")
	signerKeyPEM := req.FormValue("signer-key")

	cacheKeyArray := sha256.Sum256([]byte(toSignPEM + "\n\n" + signerCertPEM + "\n\n" + signerKeyPEM + "\n\n"))
	cacheKey := hex.EncodeToString(cacheKeyArray[:])

	cacheResults, needRefresh := getCachedNegativeCerts(cacheKey)
	if !needRefresh {
		_, err = io.WriteString(w, cacheResults)
		if err != nil {
			log.Printf("write error: %s", err)
		}

		return
	}

	toSignBlock, _ := pem.Decode([]byte(toSignPEM))
	signerCertBlock, _ := pem.Decode([]byte(signerCertPEM))
	signerKeyBlock, _ := pem.Decode([]byte(signerKeyPEM))

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
		Type:  "CERTIFICATE",
		Bytes: resultBytes,
	})
	resultPEMString := string(resultPEM)

	resultParsed, err := x509.ParseCertificate(resultBytes)
	if err != nil {
		log.Printf("Unable to extract serial number from cross-signed CA: %s", err)
	}

	_, err = io.WriteString(w, resultPEMString)
	if err != nil {
		log.Printf("write error: %s", err)
	}

	cacheNegativeCert(cacheKey, resultPEMString)
	cacheOriginalFromSerial(resultParsed.SerialNumber.String(), toSignPEM)
}

func originalFromSerialHandler(w http.ResponseWriter, req *http.Request) {
	serial := req.FormValue("serial")

	cacheResults, needRefresh := getCachedOriginalFromSerial(serial)
	if !needRefresh {
		_, err := io.WriteString(w, cacheResults)
		if err != nil {
			log.Printf("write error: %s", err)
		}
	}
}

func main() {
	var (
		listenCertPem       []byte
		listenCertPemString string
	)

	config := easyconfig.Configurator{
		ProgramName: "encaya",
	}

	err := config.Parse(nil)
	if err != nil {
		log.Fatalf("Couldn't parse configuration: %s", err)
	}

	if generateCerts.Value() {
		rootCert, rootPriv, err = safetlsa.GenerateRootCA("Namecoin")
		if err != nil {
			log.Fatalf("Couldn't generate root CA: %s", err)
		}

		rootPrivBytes, err := x509.MarshalPKCS8PrivateKey(rootPriv)
		if err != nil {
			log.Fatalf("Unable to marshal private key: %v", err)
		}

		rootCertPem = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rootCert,
		})
		rootCertPemString = string(rootCertPem)

		rootPrivPem = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: rootPrivBytes,
		})

		tldCert, tldPriv, err = safetlsa.GenerateTLDCA("bit", rootCert, rootPriv)
		if err != nil {
			log.Fatalf("Couldn't generate TLD CA: %s", err)
		}

		tldCertPem = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: tldCert,
		})
		tldCertPemString = string(tldCertPem)

		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			log.Fatalf("Unable to generate serial number: %s", err)
		}

		listenPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("Unable to generate listening key: %s", err)
		}

		listenPrivBytes, err := x509.MarshalPKCS8PrivateKey(listenPriv)
		if err != nil {
			log.Fatalf("Unable to marshal private key: %v", err)
		}

		listenTemplate := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName:   "aia.x--nmc.bit",
				SerialNumber: "Namecoin TLS Certificate",
			},
			NotBefore: time.Now().Add(-1 * time.Hour),
			NotAfter:  time.Now().Add(43800 * time.Hour),

			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,

			DNSNames: []string{"aia.x--nmc.bit"},
		}

		tldCertParsed, err := x509.ParseCertificate(tldCert)
		if err != nil {
			log.Fatalf("Unable to parse TLD cert: %s", err)
		}

		listenCert, err := x509.CreateCertificate(rand.Reader, &listenTemplate, tldCertParsed, &listenPriv.PublicKey, tldPriv)
		if err != nil {
			log.Fatalf("Unable to create listening cert: %s", err)
		}

		listenCertPem = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: listenCert,
		})
		listenCertPemString = string(listenCertPem)

		listenPrivPem := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: listenPrivBytes,
		})

		err = ioutil.WriteFile("root_cert.pem", rootCertPem, 0600)
		if err != nil {
			log.Fatalf("Unable to write root cert: %s", err)
		}

		err = ioutil.WriteFile("root_key.pem", rootPrivPem, 0600)
		if err != nil {
			log.Fatalf("Unable to write root key: %s", err)
		}

		listenChainPemString := listenCertPemString + "\n\n" + tldCertPemString + "\n\n" + rootCertPemString
		listenChainPem := []byte(listenChainPemString)

		err = ioutil.WriteFile("listen_chain.pem", listenChainPem, 0600)
		if err != nil {
			log.Fatalf("Unable to write listen cert chain: %s", err)
		}

		err = ioutil.WriteFile("listen_key.pem", listenPrivPem, 0600)
		if err != nil {
			log.Fatalf("Unable to write listen key: %s", err)
		}

		return
	}

	rootCertPem, err = ioutil.ReadFile("root_cert.pem")
	if err != nil {
		log.Fatalf("Unable to read root_cert.pem: %s", err)
	}

	rootCertPemString = string(rootCertPem)

	rootCertBlock, _ := pem.Decode(rootCertPem)
	if rootCertBlock == nil {
		log.Fatalf("Unable to decode root_cert.pem: %s", err)
	}

	rootCert = rootCertBlock.Bytes

	rootPrivPem, err = ioutil.ReadFile("root_key.pem")
	if err != nil {
		log.Fatalf("Unable to read root_key.pem: %s", err)
	}

	rootPrivBlock, _ := pem.Decode(rootPrivPem)
	if rootPrivBlock == nil {
		log.Fatalf("Unable to decode root_key.pem: %s", err)
	}

	rootPrivBytes := rootPrivBlock.Bytes

	rootPriv, err = x509.ParsePKCS8PrivateKey(rootPrivBytes)
	if err != nil {
		log.Fatalf("Unable to parse root_key.pem: %s", err)
	}

	tldCert, tldPriv, err = safetlsa.GenerateTLDCA("bit", rootCert, rootPriv)
	if err != nil {
		log.Fatalf("Couldn't generate TLD CA: %s", err)
	}

	tldCertPem = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: tldCert,
	})
	tldCertPemString = string(tldCertPem)

	domainCertCache = map[string][]cachedCert{}
	negativeCertCache = map[string][]cachedCert{}
	originalCertCache = map[string][]cachedCert{}

	http.HandleFunc("/lookup", lookupHandler)
	http.HandleFunc("/aia", aiaHandler)
	http.HandleFunc("/get-new-negative-ca", getNewNegativeCAHandler)
	http.HandleFunc("/cross-sign-ca", crossSignCAHandler)
	http.HandleFunc("/original-from-serial", originalFromSerialHandler)

	if listenHTTPS.Value() {
		log.Fatal(http.ListenAndServeTLS(listenIP.Value()+":443",
			"listen_chain.pem", "listen_key.pem", nil))
	} else {
		log.Fatal(http.ListenAndServe(listenIP.Value()+":80", nil))
	}
}
