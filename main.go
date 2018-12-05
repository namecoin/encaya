package main

import (
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

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
)

func getCachedCerts(commonName string) (string, bool) {
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

func cacheCert(commonName, certPem string) {
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

func popCachedCertLater(commonName string) {
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

func lookupHandler(w http.ResponseWriter, req *http.Request) {
	domain := req.FormValue("domain")

	var dummyCert string
	var dummyTLSA dns.TLSA

	if domain == "Namecoin Root CA" {
		io.WriteString(w, rootCertPemString)

		return
	}

	if domain == ".bit TLD CA" {
		io.WriteString(w, tldCertPemString)

		return
	}

	cacheResults, needRefresh := getCachedCerts(domain)
	if !needRefresh {
		io.WriteString(w, cacheResults)
		return
	}

	if domain == "test-ca.nf.bit Domain CA" {
		//dummyPubB64 := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEZrJOMvCZFJspUsEiwKXN1S2cIEYiaTFq7p9oQ+InUxJW6LDiqcy8TGDy0zATAZ7zSY1+KcWtmTb65hQ3RcQHw=="
		// Converted to hex manually via https://cryptii.com/pipes/base64-to-hex

		dummyTLSA = dns.TLSA{
			Hdr: dns.RR_Header{Name: "", Rrtype: dns.TypeTLSA, Class: dns.ClassINET,
				Ttl: 600},
			Usage:        uint8(2),
			Selector:     uint8(1),
			MatchingType: uint8(0),
			Certificate:  strings.ToUpper("3059301306072a8648ce3d020106082a8648ce3d03010703420004119ac938cbc264526ca54b048b02973754b670811889a4c5abba7da10f889d4c495ba2c38aa732f13183cb4cc04c067bcd2635f8a716b664dbeb9850dd17101f"),
		}
	} else if domain == "nf.bit" {
		dummyCert = `-----BEGIN CERTIFICATE-----
MIIBsjCCAVigAwIBAgIUAK9zGEHB5luScHPKSmWPvVkFccQwCgYIKoZIzj0EAwIw
NDEPMA0GA1UEAxMGbmYuYml0MSEwHwYDVQQFExhOYW1lY29pbiBUTFMgQ2VydGlm
aWNhdGUwHhcNMTcwODA4MDAwMDAwWhcNMjIwODA4MDAwMDAwWjA0MQ8wDQYDVQQD
EwZuZi5iaXQxITAfBgNVBAUTGE5hbWVjb2luIFRMUyBDZXJ0aWZpY2F0ZTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABOS/PY4iSlu21+T+DMbrzuCje5NVjicoymUq
8nDGTClq3zjxjVQQQM9zNsAd2z89IpnYytKaUss9BlxFkiIJUF+jSDBGMA4GA1Ud
DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBEG
A1UdEQQKMAiCBm5mLmJpdDAKBggqhkjOPQQDAgNIADBFAiEAvMIgAFNv0XpiB5cU
WeMJKeEImKQOsr0xbpNlMARR3eICIEYyUKju6L3FbFWLxBR2NGfko0ykQj2tkAMq
0IlMmYSL
-----END CERTIFICATE-----
`
		dummyBlock, _ := pem.Decode([]byte(dummyCert))

		dummyHex := hex.EncodeToString(dummyBlock.Bytes)

		dummyTLSA = dns.TLSA{
			Hdr: dns.RR_Header{Name: "", Rrtype: dns.TypeTLSA, Class: dns.ClassINET,
				Ttl: 600},
			Usage:        uint8(3),
			Selector:     uint8(0),
			MatchingType: uint8(0),
			Certificate:  strings.ToUpper(dummyHex),
		}
	} else {
		return
	}

	safeCert, err := safetlsa.GetCertFromTLSA(domain, &dummyTLSA, tldCert, tldPriv)
	if err != nil {
		// TODO: quiet this warning
		log.Printf("GetCertFromTLSA: %s", err)
		return
	}

	safeCertPemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE",
		Bytes: safeCert,
	})

	safeCertPem := string(safeCertPemBytes)

	io.WriteString(w, cacheResults + "\n\n" + safeCertPem)

	go cacheCert(domain, safeCertPem)
	go popCachedCertLater(domain)
}

func main() {
	rootCert, rootPriv, err := safetlsa.GenerateRootCA("Namecoin")
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

	rootPriv = nil

	domainCertCache = map[string][]cachedCert{}

	http.HandleFunc("/lookup", lookupHandler)
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}
