package main

import (
	"io"
	"log"
	"net/http"
)

const (
	nfCert = `-----BEGIN CERTIFICATE-----
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
)

func lookupHandler(w http.ResponseWriter, req *http.Request) {
	domain := req.FormValue("domain")

	if domain == "nf.bit" {
		io.WriteString(w, nfCert)
	}
}

func main() {
	http.HandleFunc("/lookup", lookupHandler)
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}
