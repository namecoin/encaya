package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/hlandau/xlog"

	"github.com/namecoin/encaya/handlers"
	"github.com/namecoin/ncrpcclient"
	"github.com/namecoin/safetlsa"
)

var log, logPublic = xlog.New("encaya.server")

var Log = logPublic

type Server struct {
	cfg Config

	rootCert          []byte
	rootPriv          interface{}
	rootCertPem       []byte
	rootCertPemString string
	rootPrivPem       []byte
	tldCert           []byte
	tldPriv           interface{}
	tldCertPem        []byte
	tldCertPemString  string

	tcpListener net.Listener
	tlsListener net.Listener

	namecoin *ncrpcclient.Client
}

//nolint:lll
type Config struct {
	DNSAddress string `default:"" usage:"Use this DNS server for DNS lookups.  (If left empty, the system resolver will be used.)"`
	DNSPort    int    `default:"53" usage:"Use this port for DNS lookups."`
	ListenIP   string `default:"127.127.127.127" usage:"Listen on this IP address."`

	RootCert    string `default:"root_cert.pem" usage:"Sign with this root CA certificate."`
	RootKey     string `default:"root_key.pem" usage:"Sign with this root CA private key."`
	ListenChain string `default:"listen_chain.pem" usage:"Listen with this TLS certificate chain."`
	ListenKey   string `default:"listen_key.pem" usage:"Listen with this TLS private key."`

	NamecoinRPCUsername   string `default:"" usage:"Namecoin RPC username"`
	NamecoinRPCPassword   string `default:"" usage:"Namecoin RPC password"`
	NamecoinRPCAddress    string `default:"127.0.0.1:8336" usage:"Namecoin RPC server address"`
	NamecoinRPCCookiePath string `default:"" usage:"Namecoin RPC cookie path (used if password is unspecified)"`
	NamecoinRPCTimeout    int    `default:"1500" usage:"Timeout (in milliseconds) for Namecoin RPC requests"`

	ConfigDir string // path to interpret filenames relative to
}

func (cfg *Config) cpath(s string) string {
	return filepath.Join(cfg.ConfigDir, s)
}

func (cfg *Config) processPaths() {
	cfg.RootCert = cfg.cpath(cfg.RootCert)
	cfg.RootKey = cfg.cpath(cfg.RootKey)
	cfg.ListenChain = cfg.cpath(cfg.ListenChain)
	cfg.ListenKey = cfg.cpath(cfg.ListenKey)
}

func New(cfg *Config) (*Server, error) {
	srv := &Server{
		cfg: *cfg,
	}

	srv.cfg.processPaths()

	srv.initCerts()

	tcpAddr, err := net.ResolveTCPAddr("tcp", srv.cfg.ListenIP+":80")
	if err != nil {
		return nil, err
	}

	srv.tcpListener, err = net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}

	tlsAddr, err := net.ResolveTCPAddr("tcp", srv.cfg.ListenIP+":443")
	if err != nil {
		return nil, err
	}

	srv.tlsListener, err = net.ListenTCP("tcp", tlsAddr)
	if err != nil {
		return nil, err
	}

	// Connect to local namecoin core RPC server using HTTP POST mode.
	namecoinCfg := &rpcclient.ConnConfig{
		Host:         cfg.NamecoinRPCAddress,
		User:         cfg.NamecoinRPCUsername,
		Pass:         cfg.NamecoinRPCPassword,
		CookiePath:   cfg.NamecoinRPCCookiePath,
		HTTPPostMode: true, // Namecoin core only supports HTTP POST mode
		DisableTLS:   true, // Namecoin core does not provide TLS by default
	}

	srv.namecoin, err = ncrpcclient.New(namecoinCfg, nil)
	if err != nil {
		return nil, err
	}

	h, err := handlers.New(srv.cfg.DNSAddress, srv.cfg.DNSPort, srv.cfg.ConfigDir, srv.rootCert, srv.rootPriv, srv.namecoin)
	if err != nil {
		log.Fatale(err, "Couldn't generate TLD CA")
	}

	http.HandleFunc("/", h.IndexHandler)
	http.HandleFunc("/lookup", h.LookupHandler)
	http.HandleFunc("/aia", h.AIAHandler)
	http.HandleFunc("/get-new-negative-ca", h.GetNewNegativeCAHandler)
	http.HandleFunc("/cross-sign-ca", h.CrossSignCAHandler)
	http.HandleFunc("/original-from-serial", h.OriginalFromSerialHandler)

	return srv, nil
}

func (srv *Server) initCerts() {
	var err error

	srv.rootCertPem, err = os.ReadFile(srv.cfg.RootCert)
	if err != nil {
		log.Fatalef(err, "Unable to read %s", srv.cfg.RootCert)
	}

	srv.rootCertPemString = string(srv.rootCertPem)

	rootCertBlock, _ := pem.Decode(srv.rootCertPem)
	//nolint:staticcheck // SA5011 Unreachable if nil due to log.Fatal
	if rootCertBlock == nil {
		log.Fatalef(err, "Unable to decode %s", srv.cfg.RootCert)
	}

	//nolint:staticcheck // SA5011 Unreachable if nil due to log.Fatal
	srv.rootCert = rootCertBlock.Bytes

	srv.rootPrivPem, err = os.ReadFile(srv.cfg.RootKey)
	if err != nil {
		log.Fatalef(err, "Unable to read %s", srv.cfg.RootKey)
	}

	rootPrivBlock, _ := pem.Decode(srv.rootPrivPem)
	//nolint:staticcheck // SA5011 Unreachable if nil due to log.Fatal
	if rootPrivBlock == nil {
		log.Fatalef(err, "Unable to decode %s", srv.cfg.RootKey)
	}

	//nolint:staticcheck // SA5011 Unreachable if nil due to log.Fatal
	rootPrivBytes := rootPrivBlock.Bytes

	srv.rootPriv, err = x509.ParsePKCS8PrivateKey(rootPrivBytes)
	if err != nil {
		log.Fatalef(err, "Unable to parse %s", srv.cfg.RootKey)
	}
}

func (s *Server) Start() error {
	go s.doRunListenerTCP()
	go s.doRunListenerTLS()

	log.Info("Listeners started")

	return nil
}

func (s *Server) Stop() error {
	// Currently this doesn't actually stop the listeners, see
	// https://github.com/namecoin/encaya/issues/14
	return nil
}

func (s *Server) doRunListenerTCP() {
	tcpSrv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	err := tcpSrv.Serve(s.tcpListener)
	log.Fatale(err)
}

func (s *Server) doRunListenerTLS() {
	tlsSrv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	err := tlsSrv.ServeTLS(s.tlsListener, s.cfg.ListenChain, s.cfg.ListenKey)
	log.Fatale(err)
}

func GenerateCerts(cfg *Config) {
	var (
		err                 error
		listenCertPem       []byte
		listenCertPemString string
	)

	srv := &Server{
		cfg: *cfg,
	}

	srv.cfg.processPaths()

	srv.rootCert, srv.rootPriv, err = safetlsa.GenerateRootCA("Namecoin")
	if err != nil {
		log.Fatale(err, "Couldn't generate root CA")
	}

	rootPrivBytes, err := x509.MarshalPKCS8PrivateKey(srv.rootPriv)
	if err != nil {
		log.Fatale(err, "Unable to marshal private key")
	}

	srv.rootCertPem = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: srv.rootCert,
	})
	srv.rootCertPemString = string(srv.rootCertPem)

	srv.rootPrivPem = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: rootPrivBytes,
	})

	srv.tldCert, srv.tldPriv, err = safetlsa.GenerateTLDCA("bit", srv.rootCert, srv.rootPriv)
	if err != nil {
		log.Fatale(err, "Couldn't generate TLD CA")
	}

	srv.tldCertPem = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: srv.tldCert,
	})
	srv.tldCertPemString = string(srv.tldCertPem)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatale(err, "Unable to generate serial number")
	}

	listenPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatale(err, "Unable to generate listening key")
	}

	listenPrivBytes, err := x509.MarshalPKCS8PrivateKey(listenPriv)
	if err != nil {
		log.Fatale(err, "Unable to marshal private key")
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

	tldCertParsed, err := x509.ParseCertificate(srv.tldCert)
	if err != nil {
		log.Fatale(err, "Unable to parse TLD cert")
	}

	listenCert, err := x509.CreateCertificate(rand.Reader, &listenTemplate,
		tldCertParsed, &listenPriv.PublicKey, srv.tldPriv)
	if err != nil {
		log.Fatale(err, "Unable to create listening cert")
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

	err = os.WriteFile(srv.cfg.RootCert, srv.rootCertPem, 0600)
	if err != nil {
		log.Fatalef(err, "Unable to write %s", srv.cfg.RootCert)
	}

	err = os.WriteFile(srv.cfg.RootKey, srv.rootPrivPem, 0600)
	if err != nil {
		log.Fatalef(err, "Unable to write %s", srv.cfg.RootKey)
	}

	listenChainPemString := listenCertPemString + "\n\n" + srv.tldCertPemString + "\n\n" + srv.rootCertPemString
	listenChainPem := []byte(listenChainPemString)

	err = os.WriteFile(srv.cfg.ListenChain, listenChainPem, 0600)
	if err != nil {
		log.Fatalef(err, "Unable to write %s", srv.cfg.ListenChain)
	}

	err = os.WriteFile(srv.cfg.ListenKey, listenPrivPem, 0600)
	if err != nil {
		log.Fatalef(err, "Unable to write %s", srv.cfg.ListenKey)
	}
}
