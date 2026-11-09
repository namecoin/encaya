module github.com/namecoin/encaya

go 1.26.5

replace github.com/coreos/go-systemd => ./go-systemd

replace gopkg.in/alecthomas/kingpin.v2 => github.com/alecthomas/kingpin/v2 v2.4.0

require (
	github.com/btcsuite/btcd v0.25.0
	github.com/ferhatelmas/pi v0.1.0
	github.com/hlandau/dexlogconfig v0.0.0-20220319061854-86a3fc314fe7
	github.com/hlandau/xlog v1.0.0
	github.com/miekg/dns v1.1.72
	github.com/namecoin/crosssign v0.0.4
	github.com/namecoin/ncbtcjson v0.1.0
	github.com/namecoin/ncrpcclient v0.1.0
	github.com/namecoin/qlib v0.0.6
	github.com/namecoin/safetlsa v0.0.6
	gopkg.in/hlandau/easyconfig.v1 v1.0.18
	gopkg.in/hlandau/service.v2 v2.0.17
)

require (
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.5 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.5 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792 // indirect
	github.com/coreos/go-systemd v0.0.0-00010101000000-000000000000 // indirect
	github.com/coreos/go-systemd/v22 v22.7.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/erikdubbelboer/gspt v0.0.0-20210805194459-ce36a5128377 // indirect
	github.com/hlandau/buildinfo v0.0.0-20161112115716-337a29b54997 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/namecoin/ncdns v0.3.2 // indirect
	github.com/namecoin/splicesign v0.0.1 // indirect
	github.com/ogier/pflag v0.0.1 // indirect
	github.com/shiena/ansicolor v0.0.0-20230509054315-a9deabde6e02 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.0.0-00010101000000-000000000000 // indirect
	gopkg.in/hlandau/configurable.v1 v1.0.1 // indirect
	gopkg.in/hlandau/svcutils.v1 v1.0.11 // indirect
)
