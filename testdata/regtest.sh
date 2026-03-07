#!/usr/bin/env bash
export HOME=~
set -eu

# Adapted from Electrum-NMC.

bitcoin_cli="namecoin-cli -rpcuser=doggman -rpcpassword=donkey -rpcport=18554 -regtest"

function new_blocks()
{
    $bitcoin_cli generatetoaddress "$1" "$($bitcoin_cli getnewaddress)" > /dev/null
}

function assert_equal()
{
    err_msg="$3"

    if [[ "$1" != "$2" ]]; then
        echo "'$1' != '$2'"
        echo "$err_msg"
        return 1
    fi
}

function assert_raises_error()
{
    cmd=$1
    required_err=$2

    if observed_err=$($cmd 2>&1) ; then
        echo "Failed to raise error '$required_err'"
        return 1
    fi
    if [[ "$observed_err" != *"$required_err"* ]]; then
        echo "$observed_err"
        echo "Raised wrong error instead of '$required_err'"
        return 1
    fi
}

echo "Expire any existing names from previous functional test runs"
new_blocks 35

echo "Pre-register testls.bit"
$bitcoin_cli name_new 'd/testls'

echo "Wait for pre-registration to mature"
new_blocks 12

echo "Register testls.bit"
$bitcoin_cli name_firstupdate 'd/testls'

echo "Wait for registration to confirm"
new_blocks 1

echo "Update testls.bit"
$bitcoin_cli name_update 'd/testls' '{"ip":"107.152.38.155","map":{"*":{"tls":[[2,1,0,"MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADvxHcjwDYMNfUSTtSIn3VbBC1sOzh/1Fv5T0UzEuLWIE="]]},"sub1":{"map":{"sub2":{"map":{"sub3":{"ip":"107.152.38.155"}}}}},"_tor":{"txt":"dhflg7a7etr77hwt4eerwoovhg7b5bivt2jem4366dt4psgnl5diyiyd.onion"}}}'

echo "Wait for update to confirm"
new_blocks 1

echo "Query testls.bit via Core"
$bitcoin_cli name_show 'd/testls'

echo "Query testls.bit IPv4 Authoritative via dig"
dig_output=$(dig -p 5391 @127.0.0.1 A testls.bit)
echo "$dig_output"
echo "Checking response correctness"
echo "$dig_output" | grep "107.152.38.155"

echo "Query testls.bit TLS Authoritative via dig"
dig_output=$(dig -p 5391 @127.0.0.1 TLSA "*.testls.bit")
echo "$dig_output"
echo "Checking response correctness"
tlsa_hex="$(echo 'MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADvxHcjwDYMNfUSTtSIn3VbBC1sOzh/1Fv5T0UzEuLWIE=' | base64 --decode | xxd -u -ps -c 500)"
echo "$dig_output" | sed 's/ //g' | grep "$tlsa_hex"

echo "Query testls.bit IPv4 Recursive via dig"
dig_output=$(dig -p 53 @127.0.0.1 A testls.bit)
echo "$dig_output"
echo "Checking response correctness"
echo "$dig_output" | grep "107.152.38.155"

echo "Query testls.bit TLS Recursive via dig"
dig_output=$(dig -p 53 @127.0.0.1 TLSA "*.testls.bit")
echo "$dig_output"
echo "Checking response correctness"
tlsa_hex="$(echo 'MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADvxHcjwDYMNfUSTtSIn3VbBC1sOzh/1Fv5T0UzEuLWIE=' | base64 --decode | xxd -u -ps -c 500)"
echo "$dig_output" | sed 's/ //g' | grep "$tlsa_hex"

echo "Fetch testls.bit via curl"
curl --insecure https://testls.bit/ | grep -i "Cool or nah"

echo "Fetch Root CA via curl"
curl http://127.127.127.127/lookup?domain=Namecoin%20Root%20CA | grep -i "BEGIN CERTIFICATE"

echo "Fetch TLD CA via curl"
curl http://127.127.127.127/lookup?domain=.bit%20TLD%20CA | grep -i "BEGIN CERTIFICATE"

echo "Fetch testls.bit CA via curl"
curl http://127.127.127.127/lookup?domain=testls.bit%20Domain%20AIA%20Parent%20CA | grep -i "BEGIN CERTIFICATE"

echo "Generate ECDSA P-256 key pair for testlshashed.bit"
openssl ecparam -name prime256v1 -genkey -noout -out testdata/testlshashed_key.pem

echo "Extract SPKI in DER format"
openssl ec -in testdata/testlshashed_key.pem -pubout -outform DER -out testdata/testlshashed_spki.der 2>/dev/null

echo "Compute SHA-256 of SPKI"
spki_sha256_base64=$(openssl dgst -sha256 -binary testdata/testlshashed_spki.der | base64)

echo "Pre-register testlshashed.bit"
$bitcoin_cli name_new 'd/testlshashed'

echo "Wait for pre-registration to mature"
new_blocks 12

echo "Register testlshashed.bit"
$bitcoin_cli name_firstupdate 'd/testlshashed'

echo "Wait for registration to confirm"
new_blocks 1

echo "Update testlshashed.bit"
$bitcoin_cli name_update 'd/testlshashed' '{"ip":"127.0.0.1","map":{"*":{"tls":[[2,1,1,"'"${spki_sha256_base64}"'"]]}}}'

echo "Wait for update to confirm"
new_blocks 1

echo "Query testlshashed.bit via Core"
$bitcoin_cli name_show 'd/testlshashed'

echo "Query testlshashed.bit IPv4 Authoritative via dig"
dig_output=$(dig -p 5391 @127.0.0.1 A testlshashed.bit)
echo "$dig_output"
echo "Checking response correctness"
echo "$dig_output" | grep "127.0.0.1"

echo "Query testlshashed.bit TLS Authoritative via dig"
dig_output=$(dig -p 5391 @127.0.0.1 TLSA "*.testlshashed.bit")
echo "$dig_output"
echo "Checking response correctness"
tlsa_hex="$(openssl dgst -sha256 -binary testdata/testlshashed_spki.der | xxd -u -ps -c 500)"
echo "$dig_output" | sed 's/ //g' | grep "$tlsa_hex"

echo "Compute SPKI query parameters for Encaya"
spki_b64url=$(basenc --base64url -w0 < testdata/testlshashed_spki.der | tr -d '=')
spki_sha256_hex=$(openssl dgst -sha256 -hex testdata/testlshashed_spki.der | awk '{print $NF}')

echo "Fetch testlshashed.bit Domain CA via curl"
curl "http://127.127.127.127/lookup?domain=testlshashed.bit%20Domain%20AIA%20Parent%20CA&pubb64=${spki_b64url}&pubsha256=${spki_sha256_hex}" | grep -i "BEGIN CERTIFICATE"

echo "Generate end-entity cert with AIA URL for testlshashed.bit"
cat > testdata/ee_ext.cnf <<EOF
[v3_ee]
subjectAltName = DNS:testlshashed.bit
authorityInfoAccess = caIssuers;URI:http://127.127.127.127/aia?domain=testlshashed.bit%20Domain%20AIA%20Parent%20CA&pubb64=${spki_b64url}&pubsha256=${spki_sha256_hex}
EOF
openssl req -new -key testdata/testlshashed_key.pem -out testdata/testlshashed.csr -subj "/CN=testlshashed.bit"
openssl x509 -req -in testdata/testlshashed.csr -signkey testdata/testlshashed_key.pem -out testdata/testlshashed_ee.pem -days 1 -extfile testdata/ee_ext.cnf -extensions v3_ee

echo "Start local HTTPS server for testlshashed.bit"
openssl s_server -accept 4443 -cert testdata/testlshashed_ee.pem -key testdata/testlshashed_key.pem -www &
sleep 2

echo "Import Encaya root CA into Chromium NSS DB"
mkdir -p "$HOME/.pki/nssdb"
certutil -d "sql:$HOME/.pki/nssdb" -N --empty-password
curl -s http://127.127.127.127/lookup?domain=Namecoin%20Root%20CA > testdata/root_ca.pem
certutil -d "sql:$HOME/.pki/nssdb" -A -t "CT,C,C" -n "Encaya Root CA" -i testdata/root_ca.pem

echo "Verify AIA chain via headless Chromium"
chromium_output=$(chromium --headless --no-sandbox --disable-gpu --dump-dom "https://testlshashed.bit:4443/" 2>/dev/null)
echo "$chromium_output"
echo "Checking response correctness"
echo "$chromium_output" | grep -i "s_server"
