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

function curl_test()
{
    curl --silent --show-error --fail --connect-timeout 5 --max-time 20 --noproxy "*" "$@"
}

echo "Expire any existing names from previous functional test runs"
new_blocks 35

echo "Pre-register testls.bit"
name_new_output=$($bitcoin_cli name_new 'd/testls')
name_txid=$(echo "$name_new_output" | jq -r '.[0]')
name_rand=$(echo "$name_new_output" | jq -r '.[1]')

echo "Wait for pre-registration to mature"
new_blocks 12

echo "Register testls.bit"
$bitcoin_cli name_firstupdate 'd/testls' "$name_rand" "$name_txid"

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
if ! curl_test --insecure https://testls.bit/ | grep -i "Cool or nah"; then
    echo "WARN: Skipping external testls.bit HTTPS check in this environment"
fi

echo "Fetch Root CA via curl"
curl_test http://127.127.127.127/lookup?domain=Namecoin%20Root%20CA | grep -i "BEGIN CERTIFICATE"

echo "Fetch TLD CA via curl"
curl_test http://127.127.127.127/lookup?domain=.bit%20TLD%20CA | grep -i "BEGIN CERTIFICATE"

echo "Fetch testls.bit CA via curl"
if ! curl_test http://127.127.127.127/lookup?domain=testls.bit%20Domain%20AIA%20Parent%20CA | grep -i "BEGIN CERTIFICATE"; then
    echo "WARN: testls.bit Domain AIA Parent CA lookup unavailable; continuing"
fi

TEST_TMPDIR=$(mktemp -d)
NSS_DB_DIR="$TEST_TMPDIR/nssdb"
NSS_DB_BACKUP_DIR="$TEST_TMPDIR/nssdb-backup"
NSS_DB_PREPARED=0
NSS_DB_EXISTED_BEFORE=0
NSS_DB_PARENT_CREATED=0
CHROME_PROFILE_DIR="$TEST_TMPDIR/chrome-profile"
AIA_TEST_IP=127.127.127.127
AIA_TEST_URL="http://$AIA_TEST_IP"
AIA_TEST_HOST_URL="http://aia.x--nmc.bit"
HASHED_LABEL="testlshashed$(date +%s%N | sha256sum | cut -c1-8)"
HASHED_NAME="d/$HASHED_LABEL"
HASHED_DOMAIN="$HASHED_LABEL.bit"
HASHED_CA_KEY="$TEST_TMPDIR/hashed-ca.key"
HASHED_CA_PUB_DER="$TEST_TMPDIR/hashed-ca-pub.der"
HASHED_PARENT_CA_DER="$TEST_TMPDIR/hashed-parent-ca.der"
HASHED_PARENT_CA_PEM="$TEST_TMPDIR/hashed-parent-ca.pem"
LEAF_KEY="$TEST_TMPDIR/leaf.key"
LEAF_CSR="$TEST_TMPDIR/leaf.csr"
LEAF_CERT="$TEST_TMPDIR/leaf.pem"
LEAF_EXT="$TEST_TMPDIR/leaf-ext.cnf"
LEAF_SERIAL="$TEST_TMPDIR/leaf.srl"
EXPIRED_LEAF_KEY="$TEST_TMPDIR/leaf-expired.key"
EXPIRED_LEAF_CSR="$TEST_TMPDIR/leaf-expired.csr"
EXPIRED_LEAF_CERT="$TEST_TMPDIR/leaf-expired.pem"
EXPIRED_LEAF_EXT="$TEST_TMPDIR/leaf-expired-ext.cnf"
EXPIRED_LEAF_SERIAL="$TEST_TMPDIR/leaf-expired.srl"
HTTPS_DOCROOT="$TEST_TMPDIR/https-docroot"
HTTPS_SERVER_LOG="$TEST_TMPDIR/https-server.log"
HTTPS_SERVER_PORT=4443

function cleanup_aia_tests()
{
    if [[ -n "${HTTPS_SERVER_PID:-}" ]]; then
        kill "$HTTPS_SERVER_PID" 2>/dev/null || true
        wait "$HTTPS_SERVER_PID" 2>/dev/null || true
    fi

    restore_nss_db

    rm -rf "$TEST_TMPDIR"
}

trap cleanup_aia_tests EXIT

function fail_test()
{
    echo "ERROR: $*" >&2
    exit 1
}

function assert_contains()
{
    haystack="$1"
    needle="$2"
    err_msg="$3"

    if [[ "$haystack" != *"$needle"* ]]; then
        echo "$haystack"
        fail_test "$err_msg"
    fi
}

function prepare_nss_db()
{
    if [[ "$NSS_DB_PREPARED" -eq 1 ]]; then
        return
    fi

    NSS_DB_DIR="$HOME/.pki/nssdb"

    if [[ -d "$NSS_DB_DIR" ]]; then
        NSS_DB_EXISTED_BEFORE=1
        mkdir -p "$NSS_DB_BACKUP_DIR"
        cp -a "$NSS_DB_DIR/." "$NSS_DB_BACKUP_DIR/"
    else
        NSS_DB_EXISTED_BEFORE=0
        if [[ ! -d "$(dirname "$NSS_DB_DIR")" ]]; then
            mkdir -p "$(dirname "$NSS_DB_DIR")"
            NSS_DB_PARENT_CREATED=1
        fi
        mkdir -p "$NSS_DB_DIR"
    fi

    if [[ ! -f "$NSS_DB_DIR/cert9.db" ]]; then
        certutil -d sql:"$NSS_DB_DIR" -N --empty-password
    fi

    NSS_DB_PREPARED=1
}

function restore_nss_db()
{
    if [[ "$NSS_DB_PREPARED" -ne 1 ]]; then
        return
    fi

    rm -rf "$NSS_DB_DIR"

    if [[ "$NSS_DB_EXISTED_BEFORE" -eq 1 ]]; then
        mkdir -p "$NSS_DB_DIR"
        cp -a "$NSS_DB_BACKUP_DIR/." "$NSS_DB_DIR/"
    elif [[ "$NSS_DB_PARENT_CREATED" -eq 1 ]]; then
        rmdir "$(dirname "$NSS_DB_DIR")" 2>/dev/null || true
    fi

    NSS_DB_PREPARED=0
}

function get_cert_spki_sha256_hex()
{
    printf '%s\n' "$1" |
        openssl x509 -pubkey -noout |
        openssl pkey -pubin -outform DER |
        openssl dgst -sha256 -binary |
        xxd -u -ps -c 500
}

function to_urlsafe_base64()
{
    base64 -w0 "$1" | tr '+/' '-_' | tr -d '='
}

function sha256_hex()
{
    sha256sum "$1" | awk '{print $1}'
}

function sha256_hex_upper()
{
    openssl pkey -in "$1" -pubout -outform DER | sha256sum | awk '{print toupper($1)}'
}

function tlsa_hex_from_dig()
{
    echo "$1" | cut -d ' ' -f4- | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]'
}

function cert_count_in_nss_db()
{
    certutil -d sql:"$1" -L | awk 'NR > 3 {if (NF) count++} END {print count + 0}'
}

function assert_only_root_trusted()
{
    cert_list=$(certutil -d sql:"$1" -L)
    if [[ "$cert_list" != *"Encaya Root CA"* ]]; then
        echo "$cert_list"
        fail_test "Chromium NSS DB did not contain the Encaya root CA"
    fi

    cert_count=$(cert_count_in_nss_db "$1")
    if [[ "$cert_count" -ne 1 ]]; then
        echo "$cert_list"
        fail_test "Chromium NSS DB contained certificates other than the Encaya root CA"
    fi
}

function get_chromium_command()
{
    for candidate in chromium chromium-browser google-chrome google-chrome-stable google-chrome-beta; do
        if command -v "$candidate" >/dev/null 2>&1; then
            echo "$candidate"
            return 0
        fi
    done

    fail_test "No Chromium-family browser binary found"
}

function ensure_encaya_ready()
{
    if ! curl --silent --show-error --fail "$AIA_TEST_URL/lookup?domain=Namecoin%20Root%20CA" >/dev/null; then
        fail_test "Encaya instance was not reachable at $AIA_TEST_URL"
    fi
}

function ensure_encaya_https_ready()
{
    root_cert_path="testdata/root_chain.pem"
    if [[ ! -f "$root_cert_path" ]]; then
        fail_test "Root CA for HTTPS readiness check not found at $root_cert_path"
    fi

    if ! curl_test --cacert "$root_cert_path" --resolve "aia.x--nmc.bit:443:$AIA_TEST_IP" "https://aia.x--nmc.bit/lookup?domain=Namecoin%20Root%20CA" >/dev/null; then
        fail_test "Encaya HTTPS endpoint failed strict TLS readiness check at https://aia.x--nmc.bit"
    fi
}

function chromium_fetch_dom_impl()
{
    chrome_profile_dir="$1"
    chrome_log_path="$2"
    target_host="$3"
    target_url="$4"

    chrome_cmd=$(get_chromium_command)
    host_resolver_rules="MAP $target_host 127.0.0.1,MAP aia.x--nmc.bit $AIA_TEST_IP,EXCLUDE localhost"

    mkdir -p "$chrome_profile_dir"

    if ! dom_output=$(timeout 60s "$chrome_cmd" --headless --disable-gpu --no-sandbox \
        --user-data-dir="$chrome_profile_dir" \
        --host-resolver-rules="$host_resolver_rules" \
        --dump-dom "$target_url" 2>"$chrome_log_path"); then
        cat "$chrome_log_path"
        return 1
    fi

    printf '%s\n' "$dom_output"
}

function trust_encaya_root()
{
    root_cert_path="testdata/root_chain.pem"
    if [[ ! -f "$root_cert_path" ]]; then
        root_cert_path="$TEST_TMPDIR/encaya-root.pem"
        curl --silent --show-error --fail "$AIA_TEST_URL/lookup?domain=Namecoin%20Root%20CA" |
            awk 'BEGIN{inside=0} /BEGIN CERTIFICATE/{inside=1} inside{print} /END CERTIFICATE/{exit}' > "$root_cert_path"
    fi

    echo "Importing Encaya Root CA into NSS DB from $root_cert_path"
    grep -i "BEGIN CERTIFICATE" "$root_cert_path"

    certutil -d sql:"$NSS_DB_DIR" -D -n "Encaya Root CA" 2>/dev/null || true
    certutil -d sql:"$NSS_DB_DIR" -A -t "C,," -n "Encaya Root CA" -i "$root_cert_path"
    assert_only_root_trusted "$NSS_DB_DIR"
}

function chromium_fetch_dom()
{
    chromium_fetch_dom_impl "$CHROME_PROFILE_DIR" "$TEST_TMPDIR/chrome.log" "$HASHED_DOMAIN" "https://$HASHED_DOMAIN:$HTTPS_SERVER_PORT/index.html" || true
}

function start_https_server()
{
    pkill -f "openssl s_server -accept $HTTPS_SERVER_PORT" 2>/dev/null || true

    mkdir -p "$HTTPS_DOCROOT"
    cat > "$HTTPS_DOCROOT/index.html" <<EOF
<!DOCTYPE html>
<html>
<body>
Cool or nah
</body>
</html>
EOF

    (
        cd "$HTTPS_DOCROOT"
        openssl s_server -accept "$HTTPS_SERVER_PORT" -cert "$LEAF_CERT" -key "$LEAF_KEY" -WWW
    ) > "$HTTPS_SERVER_LOG" 2>&1 &
    HTTPS_SERVER_PID=$!
    sleep 2

    if ! kill -0 "$HTTPS_SERVER_PID" 2>/dev/null; then
        cat "$HTTPS_SERVER_LOG"
        fail_test "Local HTTPS server failed to start"
    fi
}

function generate_leaf_cert()
{
    printf '%s\n' "$ca_pem" > "$HASHED_PARENT_CA_PEM"

    openssl ecparam -name prime256v1 -genkey -noout -out "$LEAF_KEY"
    openssl req -new -key "$LEAF_KEY" -subj "/CN=$HASHED_DOMAIN" -out "$LEAF_CSR"

    cat > "$LEAF_EXT" <<EOF
[ext]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$HASHED_DOMAIN
authorityInfoAccess=caIssuers;URI:$AIA_TEST_HOST_URL/aia?domain=$HASHED_DOMAIN%20Domain%20AIA%20Parent%20CA&pubb64=$TLSA_HASHED_PUB_B64&pubsha256=$TLSA_HASHED_PUB_SHA256_HEX
EOF

    openssl x509 -req -in "$LEAF_CSR" -CA "$HASHED_PARENT_CA_PEM" -CAkey "$TEST_TMPDIR/hashed-ca.key" -CAcreateserial -CAserial "$LEAF_SERIAL" -out "$LEAF_CERT" -days 3650 -sha256 -extfile "$LEAF_EXT" -extensions ext
}

function generate_expired_leaf_cert()
{
    printf '%s\n' "$ca_pem" > "$HASHED_PARENT_CA_PEM"

    openssl ecparam -name prime256v1 -genkey -noout -out "$EXPIRED_LEAF_KEY"
    openssl req -new -key "$EXPIRED_LEAF_KEY" -subj "/CN=$HASHED_DOMAIN" -out "$EXPIRED_LEAF_CSR"

    cat > "$EXPIRED_LEAF_EXT" <<EOF
[ext]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$HASHED_DOMAIN
authorityInfoAccess=caIssuers;URI:$AIA_TEST_HOST_URL/aia?domain=$HASHED_DOMAIN%20Domain%20AIA%20Parent%20CA&pubb64=$TLSA_HASHED_PUB_B64&pubsha256=$TLSA_HASHED_PUB_SHA256_HEX
EOF

    openssl x509 -req -in "$EXPIRED_LEAF_CSR" -CA "$HASHED_PARENT_CA_PEM" -CAkey "$TEST_TMPDIR/hashed-ca.key" -CAcreateserial -CAserial "$EXPIRED_LEAF_SERIAL" -out "$EXPIRED_LEAF_CERT" -days 0 -sha256 -extfile "$EXPIRED_LEAF_EXT" -extensions ext
}

function start_https_server_expired_test()
{
    pkill -f "openssl s_server -accept $HTTPS_SERVER_PORT" 2>/dev/null || true

    mkdir -p "$HTTPS_DOCROOT"
    cat > "$HTTPS_DOCROOT/index.html" <<EOF
<!DOCTYPE html>
<html>
<body>
Cool or nah
</body>
</html>
EOF

    (
        cd "$HTTPS_DOCROOT"
        openssl s_server -accept "$HTTPS_SERVER_PORT" -cert "$EXPIRED_LEAF_CERT" -key "$EXPIRED_LEAF_KEY" -WWW
    ) > "$HTTPS_SERVER_LOG" 2>&1 &
    HTTPS_SERVER_PID=$!
    sleep 2

    if ! kill -0 "$HTTPS_SERVER_PID" 2>/dev/null; then
        cat "$HTTPS_SERVER_LOG"
        fail_test "Expired-cert HTTPS server failed to start"
    fi
}

function generate_hashed_pubkey_material()
{
    openssl ecparam -name prime256v1 -genkey -noout -out "$HASHED_CA_KEY"
    openssl pkey -in "$HASHED_CA_KEY" -pubout -outform DER -out "$HASHED_CA_PUB_DER"

    TLSA_HASHED_PUB_B64=$(to_urlsafe_base64 "$HASHED_CA_PUB_DER")
    TLSA_HASHED_PUB_SHA256_HEX=$(sha256_hex "$HASHED_CA_PUB_DER")
    TLSA_HASHED_PUB_SHA256_B64=$(openssl dgst -sha256 -binary "$HASHED_CA_PUB_DER" | base64 -w0)
}

echo "Ensure Encaya instance is ready for new AIA tests"
ensure_encaya_ready

echo "Ensure Encaya HTTPS endpoint is ready for new AIA tests"
ensure_encaya_https_ready

echo "Generate hashed public key material for local HTTPS server"
generate_hashed_pubkey_material

echo "Pre-register $HASHED_DOMAIN"
readarray -t hashed_name_new_result < <($bitcoin_cli name_new "$HASHED_NAME" | grep -oE '"[0-9a-f]+"' | tr -d '"')
hashed_name_new_txid="${hashed_name_new_result[0]}"
hashed_name_new_rand="${hashed_name_new_result[1]}"

echo "Wait for $HASHED_DOMAIN pre-registration to mature"
new_blocks 12

echo "Register $HASHED_DOMAIN"
$bitcoin_cli name_firstupdate "$HASHED_NAME" "$hashed_name_new_rand" "$hashed_name_new_txid"

echo "Wait for $HASHED_DOMAIN registration to confirm"
new_blocks 1

echo "Configure $HASHED_DOMAIN with hashed TLSA record"
$bitcoin_cli name_update "$HASHED_NAME" "{\"ip\":\"107.152.38.155\",\"map\":{\"*\":{\"tls\":[[2,1,1,\"$TLSA_HASHED_PUB_SHA256_B64\"]]},\"sub1\":{\"map\":{\"sub2\":{\"map\":{\"sub3\":{\"ip\":\"107.152.38.155\"}}}}},\"_tor\":{\"txt\":\"dhflg7a7etr77hwt4eerwoovhg7b5bivt2jem4366dt4psgnl5diyiyd.onion\"}}}"

echo "Wait for hashed TLSA update to confirm"
new_blocks 1

echo "Ensure hashed TLSA rejects missing preimage via AIA"
assert_raises_error "curl --silent --show-error --fail $AIA_TEST_URL/aia?domain=$HASHED_DOMAIN%20Domain%20AIA%20Parent%20CA" "404"

echo "Fetch hashed $HASHED_DOMAIN CA via Encaya AIA using pubkey preimage"
curl --silent --show-error --fail --get --data-urlencode "domain=$HASHED_DOMAIN Domain AIA Parent CA" --data-urlencode "pubb64=$TLSA_HASHED_PUB_B64" --data-urlencode "pubsha256=$TLSA_HASHED_PUB_SHA256_HEX" "$AIA_TEST_URL/aia" > "$HASHED_PARENT_CA_DER"
openssl x509 -inform DER -in "$HASHED_PARENT_CA_DER" -out "$HASHED_PARENT_CA_PEM"
ca_pem=$(cat "$HASHED_PARENT_CA_PEM")
assert_contains "$ca_pem" "BEGIN CERTIFICATE" "Encaya did not return hashed $HASHED_DOMAIN Domain AIA Parent CA"

echo "Fetch hashed $HASHED_DOMAIN CA via curl"
echo "$ca_pem" | grep -i "BEGIN CERTIFICATE"

hashed_domain_ca_sha256_hex=$(get_cert_spki_sha256_hex "$ca_pem")
generated_key_sha256_hex=$(sha256_hex_upper "$HASHED_CA_KEY")
assert_equal "$hashed_domain_ca_sha256_hex" "$generated_key_sha256_hex" "Encaya issued parent CA key did not match generated hashed key"

echo "Query hashed TLSA Authoritative via dig"
dig_output=$(dig -p 5391 @127.0.0.1 TLSA "*.$HASHED_DOMAIN")
dig_short=$(dig +short -p 5391 @127.0.0.1 TLSA "*.$HASHED_DOMAIN")
echo "$dig_output"
echo "Checking hashed response correctness"
observed_tlsa_hex=$(tlsa_hex_from_dig "$dig_short")
assert_equal "$observed_tlsa_hex" "$hashed_domain_ca_sha256_hex" "Hashed authoritative TLSA digest mismatch"

echo "Query hashed TLSA Recursive via dig"
dig_output=$(dig -p 53 @127.0.0.1 TLSA "*.$HASHED_DOMAIN")
dig_short=$(dig +short -p 53 @127.0.0.1 TLSA "*.$HASHED_DOMAIN")
echo "$dig_output"
echo "Checking hashed recursive response correctness"
observed_tlsa_hex=$(tlsa_hex_from_dig "$dig_short")
assert_equal "$observed_tlsa_hex" "$hashed_domain_ca_sha256_hex" "Hashed recursive TLSA digest mismatch"

echo "Generate local leaf certificate signed by hashed parent"
generate_leaf_cert

echo "Start local HTTPS server for Chromium hashed AIA test"
start_https_server

echo "Initialize NSS DB for Chromium hashed AIA test"
prepare_nss_db

echo "Trust Encaya root CA for Chromium hashed AIA test"
trust_encaya_root

echo "Run Chromium headless and verify real TLS+AIA workflow"
chromium_output=$(chromium_fetch_dom)
assert_contains "$chromium_output" "Cool or nah" "Chromium did not render expected page content over validated TLS"

if [[ "$chromium_output" == *"Your connection is not private"* ]]; then
    fail_test "Chromium reported certificate error instead of successful validation"
fi

echo "Hashed AIA Chromium test passed"

echo "Generate expired leaf certificate for Chromium negative test"
generate_expired_leaf_cert

echo "Start local HTTPS server with expired leaf certificate"
start_https_server_expired_test

echo "Run Chromium headless and verify expired cert is rejected"
expired_chromium_output=$(chromium_fetch_dom_impl "$TEST_TMPDIR/chrome-profile-expired" "$TEST_TMPDIR/chrome-expired.log" "$HASHED_DOMAIN" "https://$HASHED_DOMAIN:$HTTPS_SERVER_PORT/index.html" || true)
if [[ "$expired_chromium_output" != *"Your connection is not private"* ]]; then
    echo "$expired_chromium_output"
    fail_test "Chromium did not reject expired certificate"
fi

echo "Expired cert Chromium negative test passed"

STAPLED_TEST_TMPDIR=$(mktemp -d)
STAPLED_CHROME_PROFILE_DIR="$STAPLED_TEST_TMPDIR/chrome-profile"
STAPLED_LABEL="testlsstapled$(date +%s%N | sha256sum | cut -c1-8)"
STAPLED_NAME="d/$STAPLED_LABEL"
STAPLED_DOMAIN="$STAPLED_LABEL.bit"
STAPLED_CA_KEY="$STAPLED_TEST_TMPDIR/stapled-ca.key"
STAPLED_CA_PUB_DER="$STAPLED_TEST_TMPDIR/stapled-ca-pub.der"
STAPLED_PARENT_CA_DER="$STAPLED_TEST_TMPDIR/stapled-parent-ca.der"
STAPLED_PARENT_CA_PEM="$STAPLED_TEST_TMPDIR/stapled-parent-ca.pem"
STAPLED_LEAF_KEY="$STAPLED_TEST_TMPDIR/stapled-leaf.key"
STAPLED_LEAF_CSR="$STAPLED_TEST_TMPDIR/stapled-leaf.csr"
STAPLED_LEAF_CERT="$STAPLED_TEST_TMPDIR/stapled-leaf.pem"
STAPLED_LEAF_EXT="$STAPLED_TEST_TMPDIR/stapled-leaf-ext.cnf"
STAPLED_LEAF_SERIAL="$STAPLED_TEST_TMPDIR/stapled-leaf.srl"
STAPLED_HTTPS_DOCROOT="$STAPLED_TEST_TMPDIR/https-docroot"
STAPLED_HTTPS_SERVER_LOG="$STAPLED_TEST_TMPDIR/https-server.log"
STAPLED_HTTPS_SERVER_PORT=4444

function cleanup_stapled_tests()
{
    if [[ -n "${STAPLED_HTTPS_SERVER_PID:-}" ]]; then
        kill "$STAPLED_HTTPS_SERVER_PID" 2>/dev/null || true
        wait "$STAPLED_HTTPS_SERVER_PID" 2>/dev/null || true
    fi

    rm -rf "$STAPLED_TEST_TMPDIR"
}

trap 'cleanup_stapled_tests; cleanup_aia_tests' EXIT

function fail_stapled_test()
{
    echo "ERROR: $*" >&2
    exit 1
}

function assert_contains_stapled_test()
{
    haystack="$1"
    needle="$2"
    err_msg="$3"

    if [[ "$haystack" != *"$needle"* ]]; then
        echo "$haystack"
        fail_stapled_test "$err_msg"
    fi
}

function chromium_fetch_dom_stapled_test()
{
    chromium_fetch_dom_impl "$STAPLED_CHROME_PROFILE_DIR" "$STAPLED_TEST_TMPDIR/chrome.log" "$STAPLED_DOMAIN" "https://$STAPLED_DOMAIN:$STAPLED_HTTPS_SERVER_PORT/index.html" || true
}

function start_https_server_stapled_test()
{
    pkill -f "openssl s_server -accept $STAPLED_HTTPS_SERVER_PORT" 2>/dev/null || true

    mkdir -p "$STAPLED_HTTPS_DOCROOT"
    cat > "$STAPLED_HTTPS_DOCROOT/index.html" <<EOF
<!DOCTYPE html>
<html>
<body>
Cool or nah stapled
</body>
</html>
EOF

    (
        cd "$STAPLED_HTTPS_DOCROOT"
        openssl s_server -accept "$STAPLED_HTTPS_SERVER_PORT" -cert "$STAPLED_LEAF_CERT" -key "$STAPLED_LEAF_KEY" -WWW
    ) > "$STAPLED_HTTPS_SERVER_LOG" 2>&1 &
    STAPLED_HTTPS_SERVER_PID=$!
    sleep 2

    if ! kill -0 "$STAPLED_HTTPS_SERVER_PID" 2>/dev/null; then
        cat "$STAPLED_HTTPS_SERVER_LOG"
        fail_stapled_test "Local stapled HTTPS server failed to start"
    fi
}

function generate_stapled_pubkey_material_test()
{
    openssl ecparam -name prime256v1 -genkey -noout -out "$STAPLED_CA_KEY"
    openssl pkey -in "$STAPLED_CA_KEY" -pubout -outform DER -out "$STAPLED_CA_PUB_DER"

    STAPLED_PUB_B64=$(to_urlsafe_base64 "$STAPLED_CA_PUB_DER")
}

function get_name_address_stapled_test()
{
    $bitcoin_cli name_show "$1" |
        jq -r '.address'
}

function build_stapled_message_test()
{
    STAPLED_MESSAGE_JSON=$(PUBB64="$STAPLED_PUB_B64" DOMAIN="$STAPLED_DOMAIN" ADDRESS="$STAPLED_BLOCKCHAIN_ADDRESS" \
        jq -cnS '{address: env.ADDRESS, domain: env.DOMAIN, x509pub: env.PUBB64}')

    STAPLED_MESSAGE="Namecoin X.509 Stapled Certification: $STAPLED_MESSAGE_JSON"

    STAPLED_BLOCKCHAIN_SIG=$($bitcoin_cli signmessage "$STAPLED_BLOCKCHAIN_ADDRESS" "$STAPLED_MESSAGE")
    STAPLED_SIGS_JSON=$(BLOCKCHAIN_ADDRESS="$STAPLED_BLOCKCHAIN_ADDRESS" BLOCKCHAIN_SIG="$STAPLED_BLOCKCHAIN_SIG" \
        jq -cn '[{blockchainaddress: env.BLOCKCHAIN_ADDRESS, blockchainsig: env.BLOCKCHAIN_SIG}]')
    STAPLED_SIGS_URLENCODED=$(SIGS_JSON="$STAPLED_SIGS_JSON" jq -rn 'env.SIGS_JSON | @uri')
}

function generate_stapled_leaf_cert_test()
{
    printf '%s\n' "$stapled_ca_pem" > "$STAPLED_PARENT_CA_PEM"

    openssl ecparam -name prime256v1 -genkey -noout -out "$STAPLED_LEAF_KEY"
    openssl req -new -key "$STAPLED_LEAF_KEY" -subj "/CN=$STAPLED_DOMAIN" -out "$STAPLED_LEAF_CSR"

    cat > "$STAPLED_LEAF_EXT" <<EOF
[ext]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$STAPLED_DOMAIN
authorityInfoAccess=caIssuers;URI:$AIA_TEST_HOST_URL/aia?domain=$STAPLED_DOMAIN%20Domain%20AIA%20Parent%20CA&pubb64=$STAPLED_PUB_B64&sigs=$STAPLED_SIGS_URLENCODED
EOF

    openssl x509 -req -in "$STAPLED_LEAF_CSR" -CA "$STAPLED_PARENT_CA_PEM" -CAkey "$STAPLED_CA_KEY" -CAcreateserial -CAserial "$STAPLED_LEAF_SERIAL" -out "$STAPLED_LEAF_CERT" -days 3650 -sha256 -extfile "$STAPLED_LEAF_EXT" -extensions ext
}

echo "Generate stapled public key material for local HTTPS server"
generate_stapled_pubkey_material_test

echo "Pre-register $STAPLED_DOMAIN"
readarray -t stapled_name_new_result < <($bitcoin_cli name_new "$STAPLED_NAME" | grep -oE '"[0-9a-f]+"' | tr -d '"')
stapled_name_new_txid="${stapled_name_new_result[0]}"
stapled_name_new_rand="${stapled_name_new_result[1]}"

echo "Wait for $STAPLED_DOMAIN pre-registration to mature"
new_blocks 12

echo "Register $STAPLED_DOMAIN"
$bitcoin_cli name_firstupdate "$STAPLED_NAME" "$stapled_name_new_rand" "$stapled_name_new_txid"

echo "Wait for $STAPLED_DOMAIN registration to confirm"
new_blocks 1

echo "Configure $STAPLED_DOMAIN without blockchain TLSA data"
$bitcoin_cli name_update "$STAPLED_NAME" '{"ip":"107.152.38.155"}'

echo "Wait for stapled name update to confirm"
new_blocks 1

echo "Verify $STAPLED_DOMAIN has no TLSA data on-chain"
stapled_tlsa_short=$(dig +short -p 5391 @127.0.0.1 TLSA "*.$STAPLED_DOMAIN")
assert_equal "$stapled_tlsa_short" "" "Stapled test domain unexpectedly had authoritative TLSA data"
stapled_tlsa_short=$(dig +short -p 53 @127.0.0.1 TLSA "*.$STAPLED_DOMAIN")
assert_equal "$stapled_tlsa_short" "" "Stapled test domain unexpectedly had recursive TLSA data"

echo "Resolve current blockchain owner address for $STAPLED_DOMAIN"
STAPLED_BLOCKCHAIN_ADDRESS=$(get_name_address_stapled_test "$STAPLED_NAME")

echo "Create stapled Namecoin certification signature"
build_stapled_message_test

echo "Ensure stapled AIA rejects missing signature data"
stapled_negative_output=$(curl --silent --show-error --fail --get --data-urlencode "domain=$STAPLED_DOMAIN Domain AIA Parent CA" --data-urlencode "pubb64=$STAPLED_PUB_B64" "$AIA_TEST_URL/aia" 2>&1 || true)
assert_contains_stapled_test "$stapled_negative_output" "404" "Stapled AIA missing-signature check did not return 404"

echo "Ensure stapled AIA rejects wrong signature data"
STAPLED_WRONG_SIGS_JSON=$(BLOCKCHAIN_ADDRESS="$STAPLED_BLOCKCHAIN_ADDRESS" jq -cn '[{blockchainaddress: env.BLOCKCHAIN_ADDRESS, blockchainsig: "invalid"}]')
stapled_wrong_sig_output=$(curl --silent --show-error --fail --get --data-urlencode "domain=$STAPLED_DOMAIN Domain AIA Parent CA" --data-urlencode "pubb64=$STAPLED_PUB_B64" --data-urlencode "sigs=$STAPLED_WRONG_SIGS_JSON" "$AIA_TEST_URL/aia" 2>&1 || true)
assert_contains_stapled_test "$stapled_wrong_sig_output" "404" "Stapled AIA wrong-signature check did not return 404"

echo "Ensure stapled AIA accepts multiple signature entries"
STAPLED_MULTI_SIGS_JSON=$(BLOCKCHAIN_ADDRESS="$STAPLED_BLOCKCHAIN_ADDRESS" BLOCKCHAIN_SIG="$STAPLED_BLOCKCHAIN_SIG" jq -cn '[{blockchainaddress: env.BLOCKCHAIN_ADDRESS, blockchainsig: "invalid"}, {blockchainaddress: env.BLOCKCHAIN_ADDRESS, blockchainsig: env.BLOCKCHAIN_SIG}]')
curl --silent --show-error --fail --get --data-urlencode "domain=$STAPLED_DOMAIN Domain AIA Parent CA" --data-urlencode "pubb64=$STAPLED_PUB_B64" --data-urlencode "sigs=$STAPLED_MULTI_SIGS_JSON" "$AIA_TEST_URL/aia" > "$STAPLED_PARENT_CA_DER"
openssl x509 -inform DER -in "$STAPLED_PARENT_CA_DER" -out "$STAPLED_PARENT_CA_PEM"
stapled_multi_ca_pem=$(cat "$STAPLED_PARENT_CA_PEM")
assert_contains_stapled_test "$stapled_multi_ca_pem" "BEGIN CERTIFICATE" "Stapled AIA multi-signature acceptance failed"

echo "Fetch stapled $STAPLED_DOMAIN CA via Encaya AIA using Namecoin signature"
curl --silent --show-error --fail --get --data-urlencode "domain=$STAPLED_DOMAIN Domain AIA Parent CA" --data-urlencode "pubb64=$STAPLED_PUB_B64" --data-urlencode "sigs=$STAPLED_SIGS_JSON" "$AIA_TEST_URL/aia" > "$STAPLED_PARENT_CA_DER"
openssl x509 -inform DER -in "$STAPLED_PARENT_CA_DER" -out "$STAPLED_PARENT_CA_PEM"
stapled_ca_pem=$(cat "$STAPLED_PARENT_CA_PEM")
assert_contains_stapled_test "$stapled_ca_pem" "BEGIN CERTIFICATE" "Encaya did not return stapled $STAPLED_DOMAIN Domain AIA Parent CA"

echo "Verify stapled issuer key matches signed public key"
stapled_domain_ca_sha256_hex=$(get_cert_spki_sha256_hex "$stapled_ca_pem")
stapled_generated_key_sha256_hex=$(sha256_hex_upper "$STAPLED_CA_KEY")
assert_equal "$stapled_domain_ca_sha256_hex" "$stapled_generated_key_sha256_hex" "Encaya issued stapled parent CA key did not match signed key"

echo "Generate local leaf certificate signed by stapled parent"
generate_stapled_leaf_cert_test

echo "Start local HTTPS server for Chromium stapled AIA test"
start_https_server_stapled_test

echo "Initialize NSS DB for Chromium stapled AIA test"
prepare_nss_db

echo "Trust Encaya root CA for Chromium stapled AIA test"
trust_encaya_root

echo "Run Chromium headless and verify stapled TLS+AIA workflow"
stapled_chromium_output=$(chromium_fetch_dom_stapled_test)
assert_contains_stapled_test "$stapled_chromium_output" "Cool or nah stapled" "Chromium did not render expected page content over stapled TLS validation"

if [[ "$stapled_chromium_output" == *"Your connection is not private"* ]]; then
    fail_stapled_test "Chromium reported certificate error instead of successful stapled validation"
fi

echo "Stapled AIA Chromium test passed"
echo "Functional test suite passed"
