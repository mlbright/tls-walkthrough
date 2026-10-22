#!/usr/bin/env bash
# SPDX-License-Identifier: MIT  (Copyright (c) 2026 Martin-Louis Bright; see LICENSE)
# =============================================================================
# tls13-walkthrough.sh — take one real TLS 1.3 handshake apart, message by
# message, and re-do the security checks by hand.
#
#   Usage:   ./tls13-walkthrough.sh [host] [port]        (default cpacket.com 443)
#
#   Env overrides:
#     OPENSSL=/path/to/openssl  OpenSSL 1.1.1+ (3.x recommended; LibreSSL won't
#                               work). macOS: OPENSSL=$(brew --prefix openssl@3)/bin/openssl
#     CAFILE=/path/bundle.pem   trust store (default: the system CA bundle)
#     CONNECT_TO=ip:port        TCP target, when it differs from host:port
#                               (SNI and name checks still use <host>)
#     HTTP_METHOD=GET           request sent after the handshake (default HEAD)
#     TIMEOUT=15                seconds per network operation
#     PAUSE=0                   never pause (it only pauses in a terminal anyway)
#
# Pausing
#   Run in a terminal, the walkthrough stops after every step (each numbered
#   section and each subsection), shows a "What just happened" recap, and waits:
#     Enter  next step     s  skip to the next section
#     c      run to the end without stopping     q  quit (exit status 130)
#   Piped or redirected, it never stops, but the recaps are still printed, so
#   `./tls13-walkthrough.sh > run.txt` gives a complete annotated transcript.
#
# The sections
#    1. Prerequisites       openssl version, trust store
#    2. DNS                 name -> address (not protected by TLS)
#    3. Handshake           ONE TLS 1.3 connection with `openssl s_client`, recording
#                           every record and handshake message as raw bytes (-msg;
#                           OpenSSL prints encrypted ones after decrypting them), the
#                           traffic secrets (-keylogfile), the session ticket (-sess_out).
#                           Everything up to section 11 takes those bytes apart.
#    4. ClientHello         \
#    5. ServerHello          | decoded byte by byte from the capture
#    6. Key schedule         | (RFC 8446)
#    7. EncryptedExtensions /
#    8. Certificate         the chain, validated by hand (RFC 5280 §6, simplified):
#                           path building, each signature, validity, basic constraints,
#                           key usage, EKU, path length, hostname, revocation, CT
#    9. CertificateVerify   proof the server holds the leaf's private key
#   10. Finished            proof both sides saw the same handshake and derived the same keys
#   11. After the handshake application data, session tickets
#   12. Resumption          a second connection using the ticket: no certificates
#   13. Timing              DNS / TCP / TLS with curl
#   14. Summary
#
# Try these next (public test sites that speak TLS 1.3 and fail on purpose):
#   ./tls13-walkthrough.sh expired-isrgrootx1.letsencrypt.org   expired leaf
#   ./tls13-walkthrough.sh revoked-isrgrootx1.letsencrypt.org   revoked leaf
#   ./tls13-walkthrough.sh expired-rsa-dv.ssl.com               expired leaf, another CA
#   ./tls13-walkthrough.sh revoked-rsa-dv.ssl.com               revoked leaf, another CA
#
# Exit status: 0 = every check passed, 1 = at least one FAIL, 2 = could not run,
#              130 = quit at a pause (q) or interrupted (Ctrl-C).
# Everything it captured stays in a temp directory printed at the end. Note that
# keylog.txt can decrypt a packet capture of that session — delete it when done.
#
# Portability: bash 3.2+ (macOS default is fine), POSIX awk (mawk/BSD awk), od.
# =============================================================================

set -u -o pipefail # deliberately no `set -e`: a failed check should be
# reported and the walkthrough should carry on.

HOST="${1:-cpacket.com}"
PORT="${2:-443}"
CONNECT_TO="${CONNECT_TO:-$HOST:$PORT}"
OPENSSL="${OPENSSL:-openssl}"
TIMEOUT="${TIMEOUT:-15}"
HTTP_METHOD="${HTTP_METHOD:-HEAD}"

# ----------------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  RED=$'\033[31m'
  GRN=$'\033[32m'
  YEL=$'\033[33m'
  CYN=$'\033[36m'
  MAG=$'\033[35m'
  RST=$'\033[0m'
else
  BOLD=""
  DIM=""
  RED=""
  GRN=""
  YEL=""
  CYN=""
  MAG=""
  RST=""
fi

# Pause only when someone is at a terminal to press a key.
PAUSING=0
if [ "${PAUSE:-1}" != 0 ] && [ -t 0 ] && [ -t 1 ]; then PAUSING=1; fi
SKIP_SECTION=0 # set by "s": no more pauses until the next section

W=$(mktemp -d "${TMPDIR:-/tmp}/tls13-walkthrough.XXXXXX") || {
  echo "mktemp failed" >&2
  exit 2
}
RESULTS="$W/results.txt"
: >"$RESULTS"

STEP=0
STEP_TITLE=""
# Verdicts within the current step, so its recap can explain them.
STEP_FAILS=0
STEP_WARNS=0
STEP_SKIPS=0
step_start() {
  STEP_TITLE=$1
  STEP_FAILS=0
  STEP_WARNS=0
  STEP_SKIPS=0
}
section() {
  STEP=$((STEP + 1))
  SKIP_SECTION=0
  step_start "[$STEP] $*"
  printf '\n%s%s[%d] %s%s\n' "$BOLD" "$CYN" "$STEP" "$*" "$RST"
}
subsection() {
  step_start "[$STEP] $*"
  printf '\n   %s%s%s\n' "$BOLD" "$*" "$RST"
}
note() { printf '   %s%s%s\n' "$DIM" "$*" "$RST"; } # intro lines
kv() { printf '     %-26s %s\n' "$1" "$2"; }        # key/value lines
pass() {
  printf '   %s[PASS]%s %s\n' "$GRN" "$RST" "$*"
  echo "PASS|$*" >>"$RESULTS"
}
fail() {
  printf '   %s[FAIL]%s %s\n' "$RED" "$RST" "$*"
  echo "FAIL|$*" >>"$RESULTS"
  STEP_FAILS=$((STEP_FAILS + 1))
}
warn() {
  printf '   %s[WARN]%s %s\n' "$YEL" "$RST" "$*"
  echo "WARN|$*" >>"$RESULTS"
  STEP_WARNS=$((STEP_WARNS + 1))
}
skip() {
  printf '   %s[SKIP]%s %s\n' "$DIM" "$RST" "$*"
  echo "SKIP|$*" >>"$RESULTS"
  STEP_SKIPS=$((STEP_SKIPS + 1))
}

# recap_text LINE... — the "What just happened" block that ends a step: one
# argument per line, written for someone who has never looked inside a
# handshake. Adds a line for any FAIL / WARN / SKIP in the step.
recap_text() {
  printf '\n   %s%s> What just happened%s\n' "$BOLD" "$MAG" "$RST"
  # The arguments are re-flowed, so values of any length fit: a line starting
  # "- " opens a bullet, a line starting with spaces continues it, and any other
  # line continues the current paragraph (or starts one after a bullet).
  printf '%s\n' "$@" | awk -v W=84 '
    function wrap(s, b,   n, w, i, line, pre) {
      n = split(s, w, " "); line = ""; pre = ""
      for (i = 1; i <= n; i++) {
        if (line != "" && length(pre line " " w[i]) > W) { print "     " pre line; line = w[i]; pre = b ? "  " : "" }
        else line = (line == "" ? w[i] : line " " w[i])
      }
      if (line != "") print "     " pre line
    }
    function flush() { if (item != "") wrap(item, bul); item = "" }
    /^- / { flush(); item = $0; bul = 1; next }
    /^ /  { sub(/^ +/, ""); item = item " " $0; next }
    { if (bul) { flush(); bul = 0 }; item = (item == "" ? $0 : item " " $0) }
    END { flush() }'
  if [ "$STEP_FAILS" -gt 0 ]; then
    printf '     %sA real client would have aborted the connection at that FAIL: a browser shows%s\n' "$RED" "$RST"
    printf '     %s"Your connection is not private" and sends nothing more. The walkthrough keeps%s\n' "$RED" "$RST"
    printf '     %sgoing anyway so you can see the remaining checks.%s\n' "$RED" "$RST"
  fi
  if [ "$STEP_WARNS" -gt 0 ]; then
    printf '     %sWARN means most clients accept this anyway; the WARN line says what to watch for.%s\n' "$YEL" "$RST"
  fi
  if [ "$STEP_SKIPS" -gt 0 ]; then
    printf '     %sSKIP means the check could not run here; the SKIP line says why.%s\n' "$DIM" "$RST"
  fi
}
# recap LINE... — print the recap, then wait for the learner.
recap() {
  recap_text "$@"
  pause_point
}
pause_point() {
  [ "$PAUSING" = 1 ] && [ "$SKIP_SECTION" = 0 ] || return 0
  local prompt key
  prompt="   -- Enter: next step | s: skip to next section | c: run to the end | q: quit "
  printf '\n%s%s%s' "$DIM" "$prompt" "$RST"
  IFS= read -rsn1 key </dev/tty || key=c
  printf '\r%*s\r' "${#prompt}" ''
  case "$key" in
    s | S) SKIP_SECTION=1 ;;
    c | C) PAUSING=0 ;;
    q | Q)
      printf '   Stopped after %s.\n   Artifacts so far: %s\n' "$STEP_TITLE" "$W"
      exit 130
      ;;
  esac
}
die() {
  printf '%sERROR:%s %s\n' "$RED" "$RST" "$*" >&2
  echo "Artifacts: $W" >&2
  exit 2
}
short() {
  local s=$1 n=${2:-32}
  if [ ${#s} -gt "$n" ]; then printf '%s...' "${s:0:$n}"; else printf '%s' "$s"; fi
}

# ----------------------------------------------------------------------------
# Byte helpers. Handshake messages travel through this script as lowercase hex
# strings; these convert between hex and raw bytes for openssl to hash/verify.
# ----------------------------------------------------------------------------
bin2hex() { od -An -v -tx1 | tr -d ' \n'; }
hex2bin() {
  if command -v xxd >/dev/null 2>&1; then
    xxd -r -p
  elif command -v perl >/dev/null 2>&1; then
    perl -ne 's/\s+//g; print pack("H*", $_)'
  else
    local h
    h=$(tr -d ' \n')
    printf '%b' "$(printf '%s' "$h" | sed 's/../\\x&/g')"
  fi
}
str2hex() { printf '%s' "$1" | bin2hex; }

# run_timeout SECONDS STDIN_FILE CMD...  (coreutils timeout isn't on macOS)
run_timeout() {
  local secs=$1 in=$2
  shift 2
  if command -v timeout >/dev/null 2>&1; then
    timeout "$secs" "$@" <"$in"
    return $?
  fi
  if command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$secs" "$@" <"$in"
    return $?
  fi
  "$@" <"$in" &
  local pid=$!
  (
    sleep "$secs"
    kill -TERM "$pid" 2>/dev/null
  ) >/dev/null 2>&1 &
  local wd=$!
  wait "$pid"
  local rc=$?
  kill "$wd" 2>/dev/null
  wait "$wd" 2>/dev/null
  return $rc
}

# OpenSSL prints dates like "Oct 22 10:16:00 2026 GMT"; convert to epoch seconds.
to_epoch() {
  date -u -d "$1" +%s 2>/dev/null ||                             # GNU date
    date -j -u -f '%b %e %H:%M:%S %Y %Z' "$1" +%s 2>/dev/null || # BSD/macOS date
    echo ""
}

# ----------------------------------------------------------------------------
# Certificate helpers
# ----------------------------------------------------------------------------
ctext() { "$OPENSSL" x509 -in "$1" -noout -text 2>/dev/null; }
cfield() { "$OPENSSL" x509 -in "$1" -noout "-$2" -nameopt RFC2253 2>/dev/null | sed 's/^[A-Za-z]*= *//'; }
fp_of() {
  local o
  o=$("$OPENSSL" x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null)
  printf '%s' "${o##*=}"
}
subject_hash() { "$OPENSSL" x509 -in "$1" -noout -subject_hash 2>/dev/null; }
issuer_hash() { "$OPENSSL" x509 -in "$1" -noout -issuer_hash 2>/dev/null; }
# First value line under an X.509 extension heading in `x509 -text` output.
ext_val() { awk -v h="$2" 'f { sub(/^ +/, ""); print; exit } index($0, h ":") { f = 1 }' "$1"; }
ext_is_critical() { grep -q "$2: critical" "$1"; }

# ----------------------------------------------------------------------------
# sig_check CHILD PARENT [VERBOSE]
# Checks that PARENT's private key signed CHILD, the way a TLS client does,
# and without letting OpenSSL do the X.509 logic for us:
#   1. Split the child's DER into its 3 top-level fields:
#        Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
#   2. Take the exact DER bytes of tbsCertificate (the signed part).
#   3. Take the raw signature from the signatureValue BIT STRING.
#   4. Verify that signature over those bytes with PARENT's public key.
# ----------------------------------------------------------------------------
sig_check() {
  local child=$1 parent=$2 verbose=${3:-0}
  local t
  t="$W/sig.$(basename "$child" .pem).$(basename "$parent" .pem)"
  "$OPENSSL" x509 -in "$child" -outform DER -out "$t.der" 2>/dev/null || return 1
  # asn1parse lines look like "    4:d=1  hl=4 l=1197 cons: SEQUENCE".
  # d=1 = direct children of the outer SEQUENCE; keep "offset header_len content_len".
  "$OPENSSL" asn1parse -inform DER -in "$t.der" 2>/dev/null |
    sed -nE 's/^ *([0-9]+):d=1 +hl= *([0-9]+) +l= *([0-9]+).*/\1 \2 \3/p' >"$t.layout"
  local t_off t_hl t_len s_off s_hl s_len
  read -r t_off t_hl t_len < <(sed -n 1p "$t.layout")
  read -r s_off s_hl s_len < <(sed -n 3p "$t.layout")
  [ -n "${t_off:-}" ] && [ -n "${s_len:-}" ] || return 1
  # tbsCertificate: the whole TLV (header + content), byte-exact. tail -c is 1-based.
  tail -c +$((t_off + 1)) "$t.der" | head -c $((t_hl + t_len)) >"$t.tbs"
  # signatureValue: BIT STRING content minus its leading "unused bits" byte.
  tail -c +$((s_off + s_hl + 2)) "$t.der" | head -c $((s_len - 1)) >"$t.sig"
  "$OPENSSL" x509 -in "$parent" -noout -pubkey >"$t.pub" 2>/dev/null || return 1

  local alg md="" kind=""
  alg=$(ctext "$child" | awk -F': ' '/Signature Algorithm:/ { print $2; exit }')
  case "$alg" in
    *[Ww]ith[Rr][Ss][Aa]*) kind=pkcs1 ;;
    ecdsa-with-*) kind=ecdsa ;;
    rsassaPss) kind=pss ;;
    ED25519 | ED448) kind=eddsa ;;
  esac
  case "$alg" in
    *[Ss][Hh][Aa]1[Ww]* | *SHA1) md=sha1 ;;
    *256*) md=sha256 ;; *384*) md=sha384 ;; *512*) md=sha512 ;;
  esac
  [ "$kind" = pss ] && md=$(ctext "$child" | awk '/Hash Algorithm:/ { print $3; exit }')

  if [ "$verbose" = 1 ]; then
    kv "signatureAlgorithm" "$alg"
    kv "tbsCertificate" "$(wc -c <"$t.tbs" | tr -d ' ') bytes (DER offset $t_off) <- this is what was signed"
    kv "signatureValue" "$(wc -c <"$t.sig" | tr -d ' ') bytes"
    if [ -n "$md" ] && [ "$kind" != eddsa ]; then
      local h
      h=$("$OPENSSL" dgst "-$md" -binary "$t.tbs" | bin2hex)
      kv "$md(tbsCertificate)" "$(short "$h" 40)"
      if [ "$kind" = pkcs1 ]; then
        # RSA PKCS#1 v1.5: s^e mod n gives back DigestInfo{hashAlg, digest}.
        # The digest inside must equal the hash we just computed.
        local rec
        rec=$("$OPENSSL" pkeyutl -verifyrecover -pubin -inkey "$t.pub" -in "$t.sig" 2>/dev/null |
          "$OPENSSL" asn1parse -inform DER 2>/dev/null | awk -F: '/OCTET STRING/ { print tolower($NF) }')
        kv "RSA: sig^e mod n" "DigestInfo digest = $(short "$rec" 40)"
        if [ "$rec" = "$h" ]; then note "      -> digest recovered from the signature matches the hash of tbsCertificate"; fi
      elif [ "$kind" = ecdsa ]; then
        # ECDSA: the signature is SEQUENCE { r, s }. Nothing to "recover";
        # the verifier recomputes a curve point from (hash, r, s, pubkey) and
        # checks that its x-coordinate equals r.
        local rs
        rs=$("$OPENSSL" asn1parse -inform DER -in "$t.sig" 2>/dev/null | awk -F: '/INTEGER/ { print $NF }')
        kv "ECDSA r" "$(short "$(echo "$rs" | sed -n 1p)" 40)"
        kv "ECDSA s" "$(short "$(echo "$rs" | sed -n 2p)" 40)"
      fi
    fi
  fi

  local ok=1
  case "$kind" in
    pkcs1 | ecdsa)
      "$OPENSSL" dgst "-$md" -verify "$t.pub" -signature "$t.sig" "$t.tbs" >/dev/null 2>&1 && ok=0
      ;;
    pss)
      "$OPENSSL" dgst "-$md" -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:auto \
        -verify "$t.pub" -signature "$t.sig" "$t.tbs" >/dev/null 2>&1 && ok=0
      ;;
    eddsa)
      "$OPENSSL" pkeyutl -verify -pubin -inkey "$t.pub" -rawin -in "$t.tbs" -sigfile "$t.sig" >/dev/null 2>&1 && ok=0
      ;;
    *) [ "$verbose" = 1 ] && note "      (signature algorithm '$alg' not handled by this script)" ;;
  esac
  [ "$md" = sha1 ] && [ "$verbose" = 1 ] && note "      SHA-1 signatures are rejected by modern clients"
  return $ok
}

# ----------------------------------------------------------------------------
# Parse `s_client -msg` output into two tab-separated files:
#   records.tsv:   n  dir  outer_type  inner_type  messages
#   handshake.tsv: n  dir  name        hex_of_the_whole_handshake_message
# The -msg dump of a TLS 1.3 encrypted record shows three things in order:
# the 5-byte RecordHeader (outer type, always 0x17 after ServerHello), the
# InnerContent byte (the real type, hidden inside the encryption), and then the
# decrypted handshake message(s), including their 4-byte type+length header.
# ----------------------------------------------------------------------------
parse_msglog() {
  awk -v R="$2" -v H="$3" '
  function flushmsg() { if (cur) printf "%d\t%s\t%s\t%s\n", ++seq, cdir, cname, hex > H; cur = 0; hex = "" }
  function flushrec() {
    if (rdir != "") printf "%d\t%s\t%s\t%s\t%s\n", ++nrec, rdir, (outer == "" ? "-" : outer),
                           (inner == "" ? "-" : inner), (msgs == "" ? "-" : msgs) > R
    rdir = ""; outer = ""; inner = ""; msgs = ""
  }
  /^(>>>|<<<) / {
    flushmsg()
    d = ($1 == ">>>") ? "C->S" : "S->C"
    if (index($0, "RecordHeader")) { flushrec(); rdir = d; want = "rh"; next }
    if (index($0, "InnerContent")) { want = "ic"; next }
    n = split($0, a, ", ")
    if (index($0, ", Handshake [")) { cname = a[n]; cdir = d; cur = 1; want = "hs"
                                       msgs = msgs (msgs == "" ? "" : " + ") cname; next }
    if (index($0, ", Alert ["))     { msgs = msgs (msgs == "" ? "" : " + ") "Alert: " a[n] }
    want = ""; next
  }
  /^    [0-9a-f][0-9a-f]/ {
    line = $0; gsub(/[^0-9a-f]/, "", line)
    if (want == "rh")      { outer = substr(line, 1, 2); want = "" }
    else if (want == "ic") { inner = substr(line, 1, 2); want = "" }
    else if (want == "hs") { hex = hex line }
    next
  }
  END { flushmsg(); flushrec() }' "$1"
}

# hs_hex FILE NAME DIR [OCCURRENCE] -> hex of that handshake message
hs_hex() { awk -F'\t' -v n="$2" -v d="$3" -v k="${4:-1}" '$3 == n && $2 == d { if (++c == k) { print $4; exit } }' "$1"; }

# Print the record-by-record timeline, with which traffic key protects each record.
print_timeline() {
  printf '     %3s  %-4s  %-28s %-17s %s\n' "#" "dir" "record type (outer->inner)" "protected by" "contents"
  awk -F'\t' '
  function tn(h) { return h == "14" ? "ChangeCipherSpec" : h == "15" ? "Alert" : h == "16" ? "Handshake" : h == "17" ? "AppData" : "0x" h }
  function out(n, d, r, k, w, c) { if (c > 1) w = w " x" c; printf "     %3s  %-4s  %-28s %-17s %s\n", n, d, r, k, w }
  {
    rec = tn($3); keys = "none (cleartext)"
    if ($4 != "-") {
      rec = rec "->" tn($4)
      if ($2 == "C->S") keys = cfin ? "client app key" : "client hs key"
      else              keys = sfin ? "server app key" : "server hs key"
    } else if ($3 == "14") keys = "none (no-op)"
    what = $5
    if (what == "-" && $4 == "17") what = ($2 == "C->S") ? "(HTTP request)" : "(HTTP response)"
    # collapse runs of identical application-data records
    sig = $2 SUBSEP rec SUBSEP keys SUBSEP what
    if ($4 == "17" && sig == psig) { pc++ }
    else { if (psig != "") out(pn, pd, pr, pk, pw, pc); psig = sig; pn = $1; pd = $2; pr = rec; pk = keys; pw = what; pc = 1 }
    if ($2 == "C->S" && $5 ~ /Finished/) cfin = 1
    if ($2 == "S->C" && $5 ~ /Finished/) sfin = 1
  }
  END { if (psig != "") out(pn, pd, pr, pk, pw, pc) }' "$1"
}

# ----------------------------------------------------------------------------
# decode_hello KIND HEX — decode a ClientHello (CH), ServerHello (SH) or
# EncryptedExtensions (EE) from its bytes. Byte layouts are from RFC 8446 §4.1.2,
# §4.1.3 and §4.3.1. Plain POSIX awk, so hex is converted by hand.
# ----------------------------------------------------------------------------
decode_hello() {
  printf '%s\n' "$2" | awk -v kind="$1" '
  function hv(s,  i, v) { v = 0; for (i = 1; i <= length(s); i++) v = v * 16 + index("0123456789abcdef", substr(s, i, 1)) - 1; return v }
  function B(o, n) { return substr(X, o * 2 + 1, n * 2) }          # n bytes at byte offset o
  function U(o, n) { return hv(B(o, n)) }                          # ...as an unsigned integer
  function grease(c) { return substr(c,1,1) == substr(c,3,1) && substr(c,2,1) == "a" && substr(c,4,1) == "a" }
  function nm(tab, c) { if (c in tab) return tab[c]; if (grease(c)) return "GREASE"; return "0x" c }
  function asc(o, n,  i, s) { s = ""; for (i = 0; i < n; i++) s = s sprintf("%c", U(o + i, 1)); return s }
  function l16(o, n, tab,  i, s) { s = ""; for (i = 0; i < n; i += 2) s = s (s == "" ? "" : ", ") nm(tab, B(o + i, 2)); return s }
  function row(k, v) { printf "     %-26s %s\n", k, v }
  function load(tab, s,  a, p, i, n) { n = split(s, a, "|"); for (i = 1; i <= n; i++) { split(a[i], p, "="); tab[p[1]] = p[2] } }
  BEGIN {
    load(CS, "1301=TLS_AES_128_GCM_SHA256|1302=TLS_AES_256_GCM_SHA384|1303=TLS_CHACHA20_POLY1305_SHA256|1304=TLS_AES_128_CCM_SHA256|1305=TLS_AES_128_CCM_8_SHA256|00ff=TLS_EMPTY_RENEGOTIATION_INFO_SCSV")
    load(GR, "0017=secp256r1|0018=secp384r1|0019=secp521r1|001d=x25519|001e=x448|0100=ffdhe2048|0101=ffdhe3072|0102=ffdhe4096|0103=ffdhe6144|0104=ffdhe8192|0200=MLKEM512|0201=MLKEM768|0202=MLKEM1024|11eb=SecP256r1MLKEM768|11ec=X25519MLKEM768|11ed=SecP384r1MLKEM1024|6399=X25519Kyber768Draft00")
    load(SA, "0401=rsa_pkcs1_sha256|0501=rsa_pkcs1_sha384|0601=rsa_pkcs1_sha512|0403=ecdsa_secp256r1_sha256|0503=ecdsa_secp384r1_sha384|0603=ecdsa_secp521r1_sha512|0804=rsa_pss_rsae_sha256|0805=rsa_pss_rsae_sha384|0806=rsa_pss_rsae_sha512|0807=ed25519|0808=ed448|0809=rsa_pss_pss_sha256|080a=rsa_pss_pss_sha384|080b=rsa_pss_pss_sha512|081a=ecdsa_brainpoolP256r1tls13_sha256|081b=ecdsa_brainpoolP384r1tls13_sha384|081c=ecdsa_brainpoolP512r1tls13_sha512|0201=rsa_pkcs1_sha1|0203=ecdsa_sha1|0904=mldsa44|0905=mldsa65|0906=mldsa87")
    load(VER, "0304=TLS 1.3|0303=TLS 1.2|0302=TLS 1.1|0301=TLS 1.0")
    load(EXT, "0000=server_name|0005=status_request|000a=supported_groups|000b=ec_point_formats|000d=signature_algorithms|0010=alpn|0012=signed_cert_timestamp|0015=padding|0016=encrypt_then_mac|0017=extended_master_secret|001b=compress_certificate|001c=record_size_limit|0023=session_ticket|0029=pre_shared_key|002a=early_data|002b=supported_versions|002c=cookie|002d=psk_key_exchange_modes|0031=post_handshake_auth|0032=signature_algorithms_cert|0033=key_share|fe0d=encrypted_client_hello|ff01=renegotiation_info")
    HRR = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
  }
  { X = tolower($0) }
  function ext(t, d, l,   n, p, s, kl, i, m) {
    if (t == "0000") {
      if (l == 0) return "(server acknowledges SNI)"
      n = U(d + 3, 2); return asc(d + 5, n) "   <- hostname in cleartext: picks the certificate"
    }
    if (t == "000a") { n = U(d, 2); return l16(d + 2, n, GR) }
    if (t == "000d" || t == "0032") { n = U(d, 2); return l16(d + 2, n, SA) }
    if (t == "002b") {
      if (kind == "CH") { n = U(d, 1); return l16(d + 1, n, VER) "   <- the real version offer" }
      return nm(VER, B(d, 2)) "   <- negotiated version"
    }
    if (t == "0033") {
      if (kind == "SH" && hrr) return "server wants a share for " nm(GR, B(d, 2))
      if (kind == "SH") { kl = U(d + 2, 2); return nm(GR, B(d, 2)) ", " kl "-byte public key " substr(B(d + 4, kl), 1, 16) "..." }
      n = U(d, 2); p = d + 2; s = ""
      while (p < d + 2 + n) { kl = U(p + 2, 2); s = s (s == "" ? "" : "; ") nm(GR, B(p, 2)) " (" kl "-byte key " substr(B(p + 4, kl), 1, 12) "...)"; p += 4 + kl }
      return s
    }
    if (t == "0010") {
      n = U(d, 2); p = d + 2; s = ""
      while (p < d + 2 + n) { kl = U(p, 1); s = s (s == "" ? "" : ", ") asc(p + 1, kl); p += 1 + kl }
      return s
    }
    if (t == "002d") { n = U(d, 1); s = ""; for (i = 0; i < n; i++) { m = U(d + 1 + i, 1); s = s (s == "" ? "" : ", ") (m == 1 ? "psk_dhe_ke" : m == 0 ? "psk_ke" : m) }; return s }
    if (t == "0029") {
      if (kind == "SH") return "server accepted PSK identity #" U(d, 2) " -> resumption, no certificate needed"
      n = U(d, 2); p = d + 2; i = 0
      while (p < d + 2 + n) { kl = U(p, 2); p += 2 + kl + 4; i++ }
      return i " ticket identity (" kl " bytes) + binder (HMAC proving we hold the PSK)"
    }
    if (t == "0005") return "please staple an OCSP response"
    if (t == "0012") return "please send SCTs"
    if (t == "001b") { n = U(d, 1); s = ""; for (i = 0; i < n; i += 2) { m = U(d + 1 + i, 2); s = s (s == "" ? "" : ", ") (m == 1 ? "zlib" : m == 2 ? "brotli" : m == 3 ? "zstd" : m) }; return s }
    if (t == "001c") return U(d, 2) " bytes"
    if (t == "002a") return (l == 4 ? "max_early_data_size=" U(d, 4) : "early data")
    if (t == "0015") return l " zero bytes"
    if (t == "0016" || t == "0017" || t == "000b" || t == "ff01" || t == "0023") return "(TLS 1.2 fallback only; meaningless in 1.3)"
    return l " bytes"
  }
  END {
    if (kind == "EE") { o = 4 }
    else {
      o = 4
      row("legacy_version", "0x" B(o, 2) "   <- frozen at TLS 1.2 for middlebox compatibility"); o += 2
      rnd = B(o, 32); hrr = (kind == "SH" && rnd == HRR)
      row("random", hrr ? "SHA-256(\"HelloRetryRequest\") -> this is a HelloRetryRequest" : substr(rnd, 1, 32) "..."); o += 32
      n = U(o, 1); row("legacy_session_id", n " bytes" (n ? "   <- non-empty: middlebox compatibility mode" : "")); o += 1 + n
      if (kind == "CH") { n = U(o, 2); row("cipher_suites", l16(o + 2, n, CS)); o += 2 + n; n = U(o, 1); o += 1 + n }
      else { row("cipher_suite", nm(CS, B(o, 2)) "   <- chosen"); o += 3 }
    }
    n = U(o, 2); o += 2; e = o + n
    if (o >= e) row("extensions", "(none)")
    while (o < e) { t = B(o, 2); l = U(o + 2, 2); row(nm(EXT, t), ext(t, o + 4, l)); o += 4 + l }
  }'
}

# decode_certmsg HEX OUTDIR — split the Certificate message (RFC 8446 §4.4.2)
# into DER certificates (OUTDIR/cert-N.hex) plus any per-certificate extensions.
# In TLS 1.3 a stapled OCSP response rides inside the leaf entry's extensions.
decode_certmsg() {
  printf '%s\n' "$1" | awk -v D="$2" '
  function hv(s,  i, v) { v = 0; for (i = 1; i <= length(s); i++) v = v * 16 + index("0123456789abcdef", substr(s, i, 1)) - 1; return v }
  function B(o, n) { return substr(X, o * 2 + 1, n * 2) }
  function U(o, n) { return hv(B(o, n)) }
  { X = tolower($0) }
  END {
    o = 4; cl = U(o, 1); o += 1 + cl
    ll = U(o, 3); o += 3; e = o + ll; i = 0
    printf "     %-26s %d bytes (empty for a server certificate)\n", "request_context", cl
    while (o < e) {
      n = U(o, 3); o += 3
      f = D "/cert-" i ".hex"; print B(o, n) > f; close(f); o += n
      el = U(o, 2); o += 2; p = o; ex = ""
      while (p < o + el) {
        t = B(p, 2); l = U(p + 2, 2)
        if (t == "0005") { f = D "/cert-" i ".ocsp.hex"; print B(p + 8, l - 4) > f; close(f); ex = ex " status_request (stapled OCSP, " l - 4 " bytes)" }
        else if (t == "0012") ex = ex " signed_certificate_timestamp (" l " bytes)"
        else ex = ex " 0x" t " (" l " bytes)"
        p += 4 + l
      }
      o += el
      printf "     %-26s %d-byte DER certificate%s\n", "certificate_list[" i "]", n, (ex == "" ? "" : "; extensions:" ex)
      i++
    }
    f = D "/cert-count"; print i > f; close(f)
  }'
}

# =============================================================================
# [1] Prerequisites
# =============================================================================
section "Prerequisites"
command -v "$OPENSSL" >/dev/null 2>&1 || die "openssl not found (set OPENSSL=...)"
OSSL_VER=$("$OPENSSL" version 2>/dev/null)
case "$OSSL_VER" in LibreSSL*) die "LibreSSL detected ($OSSL_VER). Use OpenSSL 3.x: OPENSSL=\$(brew --prefix openssl@3)/bin/openssl" ;; esac
v=$(echo "$OSSL_VER" | awk '{ print $2 }')
MAJ=${v%%.*}
rest=${v#*.}
MIN=${rest%%.*}
if [ "$MAJ" -lt 1 ] || { [ "$MAJ" -eq 1 ] && [ "$MIN" -lt 1 ]; }; then die "OpenSSL 1.1.1+ required for TLS 1.3 (found $OSSL_VER)"; fi
kv "openssl" "$OSSL_VER"
HAVE_KDF=0
"$OPENSSL" kdf -help >/dev/null 2>&1 && HAVE_KDF=1
[ "$HAVE_KDF" = 1 ] || note "OpenSSL < 3.0: no 'openssl kdf', so the Finished MACs can't be recomputed (step skipped)."

# The trust store. The client trusts these roots and only these; nothing the
# server sends can add a root.
if [ -n "${CAFILE:-}" ]; then
  CA=$CAFILE
else
  CA=""
  for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem \
    /etc/ssl/cert.pem /opt/homebrew/etc/openssl@3/cert.pem /usr/local/etc/openssl@3/cert.pem \
    "$("$OPENSSL" version -d 2>/dev/null | sed -E 's/^OPENSSLDIR: "(.*)"/\1/')/cert.pem"; do
    [ -s "$f" ] && {
      CA=$f
      break
    }
  done
fi
[ -n "$CA" ] && [ -s "$CA" ] || die "no CA bundle found; set CAFILE=/path/to/bundle.pem"
NROOTS=$(grep -c 'BEGIN CERTIFICATE' "$CA")
kv "trust store" "$CA ($NROOTS roots)"
kv "target" "https://$HOST:$PORT/  (TCP to $CONNECT_TO)"
kv "work dir" "$W"

# Keep the Certificate message in its plain form: OpenSSL 3.2+ can negotiate
# RFC 8879 certificate compression, which would change what we parse.
EXTRA_OPTS=""
"$OPENSSL" s_client -help 2>&1 | grep -q -- '-no_rx_cert_comp' && EXTRA_OPTS="-no_rx_cert_comp"
# s_client checks the chain but, unlike a browser, checks the name only if asked.
if echo "$HOST" | grep -Eq '^[0-9.]+$|:'; then N_OPT="-verify_ip $HOST"; else N_OPT="-verify_hostname $HOST"; fi

recap "Nothing has touched the network yet. Two things were set up:" \
  "- the tool: openssl, which this script drives to send, decode and verify bytes;" \
  "- the trust store: $NROOTS root certificates that came with your system. A root" \
  "  certificate belongs to a certificate authority (CA), a company whose job is to" \
  "  vouch that a public key belongs to a website. Your machine trusts exactly these" \
  "  roots, chosen in advance. Later, $HOST will have to show a chain of signatures" \
  "  leading back to one of them, or nothing it says can be believed."

# =============================================================================
# [2] DNS
# =============================================================================
section "DNS: where is $HOST?"
CHOST=${CONNECT_TO%:*}
CPORT=${CONNECT_TO##*:}
note "Before any TLS, the client resolves the name and opens a TCP connection (SYN, SYN-ACK, ACK = 1 RTT)."
note "Neither step is protected by TLS (use DoH/DoT for DNS privacy)."
if echo "$CHOST" | grep -Eq '^[0-9.]+$|:'; then
  kv "address" "$CHOST (literal)"
elif command -v getent >/dev/null 2>&1; then
  getent ahosts "$CHOST" | awk '{ print $1 }' | sort -u | while read -r a; do kv "address" "$a"; done
elif command -v dig >/dev/null 2>&1; then
  {
    dig +short A "$CHOST"
    dig +short AAAA "$CHOST"
  } | while read -r a; do kv "address" "$a"; done
else note "(no getent/dig; openssl will resolve it)"; fi
recap "The name $CHOST was turned into one or more IP addresses. TLS can only protect a" \
  "connection that already exists, so this lookup, and the TCP connection that comes" \
  "next, travel unencrypted: anyone on the network path can see which server you are" \
  "contacting. TLS will hide WHAT you say to it, not THAT you are talking to it."

# =============================================================================
# [3] One TLS 1.3 connection, fully recorded
# =============================================================================
section "Handshake: one TLS 1.3 connection to $HOST, fully recorded"
printf '%s / HTTP/1.1\r\nHost: %s\r\nUser-Agent: tls13-walkthrough\r\nConnection: close\r\n\r\n' "$HTTP_METHOD" "$HOST" >"$W/request.txt"
# -tls1_3          offer only TLS 1.3
# -servername      SNI (which site we want; the server uses it to pick a certificate)
# -alpn http/1.1   ALPN (which protocol runs inside TLS)
# -CAfile          the trust store s_client verifies against (same as ours)
# -status          ask for a stapled OCSP response
# -msg/-msgfile    raw bytes of every record and handshake message
# -keylogfile      traffic secrets (lets us recompute the Finished MACs)
# -sess_out        save the session ticket for the resumption step
# -ign_eof         keep reading after our request until the server closes
# shellcheck disable=SC2086
run_timeout "$TIMEOUT" "$W/request.txt" "$OPENSSL" s_client -connect "$CONNECT_TO" -servername "$HOST" \
  -tls1_3 -alpn http/1.1 -CAfile "$CA" $N_OPT -status -showcerts -ign_eof $EXTRA_OPTS \
  -msg -msgfile "$W/msg.log" -keylogfile "$W/keylog.txt" -sess_out "$W/session.pem" \
  >"$W/s_client.txt" 2>&1
# "Protocol: TLSv1.3" also appears when the handshake fails, so require a cipher.
if ! grep -Eq 'New, TLSv1\.3, Cipher is [A-Z]' "$W/s_client.txt"; then
  echo
  tail -20 "$W/s_client.txt" | sed 's/^/     /'
  die "no TLS 1.3 handshake with $CONNECT_TO (see above)"
fi
parse_msglog "$W/msg.log" "$W/records.tsv" "$W/handshake.tsv"
HS="$W/handshake.tsv"
pass "TLS 1.3 handshake completed ($(grep -m1 -o 'Cipher is [A-Z0-9_]*' "$W/s_client.txt"))"
NHSMSG=$(wc -l <"$HS" | tr -d ' ')
recap "The whole conversation with $HOST has already happened, in one go: openssl connected," \
  "did the TLS handshake, sent an HTTP $HTTP_METHOD request, read the reply and hung up." \
  "Along the way it recorded $NHSMSG handshake messages as raw bytes, plus the secret keys." \
  "From here until section 11 nothing more is sent: each step takes those recorded bytes" \
  "apart and re-does one of the checks your browser does silently on every HTTPS visit."

subsection "Record-by-record timeline"
note "Every TLS record has a 5-byte header: type, legacy version, length."
note "After ServerHello, every record's outer type is AppData (0x17). The real type"
note "sits inside the encryption. Each direction uses handshake keys until it sends Finished,"
note "then application keys."
echo
print_timeline "$W/records.tsv"
echo
note "The ChangeCipherSpec records are no-ops (RFC 8446 D.4). They make the exchange look like"
note "TLS 1.2 session resumption so middleboxes don't break it."
recap "Read the table top to bottom: it is the conversation, one TLS record per row." \
  "- Only the first records (the two Hellos) are readable by an eavesdropper. Every" \
  "  record after ServerHello says 'AppData' on the outside; its true type is hidden" \
  "  inside the encryption, shown here after the arrow." \
  "- 'protected by' shows which key encrypted each record. Each side switches from its" \
  "  handshake key to its application key right after sending its own Finished." \
  "- The client speaks, the server answers, and the client sends its Finished and its" \
  "  HTTP request back to back: the handshake cost a single round trip. That is TLS 1.3's" \
  "  headline improvement over TLS 1.2, which needed two."

# =============================================================================
# [4] ClientHello
# =============================================================================
section "ClientHello (client -> server, cleartext)"
note "The client offers everything up front, including a key share (an ephemeral DH public"
note "key) for the group it guesses the server will pick. That guess is what lets TLS 1.3"
note "finish in one round trip."
CH=$(hs_hex "$HS" ClientHello 'C->S')
[ -n "$CH" ] || die "ClientHello not found in the capture"
echo
CH_DEC=$(decode_hello CH "$CH")
printf '%s\n' "$CH_DEC"
CRANDOM=${CH:12:64} # bytes 6..37, identifies this session in the key log
# "X25519MLKEM768 (1216-byte key ...); x25519 (32-byte key ...)" -> "X25519MLKEM768; x25519"
CH_SHARES=$(printf '%s\n' "$CH_DEC" | sed -nE 's/^ +key_share +//p' | sed -E 's/ \([^)]*\)//g')
recap "The client's opening message, sent in the clear. The lines to notice:" \
  "- server_name: '$HOST' travels unencrypted, so the server can pick the right" \
  "  certificate (one IP address often hosts many sites). Observers can read it too." \
  "- supported_versions: the real version offer. legacy_version still says TLS 1.2" \
  "  because some old network boxes break on anything they don't recognise." \
  "- key_share: ${CH_SHARES:-(none)}. These are ephemeral ('use once, then discard')" \
  "  public keys, sent before the server has said anything. The client is guessing which" \
  "  key-agreement method the server will choose; a right guess saves a round trip." \
  "- the client's random value: fresh for every connection, so no recording of an old" \
  "  handshake can be replayed against this one."

# =============================================================================
# [5] ServerHello
# =============================================================================
section "ServerHello (server -> client, cleartext)"
note "The server picks one option from each list and returns its own key share. Both sides"
note "can now compute the same (EC)DHE shared secret. It never crosses the wire, and because"
note "both keys are ephemeral, a later theft of the server's certificate key can't decrypt"
note "this session (forward secrecy)."
SH=$(hs_hex "$HS" ServerHello 'S->C')
echo
decode_hello SH "$SH"
HRR_MAGIC="cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
IS_HRR=0
[ "${SH:12:64}" = "$HRR_MAGIC" ] && IS_HRR=1 # ServerHello.random, bytes 6..37
if [ "$IS_HRR" = 1 ]; then
  note "That was a HelloRetryRequest: the server wanted a different group. The client resent its ClientHello:"
  SH=$(hs_hex "$HS" ServerHello 'S->C' 2)
  echo
  decode_hello SH "$SH"
fi
# cipher_suite sits after: 4-byte header, legacy_version(2), random(32), session_id(1 + len)
SIDLEN=$((16#${SH:76:2}))
SUITE=${SH:$(((39 + SIDLEN) * 2)):4}
case "$SUITE" in 1302)
  TH_MD=sha384
  HLEN=48
  ;;
*)
  TH_MD=sha256
  HLEN=32
  ;;
esac
TH_MD_UP=$(echo "$TH_MD" | tr a-z A-Z)
note "Cipher suite 0x$SUITE fixes the transcript hash and HKDF hash: $TH_MD."
SH_DEC=$(decode_hello SH "$SH")
SUITE_NAME=$(printf '%s\n' "$SH_DEC" | sed -nE 's/^ +cipher_suite +([^ ]+).*/\1/p')
SH_GROUP=$(printf '%s\n' "$SH_DEC" | sed -nE 's/^ +key_share +([^,]+),.*/\1/p')
HRR_LINES=()
if [ "$IS_HRR" = 1 ]; then
  HRR_LINES=("- This run needed a HelloRetryRequest first: none of the client's guessed key shares"
    "  suited the server, so it asked for a $SH_GROUP one and the client started over."
    "  That cost an extra round trip; it is exactly what the guessing tries to avoid.")
fi
recap "The server's reply, also in the clear. It made its choices:" \
  "- cipher suite ${SUITE_NAME:-0x$SUITE}: the encryption for everything that follows," \
  "  and the hash function ($TH_MD) used to fingerprint the handshake (the 'transcript')." \
  "- key share: ${SH_GROUP:-?}. The server sent its own ephemeral public key. Combining" \
  "  it with the client's gives both sides the same shared secret, without that secret" \
  "  ever crossing the network: an eavesdropper who saw both public keys still can't" \
  "  compute it. Because the keys are thrown away afterwards, stealing the server's" \
  "  long-term key later can't decrypt this session ('forward secrecy')." \
  ${HRR_LINES[@]+"${HRR_LINES[@]}"} \
  "From this message on, everything is encrypted."

# =============================================================================
# [6] Key schedule
# =============================================================================
section "Key schedule (RFC 8446 §7.1), from the key log"
note "  early_secret     = HKDF-Extract(0, PSK or zeros)"
note "  handshake_secret = HKDF-Extract(Derive(early_secret), ECDHE shared secret)"
note "     -> {client,server}_handshake_traffic_secret   (bound to hash of ClientHello..ServerHello)"
note "  master_secret    = HKDF-Extract(Derive(handshake_secret), 0)"
note "     -> {client,server}_application_traffic_secret_0, exporter   (..server Finished)"
note "Each secret then yields an AEAD key and IV: HKDF-Expand-Label(secret, \"key\"|\"iv\", \"\", len)."
echo
if [ -s "$W/keylog.txt" ]; then
  for label in CLIENT_HANDSHAKE_TRAFFIC_SECRET SERVER_HANDSHAKE_TRAFFIC_SECRET \
    CLIENT_TRAFFIC_SECRET_0 SERVER_TRAFFIC_SECRET_0 EXPORTER_SECRET; do
    s=$(awk -v l="$label" -v r="$CRANDOM" '$1 == l && tolower($2) == r { print $3; exit }' "$W/keylog.txt")
    [ -n "$s" ] && printf '     %-32s %s\n' "$label" "$(short "$s" 24) ($((${#s} / 2)) bytes)"
  done
  echo
  note "Wireshark can decrypt a pcap of this session with: tls.keylog_file = $W/keylog.txt"
else
  warn "no key log written"
fi
recap "Both sides computed these secrets independently, from the shared secret of the" \
  "previous step; none of them was ever sent. They are visible here only because we" \
  "asked openssl to write them to a file (browsers do the same when SSLKEYLOGFILE is set)." \
  "HKDF, the function in the recipe above, mixes a secret with a label and stretches it" \
  "into new, independent keys. So there is a separate key for each direction and each" \
  "phase: the handshake secrets protect the rest of the handshake, the *_TRAFFIC_SECRET_0" \
  "ones protect the HTTP request and reply. Section 10 uses the handshake secrets to" \
  "check both sides' Finished messages."

# =============================================================================
# [7] EncryptedExtensions
# =============================================================================
section "EncryptedExtensions (server -> client, first encrypted message)"
note "Everything not needed to set up keys moves here, under the server handshake key"
note "(ALPN, for example), so passive observers can't see it."
EE=$(hs_hex "$HS" EncryptedExtensions 'S->C')
echo
EE_DEC=$(decode_hello EE "$EE")
printf '%s\n' "$EE_DEC"
EE_ALPN=$(printf '%s\n' "$EE_DEC" | sed -nE 's/^ +alpn +//p')
if [ -n "$EE_ALPN" ]; then
  ALPN_LINE="The alpn line says both sides agreed to speak $EE_ALPN inside the encrypted tunnel."
else
  ALPN_LINE="This server sent no alpn line, so the client simply assumes HTTP/1.1."
fi
recap "This is the first message an eavesdropper can no longer read: it was encrypted with" \
  "the server's handshake key. It holds the server's answers to the client's remaining" \
  "requests. $ALPN_LINE" \
  "In TLS 1.2 these answers, and the server's certificate coming next, were readable" \
  "by anyone on the network."

# =============================================================================
# [8] Certificate + path validation
# =============================================================================
section "Certificate (server -> client): the chain, then path validation"
note "The server sends its leaf first, then the intermediates. Roots are normally left out:"
note "the client trusts only its own store, so a root sent on the wire proves nothing."
CERTMSG=$(hs_hex "$HS" Certificate 'S->C')
echo
if [ -n "$CERTMSG" ]; then
  decode_certmsg "$CERTMSG" "$W"
  NCERTS=$(cat "$W/cert-count")
  i=0
  while [ "$i" -lt "$NCERTS" ]; do
    hex2bin <"$W/cert-$i.hex" >"$W/cert-$i.der"
    "$OPENSSL" x509 -inform DER -in "$W/cert-$i.der" -out "$W/chain-$i.pem" 2>/dev/null
    i=$((i + 1))
  done
else
  # Fallback: take the PEM blocks printed by -showcerts.
  awk -v D="$W" '/-----BEGIN CERTIFICATE-----/ { f = sprintf("%s/chain-%d.pem", D, n++) } f { print > f } /-----END CERTIFICATE-----/ { close(f); f = "" }' "$W/s_client.txt"
  NCERTS=$(ls "$W"/chain-*.pem 2>/dev/null | wc -l | tr -d ' ')
  note "(no plain Certificate message captured; using the -showcerts copy)"
fi
[ "${NCERTS:-0}" -gt 0 ] || die "no certificates received"
LEAF="$W/chain-0.pem"
if [ -s "$W/cert-0.ocsp.hex" ]; then
  OCSP_LINE="The server also attached ('stapled') a recent revocation status for its certificate."
else
  OCSP_LINE="No revocation status was stapled to it; the Revocation step will go and look."
fi
recap "The server sent $NCERTS certificate(s). A certificate is a public document that says" \
  "'this public key belongs to this name', signed by a CA. The first one, the leaf, is" \
  "$HOST's own; any others are CAs in between. $OCSP_LINE" \
  "Certificates are public, so anyone could send copies of these. The next steps decide" \
  "whether they are genuine (the chain), and section 9 decides whether the server is" \
  "really their owner."

subsection "Path building: leaf -> ... -> a root in the trust store"
note "Each step finds a certificate whose Subject is the current one's Issuer (compared via the"
note "subject_hash of the canonical DN) and whose public key verifies the current one's signature."
# Index the trust store once: subject_hash, SHA-256 fingerprint, file.
mkdir -p "$W/store"
awk -v D="$W/store" '/-----BEGIN CERTIFICATE-----/ { f = sprintf("%s/%04d.pem", D, ++n) } f { print > f } /-----END CERTIFICATE-----/ { close(f); f = "" }' "$CA"
: >"$W/store.idx"
for f in "$W"/store/*.pem; do
  [ -e "$f" ] || continue
  o=$("$OPENSSL" x509 -in "$f" -noout -subject_hash -fingerprint -sha256 2>/dev/null) || continue
  printf '%s\t%s\t%s\n' "${o%%$'\n'*}" "${o##*=}" "$f" >>"$W/store.idx"
done

CHAIN=("$LEAF")
USED=" 0 "
ANCHOR=""
ANCHOR_ON_WIRE=0
cur=$LEAF
for _ in 1 2 3 4 5 6 7 8; do
  # A certificate above the leaf that IS in the trust store ends the path.
  # This covers servers that send their root anyway.
  if [ ${#CHAIN[@]} -gt 1 ] && awk -F'\t' -v fp="$(fp_of "$cur")" '$2 == fp { found = 1 } END { exit !found }' "$W/store.idx"; then
    ANCHOR=$cur
    ANCHOR_ON_WIRE=1
    break
  fi
  ih=$(issuer_hash "$cur")
  parent=""
  j=1
  while [ "$j" -lt "$NCERTS" ]; do
    case "$USED" in *" $j "*)
      j=$((j + 1))
      continue
      ;;
    esac
    if [ "$(subject_hash "$W/chain-$j.pem")" = "$ih" ] && sig_check "$cur" "$W/chain-$j.pem"; then
      parent="$W/chain-$j.pem"
      USED="$USED$j "
      break
    fi
    j=$((j + 1))
  done
  if [ -n "$parent" ]; then
    CHAIN+=("$parent")
    cur=$parent
    continue
  fi
  # Not among the certs the server sent: look in the trust store.
  for s in $(awk -F'\t' -v h="$ih" '$1 == h { print $3 }' "$W/store.idx"); do
    if sig_check "$cur" "$s"; then
      ANCHOR=$s
      CHAIN+=("$s")
      break
    fi
  done
  break
done

if [ -n "$ANCHOR" ]; then
  pass "path found: ${#CHAIN[@]} certificates, leaf to trust anchor"
else
  fail "no path to a trusted root (issuer of '$(cfield "$cur" issuer)' is neither sent by the server nor in the trust store)"
  aia=$(ctext "$cur" | grep -o 'CA Issuers - URI:[^ ]*' | sed 's/.*URI://')
  [ -n "$aia" ] && note "Its AIA caIssuers URL is $aia (browsers may fetch it; most libraries won't)."
fi
EXTRA=$((NCERTS - $(echo "$USED" | wc -w | tr -d ' '))) # sent but not on the path
[ "$EXTRA" -gt 0 ] && note "The server sent $EXTRA certificate(s) not needed for this path (cross-signs or leftovers)."
if [ -n "$ANCHOR" ]; then
  if [ "$ANCHOR_ON_WIRE" = 1 ]; then
    where="The server sent the root as well, but that changes nothing: it counts only because a copy is in your trust store."
  else
    where="The last link, the root, came from your own trust store, not from the server."
  fi
  recap "The script linked $HOST's certificate to a root you trust: each certificate's" \
    "'issuer' names the one above it, and that one's public key must verify its signature." \
    "That gives a path of ${#CHAIN[@]} certificates. $where" \
    "The root at the top is the 'trust anchor': the one certificate believed without proof," \
    "because you (or your OS vendor) put it there. Everything below it is believed only" \
    "because of the signatures. The next steps walk that path one certificate at a time."
else
  recap "The script could not link $HOST's certificate to any root in your trust store." \
    "Often the server forgot to send an intermediate certificate, or the root is private" \
    "(a company's own CA) and not in your store. Without a path, the certificate is just" \
    "a claim anyone could have made. The next steps still examine what was sent."
fi

# Walk the path: describe each certificate and check its constraints and the
# signature linking it to the next one up.
NPATH=${#CHAIN[@]}
d=0
while [ "$d" -lt "$NPATH" ]; do
  c=${CHAIN[$d]}
  T="$W/text.$d"
  ctext "$c" >"$T"
  if [ "$d" -eq 0 ]; then
    role="leaf (end-entity)"
  elif [ "$c" = "$ANCHOR" ]; then
    if [ "$ANCHOR_ON_WIRE" = 1 ]; then role="trust anchor (sent by server, also in trust store)"; else role="trust anchor (from the local trust store)"; fi
  else role="intermediate CA"; fi
  subsection "depth $d: $role"
  kv "subject" "$(cfield "$c" subject)"
  kv "issuer" "$(cfield "$c" issuer)"
  kv "serial" "$(cfield "$c" serial)"
  kv "public key" "$(awk -F': ' '/Public Key Algorithm:/ { a = $2 } /Public-Key:/ { b = $2 } END { print a " " b }' "$T")"
  kv "SHA-256 fingerprint" "$(short "$(fp_of "$c")" 47)"
  ski=$(ext_val "$T" "X509v3 Subject Key Identifier")
  aki=$(ext_val "$T" "X509v3 Authority Key Identifier" | sed 's/^keyid://')
  [ -n "$ski" ] && kv "subject key id" "$ski"
  [ -n "$aki" ] && kv "authority key id" "$aki"

  # Validity window.
  nb=$(cfield "$c" startdate)
  na=$(cfield "$c" enddate)
  kv "valid" "$nb  ->  $na"
  nbs=$(to_epoch "$nb")
  nas=$(to_epoch "$na")
  now=$(date -u +%s)
  if [ -n "$nbs" ] && [ -n "$nas" ]; then
    if [ "$now" -lt "$nbs" ]; then
      fail "depth $d: not valid yet"
    elif [ "$now" -gt "$nas" ]; then
      fail "depth $d: expired"
    else pass "depth $d: within validity period ($(((nas - now) / 86400)) days left)"; fi
  elif "$OPENSSL" x509 -in "$c" -noout -checkend 0 >/dev/null 2>&1; then
    pass "depth $d: not expired"
  else fail "depth $d: expired"; fi

  bc=$(ext_val "$T" "X509v3 Basic Constraints")
  ku=$(ext_val "$T" "X509v3 Key Usage")
  eku=$(ext_val "$T" "X509v3 Extended Key Usage")
  kv "basic constraints" "${bc:-(absent)}$(ext_is_critical "$T" "X509v3 Basic Constraints" && echo ' [critical]')"
  kv "key usage" "${ku:-(absent)}$(ext_is_critical "$T" "X509v3 Key Usage" && echo ' [critical]')"
  kv "extended key usage" "${eku:-(absent)}"

  if [ "$d" -eq 0 ]; then
    # Leaf rules.
    case "$bc" in *CA:TRUE*) warn "leaf is marked CA:TRUE (many clients reject this)" ;; *) pass "leaf is not a CA" ;; esac
    if [ -z "$ku" ]; then
      pass "no keyUsage restriction"
    else case "$ku" in *"Digital Signature"*) pass "keyUsage allows digitalSignature (needed to sign CertificateVerify)" ;;
    *) fail "keyUsage lacks digitalSignature" ;; esac fi
    if [ -z "$eku" ]; then
      warn "no extendedKeyUsage (RFC 5280 allows it; public CAs must include serverAuth)"
    else case "$eku" in *"TLS Web Server Authentication"* | *"Any Extended Key Usage"*) pass "EKU includes serverAuth" ;;
    *) fail "EKU does not include serverAuth" ;; esac fi
    san=$(ext_val "$T" "X509v3 Subject Alternative Name")
    kv "subjectAltName" "$(short "${san:-(absent)}" 200)"
    # Name check: clients match SNI against SAN dNSName/iPAddress entries only.
    # CN is ignored. A wildcard covers exactly one leftmost label.
    if echo "$HOST" | grep -Eq '^[0-9.]+$|:'; then
      out=$("$OPENSSL" x509 -in "$c" -noout -checkip "$HOST" 2>&1)
    else out=$("$OPENSSL" x509 -in "$c" -noout -checkhost "$HOST" 2>&1); fi
    case "$out" in *"does match"*) pass "hostname '$HOST' matches the certificate" ;; *) fail "hostname '$HOST' does NOT match the certificate" ;; esac
  else
    # CA rules.
    case "$bc" in
      *CA:TRUE*) pass "basicConstraints CA:TRUE" ;;
      *) if [ "$c" = "$ANCHOR" ]; then warn "trust anchor has no CA:TRUE (old v1 root; trusted anyway)"; else fail "intermediate lacks CA:TRUE: it may not issue certificates"; fi ;;
    esac
    case "$bc" in *pathlen:*)
      pl=$(echo "$bc" | sed -E 's/.*pathlen:([0-9]+).*/\1/')
      below=$((d - 1))
      if [ "$below" -le "$pl" ]; then
        pass "pathlen:$pl allows the $below CA certificate(s) below it"
      else fail "pathlen:$pl exceeded ($below CA certificates below it)"; fi
      ;;
    esac
    if [ -n "$ku" ]; then case "$ku" in *"Certificate Sign"*) pass "keyUsage includes keyCertSign" ;;
    *) fail "keyUsage lacks keyCertSign" ;; esac fi
    if [ -n "$eku" ] && [ "$c" != "$ANCHOR" ]; then
      case "$eku" in *"TLS Web Server Authentication"* | *"Any Extended Key Usage"*) pass "CA's EKU allows serverAuth below it" ;;
      *) fail "CA's EKU excludes serverAuth (browsers chain EKU restrictions)" ;; esac
    fi
    grep -q "X509v3 Name Constraints" "$T" && kv "name constraints" "$(grep -A3 'X509v3 Name Constraints' "$T" | tail -3 | tr -s ' ' | tr '\n' ' ')"
  fi
  # Any critical extension the client doesn't understand must make the path fail.
  # `openssl verify` below enforces that; here we just list them.
  crit=$(grep -E '^ +[A-Za-z0-9 .:-]+: critical' "$T" | sed -E 's/^ +//; s/: critical//' | tr '\n' ',' | sed 's/,$//; s/,/, /g')
  [ -n "$crit" ] && kv "critical extensions" "$crit"

  # The link to the parent: the actual cryptographic check.
  if [ $((d + 1)) -lt "$NPATH" ]; then
    p=${CHAIN[$((d + 1))]}
    echo
    note "Link depth $d -> depth $((d + 1)): verify this certificate's signature with depth $((d + 1))'s public key"
    if [ "$(issuer_hash "$c")" = "$(subject_hash "$p")" ]; then pass "issuer name == parent's subject name"; else fail "issuer name != parent's subject name"; fi
    ctext "$p" >"$W/ptext"
    pski=$(ext_val "$W/ptext" "X509v3 Subject Key Identifier")
    if [ -n "$aki" ] && [ -n "$pski" ]; then
      if [ "$aki" = "$pski" ]; then pass "authority key id == parent's subject key id"; else fail "AKI/SKI mismatch"; fi
    fi
    if sig_check "$c" "$p" 1; then
      pass "signature verifies with the parent's public key"
    else fail "signature does NOT verify with the parent's public key"; fi
  elif [ "$c" = "$ANCHOR" ]; then
    echo
    if [ "$(issuer_hash "$c")" = "$(subject_hash "$c")" ] && sig_check "$c" "$c"; then
      note "Self-signed, and the self-signature verifies. That proves nothing by itself; this root is"
      note "trusted only because it is in $CA."
    fi
  fi

  if [ "$d" -eq 0 ] && [ "$NPATH" -eq 1 ]; then
    recap "This is the leaf: the certificate for $HOST itself. A client checks its dates," \
      "that it is meant for a TLS server (serverAuth), and that its subjectAltName covers" \
      "$HOST. It should also be signed by a CA one level up, but no such CA could be found," \
      "so that signature, the check that stops anyone from simply editing the name in a" \
      "certificate, could not be made."
  elif [ "$d" -eq 0 ]; then
    recap "This is the leaf: the certificate for $HOST itself. A client checks that it is" \
      "- inside its validity dates (expired certificates are refused outright)," \
      "- meant for a TLS server: extended key usage includes serverAuth," \
      "- issued for the name you typed: the subjectAltName list must cover $HOST" \
      "  (a '*.' wildcard covers exactly one label; the old Common Name field is ignored)," \
      "- signed by the certificate one level up: the last check above. That signature is" \
      "  what stops anyone from simply editing the name in a certificate."
  elif [ "$c" = "$ANCHOR" ]; then
    recap "This is the trust anchor, the root at the top. It is signed by itself, so that" \
      "signature proves nothing; it is believed only because it is in your trust store." \
      "Roots usually live for 20+ years with their private keys locked offline, which is" \
      "why they rarely sign leaf certificates directly."
  else
    recap "This is an intermediate CA: a root's day-to-day deputy. The root signs it once," \
      "then goes back offline, and the intermediate signs the actual website certificates." \
      "What makes it a CA rather than an ordinary certificate:" \
      "- basic constraints CA:TRUE, and key usage with keyCertSign: it may sign certificates;" \
      "- pathlen, if present: how many more CAs may sit below it." \
      "Its own signature is checked against the next certificate up, just like the leaf's."
  fi
  d=$((d + 1))
done

subsection "Revocation"
note "A valid signature only says the CA issued the certificate, not that it hasn't revoked it since."
ISSUER="${CHAIN[1]:-}"
UNTRUSTED="$W/untrusted.pem"
: >"$UNTRUSTED"
i=1
while [ "$i" -lt "$NCERTS" ]; do
  cat "$W/chain-$i.pem" >>"$UNTRUSTED"
  i=$((i + 1))
done
REVOKED=0
CHECKED=0
REV_METHOD=""
# 1) OCSP response stapled into the leaf's Certificate entry (asked for with -status).
if [ -s "$W/cert-0.ocsp.hex" ] && [ -n "$ISSUER" ]; then
  hex2bin <"$W/cert-0.ocsp.hex" >"$W/stapled-ocsp.der"
  out=$("$OPENSSL" ocsp -respin "$W/stapled-ocsp.der" -issuer "$ISSUER" -cert "$LEAF" -CAfile "$CA" -verify_other "$UNTRUSTED" 2>&1)
  kv "stapled OCSP" "$(echo "$out" | grep -E 'chain-0.pem:|verify' | sed "s|$W/||g" | tr '\n' ' ')"
  case "$out" in *": good"*)
    pass "stapled OCSP response says: good"
    CHECKED=1
    REV_METHOD="the status the server stapled to its certificate (signed by the CA, so the server can't forge it)"
    ;;
  *": revoked"*)
    fail "stapled OCSP response says: REVOKED"
    REVOKED=1
    CHECKED=1
    REV_METHOD="the status the server stapled to its certificate"
    ;;
  esac
else
  kv "stapled OCSP" "none sent"
fi
# 2) Live OCSP query, if the certificate names a responder.
OCSP_URL=$("$OPENSSL" x509 -in "$LEAF" -noout -ocsp_uri 2>/dev/null | head -1)
if [ -n "$OCSP_URL" ] && [ -n "$ISSUER" ] && [ "$CHECKED" = 0 ]; then
  out=$(run_timeout "$TIMEOUT" /dev/null "$OPENSSL" ocsp -issuer "$ISSUER" -cert "$LEAF" -url "$OCSP_URL" \
    -CAfile "$CA" -verify_other "$UNTRUSTED" -no_nonce 2>&1)
  kv "OCSP responder" "$OCSP_URL"
  case "$out" in *": good"*)
    pass "OCSP responder says: good"
    CHECKED=1
    REV_METHOD="a live question to the CA's OCSP server (which tells the CA which site you are visiting)"
    ;;
  *": revoked"*)
    fail "OCSP responder says: REVOKED"
    REVOKED=1
    CHECKED=1
    REV_METHOD="a live question to the CA's OCSP server"
    ;;
  *) note "OCSP query failed: $(echo "$out" | head -1)" ;; esac
elif [ -z "$OCSP_URL" ]; then
  kv "OCSP responder" "none listed (some CAs, e.g. Let's Encrypt since 2025, publish CRLs only)"
fi
# 3) CRL from the CRL Distribution Points extension.
CRL_URL=$(ctext "$LEAF" | grep -A4 'CRL Distribution Points' | grep -o 'URI:[^ ,]*' | head -1 | sed 's/^URI://')
if [ -n "$CRL_URL" ] && [ "$CHECKED" = 0 ] && command -v curl >/dev/null 2>&1; then
  kv "CRL" "$CRL_URL"
  if curl -fsS --max-time "$TIMEOUT" --max-filesize 50000000 -o "$W/leaf.crl" "$CRL_URL" 2>/dev/null; then
    "$OPENSSL" crl -inform DER -in "$W/leaf.crl" -out "$W/leaf.crl.pem" 2>/dev/null ||
      "$OPENSSL" crl -in "$W/leaf.crl" -out "$W/leaf.crl.pem" 2>/dev/null
    out=$("$OPENSSL" verify -crl_check -CAfile "$CA" -untrusted "$UNTRUSTED" -CRLfile "$W/leaf.crl.pem" "$LEAF" 2>&1)
    case "$out" in *": OK"*)
      pass "leaf is not on the CA's CRL (CRL signature verified)"
      CHECKED=1
      REV_METHOD="downloading the CA's full revocation list (CRL) and looking for this certificate's serial number"
      ;;
    *revoked*)
      fail "leaf is REVOKED per the CRL"
      REVOKED=1
      CHECKED=1
      REV_METHOD="the CA's revocation list (CRL)"
      ;;
    *) note "CRL check inconclusive: $(echo "$out" | grep -m1 error)" ;; esac
  else note "CRL download failed"; fi
elif [ -n "$CRL_URL" ]; then kv "CRL" "$CRL_URL"; fi
[ "$CHECKED" = 0 ] && warn "revocation status unknown (soft-fail, as most clients do)"
if [ "$REVOKED" = 1 ]; then
  REV_LINES=("This certificate HAS been revoked, according to $REV_METHOD. Its signatures"
    "and dates are all fine, which is exactly why this separate check exists.")
elif [ "$CHECKED" = 1 ]; then
  REV_LINES=("This run got an answer from $REV_METHOD: not revoked.")
else
  REV_LINES=("This run got no answer. Most clients then connect anyway ('soft-fail'), because"
    "refusing whenever a CA's server is slow would break much of the web. An attacker who"
    "can block the check can therefore hide a revocation; that weakness is one reason"
    "certificates are getting shorter lives instead.")
fi
recap "A CA can cancel ('revoke') a certificate before it expires, for example when its" \
  "private key leaks. The chain checks can't notice that: a revoked certificate still has" \
  "a perfectly valid signature. So the client has to ask separately." \
  "${REV_LINES[@]}"

subsection "Certificate Transparency"
note "Chrome and Safari require SCTs (signed promises from public CT logs that the certificate"
note "is logged) on publicly trusted leaves. Here they ride inside the certificate itself."
nsct=$(grep -c 'Signed Certificate Timestamp:' "$W/text.0" 2>/dev/null)
if [ "${nsct:-0}" -gt 0 ]; then
  grep -E '^ +Timestamp *:' "$W/text.0" | sed -E 's/^ +Timestamp *: */logged at /' | while read -r l; do kv "SCT" "$l"; done
  pass "$nsct embedded SCT(s)"
else warn "no embedded SCTs (normal for private CAs; public certs could also deliver them in TLS or OCSP)"; fi
recap "Certificate Transparency (CT) logs are public, append-only lists of every certificate" \
  "the public CAs issue. Each SCT above is a log's signed receipt for this certificate." \
  "CT doesn't stop a CA from issuing a certificate for $HOST to the wrong person; it" \
  "makes that impossible to do secretly, because the domain owner can watch the logs" \
  "for certificates bearing their name. Browsers refuse public certificates that lack SCTs."

subsection "Cross-check: OpenSSL's own path validation"
note "openssl verify runs the full RFC 5280 algorithm, including unknown critical extensions,"
note "name constraints and policies, on the same inputs."
[ -s "$UNTRUSTED" ] && U_OPT="-untrusted $UNTRUSTED" || U_OPT=""
# shellcheck disable=SC2086
out=$("$OPENSSL" verify -CAfile "$CA" $U_OPT -purpose sslserver $N_OPT -show_chain "$LEAF" 2>&1)
echo "$out" | sed "s|$W/||g; s/^/     /"
case "$out" in *"chain-0.pem: OK"*) pass "openssl verify: OK" ;; *) fail "openssl verify rejected the chain" ;; esac
VRC=$(grep -m1 'Verify return code' "$W/s_client.txt" | sed 's/^ *//')
case "$VRC" in *"0 (ok)"*) pass "s_client during the handshake: $VRC" ;; *) fail "s_client during the handshake: $VRC" ;; esac
recap "Two independent opinions on the same chain: OpenSSL's full implementation of the" \
  "standard path-validation algorithm, and the verdict s_client reached live, during the" \
  "handshake. They should agree with the hand checks above. If OpenSSL rejects something" \
  "the hand checks passed, the reason is in its error line: the hand checks are a" \
  "simplified version, written to be readable rather than complete. (Neither of these" \
  "two checks revocation.)"

# =============================================================================
# Transcript helpers for the next steps. The transcript is every handshake
# message so far, concatenated exactly as sent (headers included; record layer
# excluded). After a HelloRetryRequest, ClientHello1 is replaced by a synthetic
# message_hash = 0xfe 00 00 len || Hash(ClientHello1).
# =============================================================================
MSGHASH=""
if [ "$IS_HRR" = 1 ]; then
  ch1h=$(printf '%s' "$CH" | hex2bin | "$OPENSSL" dgst "-$TH_MD" -binary | bin2hex)
  MSGHASH="fe0000$(printf '%02x' "$HLEN")$ch1h"
fi
# transcript_hex STOP_NAME STOP_DIR INCLUDE_STOP(0|1)
transcript_hex() {
  awk -F'\t' -v stop="$1" -v sd="$2" -v inc="$3" -v mh="$MSGHASH" '
    $3 == "NewSessionTicket" || $3 == "KeyUpdate" { next }
    { hex = (NR == 1 && mh != "") ? mh : $4 }
    $3 == stop && $2 == sd { if (inc) printf "%s", hex; exit }
    { printf "%s", hex }' "$HS"
}
th_of() { printf '%s' "$1" | hex2bin | "$OPENSSL" dgst "-$TH_MD" -binary | bin2hex; }

# =============================================================================
# CertificateVerify: proof of possession
# =============================================================================
section "CertificateVerify (server -> client): does the server hold the leaf's private key?"
note "Certificates are public; anyone can replay one. Here the server signs a hash of the whole"
note "handshake so far (including our fresh random and its key share) with the leaf's private key."
note "  signed content = 0x20 x 64 || \"TLS 1.3, server CertificateVerify\" || 0x00 || Hash(ClientHello..Certificate)"
CV=$(hs_hex "$HS" CertificateVerify 'S->C')
if [ -n "$CV" ]; then
  scheme=${CV:8:4}
  siglen=$((16#${CV:12:4}))
  sighex=${CV:16:$((siglen * 2))}
  th=$(th_of "$(transcript_hex CertificateVerify 'S->C' 0)")
  content="$(printf '%064d' 0 | sed 's/0/20/g')$(str2hex 'TLS 1.3, server CertificateVerify')00$th"
  printf '%s' "$content" | hex2bin >"$W/cv-content.bin"
  printf '%s' "$sighex" | hex2bin >"$W/cv-sig.bin"
  "$OPENSSL" x509 -in "$LEAF" -noout -pubkey >"$W/leaf.pub"
  case "$scheme" in
    0403)
      sname=ecdsa_secp256r1_sha256
      vcmd="dgst -sha256"
      ;;
    0503)
      sname=ecdsa_secp384r1_sha384
      vcmd="dgst -sha384"
      ;;
    0603)
      sname=ecdsa_secp521r1_sha512
      vcmd="dgst -sha512"
      ;;
    0804 | 0809)
      sname=rsa_pss_sha256
      vcmd="dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest"
      ;;
    0805 | 080a)
      sname=rsa_pss_sha384
      vcmd="dgst -sha384 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest"
      ;;
    0806 | 080b)
      sname=rsa_pss_sha512
      vcmd="dgst -sha512 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest"
      ;;
    0807)
      sname=ed25519
      vcmd="pkeyutl"
      ;;
    0808)
      sname=ed448
      vcmd="pkeyutl"
      ;;
    0904 | 0905 | 0906)
      sname=mldsa
      vcmd="pkeyutl"
      ;;
    *)
      sname="0x$scheme"
      vcmd=""
      ;;
  esac
  echo
  kv "signature scheme" "$sname (0x$scheme)"
  kv "signature" "$siglen bytes: $(short "$sighex" 40)"
  kv "$TH_MD(transcript)" "$(short "$th" 40)"
  kv "signed content" "$((${#content} / 2)) bytes"
  ok=1
  if [ "$vcmd" = pkeyutl ]; then
    "$OPENSSL" pkeyutl -verify -pubin -inkey "$W/leaf.pub" -rawin -in "$W/cv-content.bin" -sigfile "$W/cv-sig.bin" >/dev/null 2>&1 && ok=0
  elif [ -n "$vcmd" ]; then
    # shellcheck disable=SC2086
    "$OPENSSL" $vcmd -verify "$W/leaf.pub" -signature "$W/cv-sig.bin" "$W/cv-content.bin" >/dev/null 2>&1 && ok=0
  fi
  if [ "$ok" = 0 ]; then
    pass "CertificateVerify signature verifies with the LEAF's public key: the server holds its private key"
  else fail "CertificateVerify did not verify (or scheme 0x$scheme isn't handled here)"; fi
  note "The 64 spaces and the context string keep this signature from being reusable as a"
  note "TLS 1.2 ServerKeyExchange signature or a client CertificateVerify."
  note "This proves the server holds the key in the leaf. Whether that key belongs to $HOST is"
  note "what the chain validation above decided; a client needs both."
else
  fail "no CertificateVerify captured"
fi
recap "Section 8 showed the certificate is genuine. It didn't show that the server you are" \
  "connected to owns it: certificates are public, so anyone can send a copy." \
  "Here the server signed a fingerprint (hash) of this very handshake, which includes" \
  "the client's fresh random value, using the private key that matches the leaf." \
  "Only the key's owner can make that signature, and because it covers this handshake's" \
  "random value it can't be copied from an earlier connection." \
  "Genuine certificate for $HOST + proof of owning its key = you are talking to $HOST."

# =============================================================================
# Finished: transcript integrity + key confirmation
# =============================================================================
section "Finished (both directions): same transcript, same keys"
note "  finished_key = HKDF-Expand-Label(handshake_traffic_secret, \"finished\", \"\", $HLEN)"
note "  verify_data  = HMAC-$TH_MD_UP(finished_key, Hash(transcript up to this message))"
note "A match proves both sides saw byte-identical handshakes (no downgrade, no tampering) and"
note "derived the same secrets."
if [ "$HAVE_KDF" = 1 ] && [ -s "$W/keylog.txt" ]; then
  finished_check() { # WHO(client|server) SECRET_LABEL STOP_NAME STOP_DIR MSG_DIR
    local who=$1 secret fk th exp act info
    secret=$(awk -v l="$2" -v r="$CRANDOM" '$1 == l && tolower($2) == r { print $3; exit }' "$W/keylog.txt")
    [ -n "$secret" ] || {
      skip "$who Finished: secret not in key log"
      return
    }
    # HkdfLabel = uint16 length || <"tls13 " + label> || <context>  (RFC 8446 §7.1)
    info="$(printf '%04x' "$HLEN")0e$(str2hex 'tls13 finished')00"
    fk=$("$OPENSSL" kdf -binary -keylen "$HLEN" -kdfopt "digest:$TH_MD_UP" -kdfopt mode:EXPAND_ONLY \
      -kdfopt "hexkey:$secret" -kdfopt "hexinfo:$info" HKDF 2>/dev/null | bin2hex)
    th=$(th_of "$(transcript_hex "$3" "$4" 1)")
    exp=$(printf '%s' "$th" | hex2bin | "$OPENSSL" dgst "-$TH_MD" -mac HMAC -macopt "hexkey:$fk" -binary | bin2hex)
    act=$(hs_hex "$HS" Finished "$5")
    act=${act:8}
    echo
    kv "$who finished_key" "$(short "$fk" 40)"
    kv "transcript through" "$3 ($4)"
    kv "computed verify_data" "$(short "$exp" 40)"
    kv "received verify_data" "$(short "$act" 40)"
    if [ -n "$exp" ] && [ "$exp" = "$act" ]; then pass "$who Finished MAC matches"; else fail "$who Finished MAC mismatch"; fi
  }
  finished_check server SERVER_HANDSHAKE_TRAFFIC_SECRET CertificateVerify 'S->C' 'S->C'
  finished_check client CLIENT_HANDSHAKE_TRAFFIC_SECRET Finished 'S->C' 'C->S'
  note "The server's Finished covers everything up to CertificateVerify; the client's covers"
  note "everything up to and including the server's Finished."
else
  skip "Finished recomputation needs OpenSSL 3.x ('openssl kdf') and a key log"
fi
recap "Each side ends its part of the handshake with Finished: a keyed fingerprint (MAC) of" \
  "every handshake message it sent and received, made with a key from the secrets of" \
  "section 6. The script recomputed both from the recorded bytes. A match means:" \
  "- both sides saw byte-for-byte the same handshake. If an attacker had altered anything" \
  "  in transit, say deleting the strong options from the ClientHello to force a weak" \
  "  one, the fingerprints would differ and the connection would be dropped;" \
  "- both derived the same keys, so the encrypted channel really works both ways." \
  "Only after checking the server's Finished does the client send its HTTP request."

# =============================================================================
# NewSessionTicket + application data
# =============================================================================
section "After the handshake: application data and NewSessionTicket"
resp=$(grep -m1 -E '^HTTP/[0-9.]+ [0-9]{3}' "$W/s_client.txt" | tr -d '\r')
kv "HTTP response" "${resp:-(none captured)}"
k=1
NT=0
while :; do
  nst=$(hs_hex "$HS" NewSessionTicket 'S->C' "$k")
  [ -n "$nst" ] || break
  life=$((16#${nst:8:8}))
  nl=$((16#${nst:24:2}))
  toff=$((26 + nl * 2))
  tl=$((16#${nst:$toff:4}))
  kv "ticket $k" "lifetime ${life}s ($((life / 3600))h), $tl-byte opaque ticket"
  NT=$((NT + 1))
  k=$((k + 1))
done
if [ "$NT" -gt 0 ]; then
  note "Tickets arrive after the handshake, under the server application key. Each is the server's"
  note "session state encrypted with a key only the server knows (a STEK). The client stores it next"
  note "to a PSK derived from the resumption master secret. RFC 8446 caps lifetimes at 7 days."
else note "No session tickets received."; fi
if [ "$NT" -gt 0 ]; then
  TICKET_LINE="The server also handed over $NT session ticket(s): like a cloakroom ticket, it means nothing to the client, but the server can turn it back into this session's state. The next section uses one."
else
  TICKET_LINE="The server sent no session tickets, so the next section has nothing to resume with."
fi
recap "The handshake is over, and the actual HTTP exchange travelled under the application" \
  "keys: ${resp:-no HTTP response line was captured}." \
  "$TICKET_LINE"

# =============================================================================
# Resumption
# =============================================================================
section "Resumption: reconnect with the ticket (PSK handshake)"
if [ -s "$W/session.pem" ]; then
  # shellcheck disable=SC2086
  run_timeout "$TIMEOUT" "$W/request.txt" "$OPENSSL" s_client -connect "$CONNECT_TO" -servername "$HOST" \
    -tls1_3 -alpn http/1.1 -CAfile "$CA" -ign_eof $EXTRA_OPTS -sess_in "$W/session.pem" \
    -msg -msgfile "$W/msg2.log" >"$W/s_client2.txt" 2>&1
  parse_msglog "$W/msg2.log" "$W/records2.tsv" "$W/handshake2.tsv"
  echo
  print_timeline "$W/records2.tsv"
  CH2=$(hs_hex "$W/handshake2.tsv" ClientHello 'C->S')
  SH2=$(hs_hex "$W/handshake2.tsv" ServerHello 'S->C')
  echo
  note "ClientHello extensions that matter here:"
  decode_hello CH "$CH2" | grep -E 'pre_shared_key|psk_key_exchange_modes|key_share'
  note "ServerHello:"
  decode_hello SH "$SH2" | grep -E 'pre_shared_key|key_share'
  if grep -q 'Reused, TLSv1.3' "$W/s_client2.txt"; then
    if awk -F'\t' '$3 == "Certificate" || $3 == "CertificateVerify" { f = 1 } END { exit f }' "$W/handshake2.tsv"; then
      pass "session resumed: no Certificate, no CertificateVerify, no chain validation"
    else warn "resumed, but certificates were still sent"; fi
    note "Authentication carries over from the original handshake via the PSK. In psk_dhe_ke mode"
    note "a fresh ECDHE still runs, so the resumed session keeps forward secrecy."
    recap "A second, real connection, opened with the ticket from section 11. Compare its table" \
      "with section 3's: no Certificate, no CertificateVerify. The ticket (pre_shared_key in" \
      "the ClientHello) let the server recognise the client as the one it already" \
      "authenticated, so the certificate checks, the most expensive part, were skipped." \
      "New key shares were still exchanged, so this session gets keys of its own."
  else
    warn "server did not accept the ticket (full handshake instead)"
    recap "A second connection offered the ticket from section 11, but the server ignored it" \
      "and did a full handshake. That is allowed and common, for example when a load" \
      "balancer sends the second connection to a different machine that can't read the" \
      "ticket. The client loses nothing but time."
  fi
else
  skip "no session ticket saved"
  recap "Without a ticket from the first connection there is nothing to resume, so this" \
    "step was skipped. Servers aren't required to send tickets."
fi

# =============================================================================
# Timing
# =============================================================================
section "Where the time goes (curl)"
if command -v curl >/dev/null 2>&1; then
  CURL_ARGS=(-sS -o /dev/null --noproxy '*' --tlsv1.3 --cacert "$CA" --max-time "$TIMEOUT"
    -w '%{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer}\n')
  [ "$CONNECT_TO" != "$HOST:$PORT" ] && CURL_ARGS+=(--connect-to "$HOST:$PORT:$CHOST:$CPORT")
  # macOS's own curl (SecureTransport) has no --tlsv1.3 (exit 4): drop the flag.
  curl "${CURL_ARGS[@]}" "https://$HOST:$PORT/" >/dev/null 2>&1
  if [ $? -eq 4 ]; then
    a=()
    for x in "${CURL_ARGS[@]}"; do [ "$x" = --tlsv1.3 ] || a+=("$x"); done
    CURL_ARGS=("${a[@]}")
    note "(this curl can't insist on TLS 1.3, so it uses whatever version it negotiates)"
  fi
  TIMED=0
  for run in 1 2 3; do
    t=$(curl "${CURL_ARGS[@]}" "https://$HOST:$PORT/" 2>/dev/null) || {
      note "curl failed"
      break
    }
    TIMED=$((TIMED + 1))
    echo "$t" | awk -v r="$run" '{ printf "     run %s: DNS %6.1f ms | TCP %6.1f ms | TLS %6.1f ms | to first byte %6.1f ms\n", r, $1*1000, ($2-$1)*1000, ($3-$2)*1000, ($4-$3)*1000 }'
  done
  note "TCP connect is about one RTT. A full TLS 1.3 handshake is about one more RTT plus well"
  note "under a millisecond of crypto: the signature checks above cost tens of microseconds each."
  note "(Each curl run is a fresh process, so it does a full handshake every time.)"
else
  skip "curl not installed"
  TIMED=0
fi
if [ "$TIMED" -gt 0 ]; then
  recap "$TIMED fresh connection(s), timed by curl. Compare the TCP and TLS columns: each is" \
    "about one round trip across the network, so they should be close. TLS 1.3 costs" \
    "roughly one extra round trip, and nearly all of that is waiting for the network:" \
    "the cryptography this walkthrough re-did by hand takes well under a millisecond."
else
  recap "No timings this run. Had they worked, the TCP and TLS columns would each show about" \
    "one network round trip: TLS 1.3 adds roughly one round trip to a connection, and the" \
    "cryptography re-done by hand in this walkthrough takes well under a millisecond."
fi

# =============================================================================
# Summary
# =============================================================================
section "Summary"
np=$(grep -c '^PASS' "$RESULTS")
nf=$(grep -c '^FAIL' "$RESULTS")
nw=$(grep -c '^WARN' "$RESULTS")
ns=$(grep -c '^SKIP' "$RESULTS")
kv "checks" "$np passed, $nf failed, $nw warnings, $ns skipped"
grep -E '^(FAIL|WARN)' "$RESULTS" | while IFS='|' read -r k m; do kv "$k" "$m"; done
echo
note "Artifacts in $W:"
note "  chain-N.pem (as sent), store/ (trust store, split), msg.log (raw handshake),"
note "  keylog.txt (session secrets: delete when done), s_client.txt, *.tsv (parsed)"
if [ "$nf" -eq 0 ]; then
  VERDICT="Every check passed: a careful client would trust this connection to $HOST."
else
  VERDICT="$nf check(s) failed: a careful client would have refused this connection to $HOST."
fi
recap_text "$VERDICT" \
  "To see what failures look like, try a test site that is broken on purpose:" \
  "- $0 expired-isrgrootx1.letsencrypt.org" \
  "- $0 revoked-isrgrootx1.letsencrypt.org" \
  "More are listed in the comment at the top of this script."
[ "$nf" -eq 0 ] && exit 0 || exit 1
