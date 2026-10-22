# TLS 1.3 Walkthrough

Take one real TLS 1.3 handshake apart, message by message, and re-do the
client's security checks by hand.

Every time you open an HTTPS site, your browser silently negotiates keys,
validates a certificate chain, and checks that the server owns its
certificate. This script makes one real connection, records every byte, and
then walks you through all of it in your terminal, pausing after each step to
explain what you just saw.

It is meant for developers who use HTTPS every day but have never looked
inside a handshake.

## Quick start

```sh
./tls13-walkthrough.sh                 # default target: cpacket.com:443
./tls13-walkthrough.sh example.org     # any TLS 1.3 server
./tls13-walkthrough.sh example.org 8443
```

On macOS, point it at Homebrew's OpenSSL (the system one is LibreSSL, which
won't work):

```sh
OPENSSL=$(brew --prefix openssl@3)/bin/openssl ./tls13-walkthrough.sh
```

## Requirements

- bash 3.2+ (the macOS default is fine), POSIX awk, `od`
- OpenSSL 1.1.1+; **3.x recommended**. With 1.1.1 the Finished-message check
  is skipped, because it needs `openssl kdf`.
- `curl`, optional: used for the revocation-list download and the timing section

## What you'll see

The walkthrough has 14 sections:

| #  | Section             | What it shows                                                                 |
|----|---------------------|-------------------------------------------------------------------------------|
| 1  | Prerequisites       | the openssl in use and your trust store                                       |
| 2  | DNS                 | name → address, which is not protected by TLS                                 |
| 3  | Handshake           | one recorded TLS 1.3 connection, as a record-by-record timeline               |
| 4  | ClientHello         | the client's offer, decoded byte by byte                                      |
| 5  | ServerHello         | the server's choices and key share                                            |
| 6  | Key schedule        | the secrets both sides derived, read from a key log                           |
| 7  | EncryptedExtensions | the first encrypted message                                                   |
| 8  | Certificate         | the chain, validated by hand: path, signatures, dates, names, revocation, CT  |
| 9  | CertificateVerify   | proof that the server holds the certificate's private key                     |
| 10 | Finished            | proof that both sides saw the same handshake and derived the same keys        |
| 11 | After the handshake | the HTTP response and session tickets                                         |
| 12 | Resumption          | a second connection using a ticket, with no certificates                      |
| 13 | Timing              | DNS / TCP / TLS times measured with curl                                      |
| 14 | Summary             | every check's result                                                          |

Each check prints `PASS`, `FAIL`, `WARN` (most clients accept it, with
caveats) or `SKIP` (the check couldn't run). Unlike a real client, the
walkthrough keeps going after a `FAIL`, so you can see every check.

## Pausing

Run in a terminal, the script stops after every step and shows a
**What just happened** recap, then waits for a single key:

| Key     | Action                                        |
|---------|-----------------------------------------------|
| `Enter` | next step                                     |
| `s`     | skip the remaining pauses in this section     |
| `c`     | run to the end without stopping               |
| `q`     | quit (exit status 130)                        |

When the output is piped or redirected, it never pauses, but the recaps are
still printed. So this gives you a complete annotated transcript:

```sh
./tls13-walkthrough.sh > run.txt
```

## Options

All options are environment variables:

| Variable          | Meaning                                                                  |
|-------------------|--------------------------------------------------------------------------|
| `OPENSSL`         | path to the openssl binary                                               |
| `CAFILE`          | trust store to validate against (default: the system CA bundle)          |
| `CONNECT_TO`      | `ip:port` to connect to, when it differs from host:port (the SNI and name checks still use the host) |
| `HTTP_METHOD`     | request sent after the handshake (default `HEAD`)                        |
| `TIMEOUT`         | seconds per network operation (default 15)                               |
| `PAUSE=0`         | never pause                                                              |
| `NO_COLOR`        | disable colour                                                           |

## Seeing failures

A healthy site passes every check. To see what failures look like, try these
public test sites, which speak TLS 1.3 and are broken on purpose:

```sh
./tls13-walkthrough.sh expired-isrgrootx1.letsencrypt.org   # expired leaf
./tls13-walkthrough.sh revoked-isrgrootx1.letsencrypt.org   # revoked leaf
./tls13-walkthrough.sh expired-rsa-dv.ssl.com               # expired leaf, another CA
./tls13-walkthrough.sh revoked-rsa-dv.ssl.com               # revoked leaf, another CA
```

## Exit status

| Code | Meaning                                  |
|------|------------------------------------------|
| 0    | every check passed                       |
| 1    | at least one check failed                |
| 2    | could not run (missing tools, no TLS 1.3 handshake) |
| 130  | quit at a pause (`q`) or interrupted (Ctrl-C) |

## A note on the files it leaves behind

Everything captured goes into a temporary directory, which is printed at the
start and the end: the certificates, the raw handshake bytes, the parsed
messages. It includes `keylog.txt`, which holds that session's secrets and can
decrypt a packet capture of it (for example in Wireshark). Delete the directory
when you're done.

## Vocabulary

[GLOSSARY.md](GLOSSARY.md) defines the terms used in the code and the
explanations: walkthrough, section, step, check, intro, recap.

## License

[MIT](LICENSE)
