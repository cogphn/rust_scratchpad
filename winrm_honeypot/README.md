# winrm-honeypot

A fake Windows Server WinRM endpoint that answers authentication attempts the way a
real one does, and records everything that is tried against it.

> **Deploy only on hosts and networks you own or are explicitly authorised to monitor.**
> The credentials in the config are bait: invent them for this purpose and never reuse them
> anywhere real. The log file will contain passwords chosen by attackers — treat it as
> sensitive data and keep it off shared storage.

## What it does

- Listens on one HTTP port (5985 by default) and serves `POST /wsman` — the only path WinRM uses.
- Answers an unauthenticated request with `401` plus `WWW-Authenticate: Negotiate` and
  `Basic realm="WSMAN"`, advertising both schemes the way a host with Basic enabled does.
- Speaks enough of the NTLM handshake to satisfy scanners and tooling: `Type 1` gets an
  `NTLMSSP_CHALLENGE` carrying a believable NetBIOS/DNS name, domain, OS version and timestamp,
  and a `Type 3` is parsed and verified as NTLMv2 against the configured passwords.
- Accepts HTTP Basic for `user`, `DOMAIN\user` and `user@domain` forms.
- Answers `wsmid:Identify` with Microsoft product strings (`Test-WSMan` works), and returns a
  WS-Management fault for every other request after authentication.
- Records every request, every credential attempt and every command that was *asked* for.
- Refuses a `POST` with neither `Content-Length` nor chunking with `411`, like IIS.

## What it does not do

- No command execution, no shell, no file transfer. Nothing a client asks for is ever run.
- No Kerberos, no SPNEGO-with-Kerberos (those tokens are logged as `result=non_ntlm_token`).
- No NTLMv1 and no pass-the-hash: only NTLMv2 responses can be verified against a password.
- No TLS on 5986 yet. Scanners probe 5985 first; TLS is a later addition with a self-signed cert.

## Quick start

```bash
cp config.example.toml config.toml     # edit identity + credentials
cargo run --release -- --config config.toml
```

Validate a config without binding or touching the log:

```bash
cargo run --release -- --config config.toml --check-config
# config OK: 2 credentials, listen 0.0.0.0:5985
```

Overrides (handy for a throwaway instance):

```bash
winrm_honeypot --config config.toml --listen 127.0.0.1:5985 --log-file -
```

`--log-file -` writes events to stdout, which is what a container should do.
`RUST_LOG=debug` raises the (tracing) operator log; the honeypot's own event log is separate.

**Do not run this on a host where real WinRM is enabled** — the bind fails with an explicit
message because `5985` is already held by `http.sys`.

## Configuration

```toml
[server]
listen = "0.0.0.0:5985"          # IP:port to bind
schemes = ["negotiate", "basic"] # order of WWW-Authenticate headers

[identity]
computer_name = "WIN-SRV01"      # NetBIOS name scanners fingerprint
domain = "CORP"                  # NetBIOS domain inside the NTLM challenge
dns_domain = "corp.local"        # DNS name in the challenge's TargetInfo
os_version = "10.0.20348"        # Server 2022; major.minor.build

[log]
path = "logs/winrm-events.log"   # "-" = stdout

[[credentials]]
domain = "CORP"                  # optional; defaults to identity.domain
username = "Administrator"
password = "Summer2026!"
```

Unknown keys are rejected at load time, so a typo cannot silently leave the honeypot
accepting nobody.

## Log format

One event per line, `key=value`, values quoted and escaped when they contain spaces or
control characters (a newline in a username cannot forge a line).

```text
2026-10-26T08:46:23.031Z event=request ip=127.0.0.1:25179 method=POST path=/wsman len=234 ua=curl/8.18.0 auth="Basic Q09SUFxBZG1pbmlzdHJhdG9yOlN1bW1lcjIwMjYh"
2026-10-26T08:46:23.031Z event=command ip=127.0.0.1:25179 cmd="whoami /priv" auth="Basic Q09SUFx…" len=234
2026-10-26T08:46:23.031Z event=auth scheme=basic ip=127.0.0.1:25179 domain=CORP user=Administrator password=Summer2026! result=ok
2026-10-26T08:46:39.767Z event=auth scheme=ntlm_type3 ip=127.0.0.1:24988 domain=CORP user=Administrator workstation=LABHOST8 flags=0xa2888205 result=ok ntlmv2=Administrator::CORP:25565215c0c99bd8:2b486b8a0e607baa97089aa65e8d1fc2:010100…
```

Event kinds:

| `event=` | when |
| --- | --- |
| `startup` | bind succeeded (identity, listen address, credential count) |
| `request` | every HTTP request, including probes that never reach a handler |
| `command` | a `CommandLine`/`Command` was found in the body — logged **before** auth decides |
| `auth` | one line per attempt: `scheme=basic`, `ntlm_type1`, `ntlm_type3`, or `negotiate` |

`result=` is one of `ok`, `denied`, `unknown_user`, `malformed`, `no_challenge`,
`challenge_sent`, `non_ntlm_token`, `unsupported_message_type`, `bad_base64`.

`ntlmv2=` is a hashcat mode 5600 line: `USER::DOMAIN:server_challenge:NTProofStr:blob`.
Crack it offline with the operator's own wordlist — nothing is brute-forced here.

## Verifying it behaves

```bash
# challenge
curl -i -s -X POST -H 'Content-Length: 0' http://127.0.0.1:5985/wsman        # 401, two WWW-Authenticate headers
# basic
curl -i -s -u 'CORP\Administrator:Summer2026!' --basic -d '' http://127.0.0.1:5985/wsman   # 400, not 401
curl -i -s -u 'CORP\Administrator:wrong'        --basic -d '' http://127.0.0.1:5985/wsman   # 401
# ntlmv2
curl -i -s --ntlm -u 'CORP\Administrator:Summer2026!' -d '' http://127.0.0.1:5985/wsman     # 400, not 401
curl -i -s --ntlm -u 'CORP\Administrator:wrong'        -d '' http://127.0.0.1:5985/wsman     # 401
# identify
curl -s --basic -u 'CORP\Administrator:Summer2026!' \
  -H 'Content-Type: application/soap+xml;charset=UTF-8' \
  --data '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Body><wsmid:Identify/></s:Body></s:Envelope>' \
  http://127.0.0.1:5985/wsman
```

`cargo test` runs the same checks as integration tests against an ephemeral port.

## Operational notes

- **Log growth**: no rotation yet. A busy scanner can write thousands of `event=request` lines
  per minute; run it somewhere with rotation or a size-capped volume.
- **File permissions**: on Unix the log is created `0600`.
- **One credential set per deployment**: keep it out of version control (`config.toml` is
  git-ignored; only `config.example.toml` is committed).
- **Fidelity gaps**: header *names* are lower-cased by the HTTP layer (values are exact),
  there is no Kerberos, no HTTP/2 and no fake shell — `nxc`/`evil-winrm` will authenticate and
  then fail at the shell stage. That is deliberate: nothing executes here.

## Layout

```text
src/main.rs     CLI: --config, --listen, --log-file, --check-config
src/config.rs   TOML config, validation, credential lookup
src/logging.rs  injection-safe single-line event log (file or stdout)
src/ntlm.rs     NTLM Type 2 builder, Type 3 parser, NTLMv2 verification, hashcat lines
src/soap.rs     Identify response, faults, command extraction (no XML parser → no XXE)
src/server.rs   axum router, request logging, auth orchestration
tests/          HTTP-level, NTLM handshake and CLI tests
```
