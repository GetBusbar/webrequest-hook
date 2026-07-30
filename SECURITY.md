# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues, pull
requests, or discussions.**

Instead, report privately through either channel:

- Email **security@getbusbar.com**, or
- GitHub's [private vulnerability reporting](https://github.com/GetBusbar/webrequest-hook/security/advisories/new)
  (the **Security** tab on this repository).

Please include:

- A description of the issue and its potential impact.
- Steps to reproduce (proof-of-concept if available).
- Affected version / commit.
- Any suggested mitigation.

We aim to **acknowledge your report within 48 hours**, work with you on a fix, and
coordinate disclosure timing. Confirmed vulnerabilities are published as
[GitHub Security Advisories](https://github.com/GetBusbar/webrequest-hook/security/advisories),
through which we request and issue **CVE** identifiers. We credit reporters who wish to be
credited once a fix is released.

## Scope

`webrequest-hook` is a `kind: hook` busbar plugin: it POSTs each hook op envelope
(`decide`/`transform`/`notify`/`configure`/`describe`/`status`) — which may carry
operator-granted prompt/user content — to an operator-configured URL on the
request hot path, and is the only first-party plugin in this set that makes
outbound network calls. Issues of particular interest include:

- **SSRF**: any way to make the forwarder reach an internal/metadata target
  (`169.254.169.254`, RFC1918, RFC6598 CGNAT, link-local, IPv6 ULA, cloud-metadata
  DNS names, or an alternate IPv4 encoding of any of those) despite the
  `src/net_guard.rs` guard — including at initial `open`, at a `configure` push,
  via redirect, or via an obfuscated/malformed URL the guard's parser and the
  actual outbound HTTP client disagree on.
- **Credential leakage**: any path where `user:pass@` userinfo embedded in
  `settings.url` reaches a returned error string, a log, or the wire to the
  target itself.
- **Untrusted-response handling**: the remote target's response (status,
  headers, body) is untrusted input. Issues where a hostile/buggy target can
  cause unbounded allocation, a stack overflow via deep nesting, a hang past
  the configured timeout, or a crash are in scope.
- **Grant bypass**: any way for the forwarder to relay `prompt`/`user` content
  it was not granted by the operator + the signed manifest's declared `needs`.
- A load-time config error (e.g. a malformed `settings.url`) surfacing as a
  silent success instead of a clean, fail-closed `Err` across the plugin ABI.

See busbar's own [threat model](https://github.com/GetBusbar/busbar/blob/main/THREAT_MODEL.md)
for the trust boundaries this plugin operates inside, and the security-stance
doc comments at the top of [`src/lib.rs`](src/lib.rs) and
[`src/net_guard.rs`](src/net_guard.rs) for the design rationale.

## Supported versions

This plugin is versioned independently of busbar (see the README). Security
fixes are applied to the latest `main` and the most recent tagged release of
**this repository**. Pin to a tag for production use.
