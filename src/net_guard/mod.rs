// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SSRF guard the `webrequest` forwarder applies to its operator-configured target URL.
//!
//! This plugin makes an OUTBOUND HTTP call to a URL the operator put in `settings.url`, so — exactly
//! like the retired `webhook` hook transport it replaces — it must refuse a URL that points at an
//! internal target (cloud-metadata, RFC1918 private, RFC6598 CGNAT, link-local, IPv6 ULA, or the
//! alternate IPv4 encodings a resolver still expands to those). A signed, trusted forwarder that
//! could be pointed at `169.254.169.254` would be an SSRF pivot; the guard closes that.
//!
//! ## Policy parity with the old `webhook` hook (deliberate)
//!
//! The retired `WebhookPolicy` validated its sidecar URL with `observability::validate_routing_webhook_url`,
//! which reused the OTLP carve-out: link-local / IMDS / RFC1918 / CGNAT / cloud-metadata are BLOCKED,
//! but loopback / `localhost` are ALLOWED (a hook sidecar is typically co-located on loopback), and
//! plaintext `http://` is permitted ONLY for a loopback host. This module keeps that policy bit-for-bit
//! so a hook currently on `route: webhook` can migrate by pointing this plugin at the same URL.
//!
//! ## Why the predicates are COPIED, not shared
//!
//! The pure context-free predicates below (`is_cgnat_shared_v4`, `is_unique_local_v6`,
//! `is_link_local_v6`, `is_alternate_ipv4_encoding`) are lifted verbatim from
//! `busbar/src/net_guard.rs`. A plugin cdylib must NOT depend on the `busbar` core crate (it would pull
//! the whole engine into a leaf `cdylib` and invert the plugin/core boundary), so the identical
//! security atoms are copied here; the SSRF guard belongs in the plugin that opens the socket.
//! If these are ever hoisted into a tiny no-dep shared leaf crate, this copy should reference
//! it; until then the copies must be kept byte-identical — a contributor hardening one against a new
//! obfuscation form must harden both. The tests below pin THIS COPY's behaviour against fixed test
//! vectors (obfuscated-encoding forms, RFC1918/CGNAT/ULA/link-local/metadata hosts, the loopback
//! carve-out); they do NOT diff against the core copy in `busbar/src/net_guard.rs`, so drift between
//! the two copies would not by itself turn any test here red — keeping the two byte-identical is a
//! manual review discipline at PR time, not something this test module enforces automatically.
//!
//! Note also: these predicates validate the URL's literal host (or its already-resolved IP) at
//! open/configure time; they do not re-check DNS resolution at connect time, so a host that resolves
//! to an allowed IP at validation and to a blocked internal IP later (DNS rebinding / TOCTOU) is not
//! defended against here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

// ── Pure context-free predicates (copied verbatim from busbar/src/net_guard.rs) ────────────────────

/// IPv6 unique-local range `fc00::/7` (the first 7 bits are `1111110`).
pub(crate) fn is_unique_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

/// IPv6 link-local range `fe80::/10` (the first 10 bits are `1111111010`).
pub(crate) fn is_link_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

/// IPv6 site-local `fec0::/10`. Deprecated by RFC 3879 but still routed on plenty of real networks,
/// and NOT covered by the ULA or link-local masks (`0xfec0 & 0xfe00` is `0xfe00`, not `0xfc00`;
/// `0xfec0 & 0xffc0` is `0xfec0`, not `0xfe80`), so without this it was simply allowed.
pub(crate) fn is_site_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfec0
}

/// The IPv4 address embedded in an IPv6 TRANSLATION or TUNNELLING address, if there is one.
///
/// `Ipv6Addr::to_ipv4` only unwraps the `::a.b.c.d` and `::ffff:a.b.c.d` forms, which leaves two
/// widely-deployed embeddings that carry the same internal IPv4 targets straight past the guard:
///
/// - **NAT64, `64:ff9b::/96`** (RFC 6052). Standard on IPv6-only clusters with a NAT64 gateway, so
///   `[64:ff9b::a9fe:a9fe]` is a live route to `169.254.169.254`.
/// - **6to4, `2002::/16`** (RFC 3056), which carries the IPv4 address in the next 32 bits, so
///   `[2002:a00:1::]` is `10.0.0.1`.
///
/// Returning the embedded address lets the caller run it through the same `is_internal_v4` policy
/// as any other IPv4 target, rather than maintaining a second, divergent list.
pub(crate) fn embedded_v4(addr: &Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = addr.to_ipv4() {
        return Some(v4);
    }
    let s = addr.segments();
    // NAT64 with the last 32 bits carrying the IPv4 address. Two prefixes, not one:
    //   - the RFC 6052 WELL-KNOWN prefix `64:ff9b::/96`;
    //   - the RFC 8215 LOCAL-USE prefix `64:ff9b:1::/48`, which exists precisely because the
    //     well-known prefix may not be used with non-global IPv4 addresses. That is exactly the
    //     RFC1918 case this guard cares about, so a deployment translating to internal space is
    //     using the local-use prefix, not the well-known one. Matching only the well-known prefix
    //     would have missed the deployments most likely to reach somewhere internal.
    // Both are matched at /96 (the last two segments hold the address); for the /48 local-use
    // prefix that means segments 3..5 must be zero for the address to sit at the /96 offset.
    let nat64_wkp =
        s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0;
    let nat64_local =
        s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 1 && s[3] == 0 && s[4] == 0 && s[5] == 0;
    if nat64_wkp || nat64_local {
        return Some(Ipv4Addr::new(
            (s[6] >> 8) as u8,
            (s[6] & 0xff) as u8,
            (s[7] >> 8) as u8,
            (s[7] & 0xff) as u8,
        ));
    }
    // 6to4: 2002:AABB:CCDD::/48 encodes A.B.C.D.
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(
            (s[1] >> 8) as u8,
            (s[1] & 0xff) as u8,
            (s[2] >> 8) as u8,
            (s[2] & 0xff) as u8,
        ));
    }
    None
}

/// RFC 6598 Shared Address Space `100.64.0.0/10` (CGNAT) — routable inside AWS/GCP VPCs and k8s
/// clusters, so an SSRF target the private/link-local checks miss. `Ipv4Addr::is_private()` misses it.
pub(crate) fn is_cgnat_shared_v4(v4: &Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// True when `host` is an alternate (non-dotted-quad) IPv4 encoding that `IpAddr::from_str` rejects
/// but the OS resolver still maps to an IPv4 address (bare decimal `2130706433`, `0x`/`0X` hex, a
/// leading-zero octal, or a dotted form with fewer than four octets). A canonical dotted-quad is NOT
/// matched here (handled by the `parse::<IpAddr>()` path); a normal DNS hostname is not matched either.
pub(crate) fn is_alternate_ipv4_encoding(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    if !host.contains('.') {
        if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
        }
    }
    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        let all_numeric = parts.iter().all(|p| {
            if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
                !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
            } else {
                !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
            }
        });
        if !all_numeric {
            return false;
        }
        if parts.len() < 4 {
            return true;
        }
        return parts.iter().any(|p| {
            p.starts_with("0x")
                || p.starts_with("0X")
                || (p.len() > 1 && p.starts_with('0') && p.bytes().all(|b| b.is_ascii_digit()))
        });
    }
    host.bytes().all(|b| b.is_ascii_digit())
}

/// True iff `host` is an alternate (non-dotted-quad) IPv4 encoding that unambiguously denotes the
/// loopback address `127.0.0.1` (decimal `2130706433`, hex `0x7f000001`, octal `017700000001`, or a
/// short-dotted `127.1` / `127.0.1`). Used to permit the loopback-sidecar exception while still
/// blocking every OTHER alternate-encoded internal target. Conservative: anything it cannot positively
/// confirm as loopback is treated as non-loopback (and therefore blocked). Mirrors
/// `observability::is_alternate_loopback_v4`.
pub(crate) fn is_alternate_loopback_v4(host: &str) -> bool {
    if !host.contains('.') {
        if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            return u32::from_str_radix(hex, 16).ok() == Some(0x7f00_0001);
        }
        if let Some(oct) = host.strip_prefix('0').filter(|_| host.len() > 1) {
            if let Ok(v) = u32::from_str_radix(oct, 8) {
                return v == 0x7f00_0001;
            }
        }
        if let Ok(v) = host.parse::<u32>() {
            return v == 0x7f00_0001;
        }
        return false;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 4 || parts.is_empty() {
        return false;
    }
    let Some(first) = parts.first().and_then(|p| p.parse::<u32>().ok()) else {
        return false;
    };
    first == 127 && parts.iter().all(|p| p.parse::<u32>().is_ok())
}

// ── Context-specific block/loopback wrappers (parity with the old webhook/OTLP guard) ──────────────

/// The cloud-metadata DNS names blocked case-insensitively. Mirrors `observability::METADATA_HOSTS`.
const METADATA_HOSTS: &[&str] = &["metadata.google.internal", "metadata.internal"];

/// True for an IPv4 literal the forwarder must not POST to (EXCEPT loopback, which the caller carves
/// out): link-local (incl. `169.254.169.254` IMDS), RFC1918 private, RFC6598 CGNAT, unspecified,
/// broadcast, and the Azure WireServer / OCI IMDS public-but-metadata literals. Mirrors
/// `observability::is_internal_v4` (loopback is checked by the caller so the localhost carve-out is
/// visible at the call site).
fn is_internal_v4(v4: &Ipv4Addr) -> bool {
    const AZURE_WIRESERVER: Ipv4Addr = Ipv4Addr::new(168, 63, 129, 16);
    const OCI_IMDS: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 192);
    v4.is_loopback()
        || v4.is_link_local()
        || v4.is_private()
        || is_cgnat_shared_v4(v4)
        || v4.is_unspecified()
        || v4.is_broadcast()
        || *v4 == AZURE_WIRESERVER
        || *v4 == OCI_IMDS
}

/// True iff the target URL's host is the loopback/localhost target the forwarder MAY reach — the exact
/// carve-out `host_is_blocked` leaves un-blocked (parity with the old webhook policy, which allowed a
/// loopback sidecar). Used to gate the plaintext-`http://` allowance to loopback only.
pub(crate) fn host_is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = host_of(url) else {
        return false;
    };
    if is_alternate_ipv4_encoding(&host) {
        return is_alternate_loopback_v4(&host);
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => v6.is_loopback() || v6.to_ipv4().is_some_and(|v4| v4.is_loopback()),
        Err(_) => {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .rsplit_once('.')
                    .is_some_and(|(_, tld)| tld.eq_ignore_ascii_case("localhost"))
        }
    }
}

/// SSRF block predicate for the target URL: identical to a full internal check EXCEPT loopback and the
/// `localhost` DNS name are NOT blocked (the loopback-sidecar carve-out the old webhook policy kept).
/// Every other internal/metadata target is blocked: cloud-metadata names + IMDS literal, RFC1918
/// private, RFC6598 CGNAT, link-local, IPv6 ULA/link-local/site-local/unspecified, the IPv4
/// addresses embedded in IPv4-mapped, IPv4-compatible, NAT64 and 6to4 IPv6 forms, and the
/// alternate-IPv4 encodings that resolve to those.
///
/// This inspects the URL's literal host TEXT only and never resolves a name — that is
/// [`resolve_and_check`]'s job, and the two are used together by [`checked_addrs_for`]. Keeping the
/// textual check separate matters: it is total (no I/O, no failure mode), so it can run first and
/// reject the IP-literal spellings before anything touches the network.
pub(crate) fn host_is_blocked(url: &reqwest::Url) -> bool {
    let Some(host) = host_of(url) else {
        return true; // a URL with no host is unusable as a target
    };
    if METADATA_HOSTS.iter().any(|m| host.eq_ignore_ascii_case(m)) {
        return true;
    }
    if is_alternate_ipv4_encoding(&host) {
        return !is_alternate_loopback_v4(&host);
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => !v4.is_loopback() && is_internal_v4(&v4),
        Ok(IpAddr::V6(v6)) => {
            if v6.is_loopback() {
                return false; // `::1` loopback sidecar — allowed
            }
            if let Some(v4) = embedded_v4(&v6) {
                return !v4.is_loopback() && is_internal_v4(&v4);
            }
            v6.is_unspecified()
                || is_unique_local_v6(&v6)
                || is_link_local_v6(&v6)
                || is_site_local_v6(&v6)
        }
        // DNS name: metadata names blocked above; `localhost` and any external host allowed.
        Err(_) => false,
    }
}

/// Resolve `host:port` and reject the result if ANY address is internal.
///
/// This is the half [`host_is_blocked`] cannot do. That one reads the URL's literal host text, so it
/// stops `https://169.254.169.254/` and every alternate spelling of it — the misconfiguration and
/// copy-paste case — but a NAME pointed at an internal address sails straight through, because a
/// name is not an address until something resolves it.
///
/// ANY, not all: a name that resolves to one external and one internal address is rejected outright.
/// Connecting would be a coin flip between them, and "sometimes reaches the metadata service" is not
/// a weaker problem than "always does".
///
/// A resolution FAILURE is deliberately NOT an error here (`Ok(None)`). A target whose DNS is
/// briefly down is an availability event, not a security one — it cannot reach anything, internal or
/// otherwise, and failing the plugin's load over it would take the whole gateway down for a
/// transient blip. The caller treats `None` as "allowed, but nothing to pin".
fn resolve_and_check(host: &str, port: u16) -> Result<Option<Vec<SocketAddr>>, String> {
    let Ok(addrs) = (host, port).to_socket_addrs() else {
        return Ok(None);
    };
    let addrs: Vec<SocketAddr> = addrs.collect();
    if addrs.is_empty() {
        return Ok(None);
    }
    for addr in &addrs {
        if ip_is_internal(&addr.ip()) {
            return Err(format!(
                "resolves to the internal address {} (SSRF guard; loopback sidecars are allowed)",
                addr.ip()
            ));
        }
    }
    Ok(Some(addrs))
}

/// The internal-address predicate, over an already-resolved [`IpAddr`]. Shares its rules with
/// [`host_is_blocked`]'s literal-text path so a name and a literal cannot disagree about the same
/// address — the loopback carve-out for sidecars included.
fn ip_is_internal(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_loopback() && is_internal_v4(v4),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return false;
            }
            if let Some(v4) = embedded_v4(v6) {
                return !v4.is_loopback() && is_internal_v4(&v4);
            }
            v6.is_unspecified()
                || is_unique_local_v6(v6)
                || is_link_local_v6(v6)
                || is_site_local_v6(v6)
        }
    }
}

/// The addresses a validated `url` may be connected to, for pinning — `None` when the host is an IP
/// literal (already checked, nothing to pin) or did not resolve.
///
/// Pinning is what makes the resolve check MEAN anything. Without it the guard resolves a name,
/// approves the addresses, and then hands the bare hostname to the HTTP client, which resolves it
/// AGAIN at connect time and may get a different answer — the DNS-rebinding shape, where the second
/// answer is the metadata service. Feeding these exact addresses to the client closes that: the
/// approved addresses are the only ones it will ever dial.
pub(crate) fn checked_addrs_for(url: &reqwest::Url) -> Result<Option<Vec<SocketAddr>>, String> {
    let Some(host) = host_of(url) else {
        return Ok(None);
    };
    if host.parse::<IpAddr>().is_ok() || is_alternate_ipv4_encoding(&host) {
        return Ok(None); // an IP literal: `host_is_blocked` already ruled on it
    }
    let port = url.port_or_known_default().unwrap_or(443);
    resolve_and_check(&host, port)
        .map_err(|why| format!("webrequest: settings.url host '{host}' {why}"))
}

/// The URL's host with the IPv6 `[...]` brackets and a single trailing FQDN-root `.` stripped, so the
/// predicates see the same canonical form the OTLP/webhook guard did. Returns `None` for a hostless URL.
fn host_of(url: &reqwest::Url) -> Option<String> {
    let host = url.host_str()?;
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    let host = host.strip_suffix('.').unwrap_or(host);
    Some(host.to_string())
}

/// Case-insensitive equality of a URL's scheme to `want` (an ASCII-lowercase literal).
fn scheme_is(url: &reqwest::Url, want: &str) -> bool {
    url.scheme().eq_ignore_ascii_case(want)
}

/// Validate the operator-configured target URL against the SSRF guard, returning the canonicalized URL
/// string on success or a stable, credential-free error on rejection. Accepts `https://` for any
/// allowed host and `http://` ONLY for a loopback host (parity with the old webhook policy: a plaintext
/// hop must stay on loopback so a payload — which may carry granted prompt/user content — is never sent
/// in cleartext to a remote host). Any embedded `user:pass@` userinfo is masked out of every error.
pub(crate) fn validate_target_url(raw: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(raw)
        .map_err(|e| format!("webrequest: settings.url is not a valid URL: {e}"))?;
    if !(scheme_is(&url, "https") || scheme_is(&url, "http")) {
        return Err(format!(
            "webrequest: settings.url must be an http:// or https:// URL (got '{}')",
            mask_userinfo(&url)
        ));
    }
    if host_is_blocked(&url) {
        return Err(format!(
            "webrequest: settings.url must not target a link-local/private/CGNAT/cloud-metadata host \
             (SSRF guard; loopback sidecars are allowed); got '{}'",
            mask_userinfo(&url)
        ));
    }
    if scheme_is(&url, "http") && !host_is_loopback(&url) {
        return Err(format!(
            "webrequest: settings.url must use https:// for a non-loopback target (plaintext http:// is \
             only permitted for a loopback sidecar; the payload could otherwise be sent in cleartext); \
             got '{}'",
            mask_userinfo(&url)
        ));
    }
    Ok(url)
}

/// Replace any `user[:pass]@` userinfo on `url` with `***@` so a credential embedded in the operator's
/// URL never reaches a (logged) error message.
///
/// Operates on the ALREADY-PARSED [`reqwest::Url`] rather than doing textual `find("://")` surgery on
/// the raw input string. This matters: WHATWG URL parsing (which both `reqwest::Url::parse` and every
/// real HTTP client use) silently strips embedded TAB/CR/LF from a URL before establishing the scheme
/// separator, so a raw string like `"https:\t//svc:hunter2@10.0.0.1/route"` parses and connects
/// completely normally (host `10.0.0.1`, userinfo `svc:hunter2`) even though the LITERAL substring
/// `"://"` never appears in it. A textual mask keyed on `raw.find("://")` misses that case entirely —
/// it is a silent no-op — and the unmasked credential then lands verbatim in the SSRF-rejection error
/// string. Masking the parsed `Url`'s username/password fields directly is correct regardless of what
/// whitespace or control characters the raw input used to spell the scheme separator.
pub(crate) fn mask_userinfo(url: &reqwest::Url) -> String {
    if url.username().is_empty() && url.password().is_none() {
        return url.to_string();
    }
    let mut masked = url.clone();
    // `set_username`/`set_password` fail only for cannot-be-a-base URLs (e.g. `mailto:`), which never
    // reach here (the scheme is already checked to be http/https) — the error is not actionable if it
    // ever did occur, so it's fine to ignore.
    let _ = masked.set_password(None);
    let _ = masked.set_username("***");
    masked.to_string()
}

/// The target URL in a form that is safe to publish on the operator-visible `status` surface.
///
/// `mask_userinfo` alone is not enough here. It masks credentials in the userinfo, which is the
/// shape that shows up in an ERROR string, but a status field is different: it carries the whole
/// URL, and a sidecar that authenticates by query parameter (`?token=...`) is a common enough shape
/// that publishing the raw query would be a credential leak into the admin API and into every
/// status snapshot taken from it. So the query is redacted to a marker rather than reproduced.
///
/// The fragment goes too: it never reaches the wire on an HTTP request, so it can only be noise or
/// an accident, and there is no reason to echo it.
pub(crate) fn reportable_url(url: &reqwest::Url) -> String {
    let mut safe = url.clone();
    safe.set_fragment(None);
    let had_query = safe.query().is_some();
    safe.set_query(None);
    let base = mask_userinfo(&safe);
    if had_query {
        format!("{base}?<redacted>")
    } else {
        base
    }
}

#[cfg(test)]
mod tests;
