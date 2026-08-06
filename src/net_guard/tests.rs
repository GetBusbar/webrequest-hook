use super::*;

fn url(s: &str) -> reqwest::Url {
    reqwest::Url::parse(s).unwrap()
}

#[test]
fn cgnat_ula_linklocal_predicates_match_core() {
    assert!(is_cgnat_shared_v4(&Ipv4Addr::new(100, 64, 0, 0)));
    assert!(is_cgnat_shared_v4(&Ipv4Addr::new(100, 100, 100, 200))); // Alibaba metadata
    assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(100, 63, 255, 255)));
    assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(8, 8, 8, 8)));
    assert!(is_unique_local_v6(&"fc00::1".parse().unwrap()));
    assert!(is_unique_local_v6(&"fd00:ec2::254".parse().unwrap()));
    assert!(!is_unique_local_v6(&"fe80::1".parse().unwrap()));
    assert!(is_link_local_v6(&"fe80::1".parse().unwrap()));
    assert!(!is_link_local_v6(&"fc00::1".parse().unwrap()));
}

#[test]
fn alternate_encoding_flags_obfuscated_forms() {
    assert!(is_alternate_ipv4_encoding("2130706433"));
    assert!(is_alternate_ipv4_encoding("0x7f000001"));
    assert!(is_alternate_ipv4_encoding("017700000001"));
    assert!(is_alternate_ipv4_encoding("127.1"));
    assert!(!is_alternate_ipv4_encoding("127.0.0.1"));
    assert!(!is_alternate_ipv4_encoding("example.com"));
    assert!(is_alternate_loopback_v4("2130706433"));
    assert!(is_alternate_loopback_v4("127.1"));
    assert!(!is_alternate_loopback_v4("2130706434"));
}

#[test]
fn host_is_blocked_blocks_internal_targets() {
    // Cloud metadata / IMDS.
    assert!(host_is_blocked(&url("http://169.254.169.254/latest")));
    assert!(host_is_blocked(&url("https://metadata.google.internal/x")));
    assert!(host_is_blocked(&url("https://100.100.100.200/meta"))); // Alibaba CGNAT
    assert!(host_is_blocked(&url("https://168.63.129.16/x"))); // Azure WireServer
    assert!(host_is_blocked(&url("https://192.0.0.192/x"))); // OCI IMDS
                                                             // RFC1918 / CGNAT / link-local / ULA.
    assert!(host_is_blocked(&url("https://10.0.0.1/x")));
    assert!(host_is_blocked(&url("https://192.168.1.1/x")));
    assert!(host_is_blocked(&url("https://100.64.0.1/x")));
    assert!(host_is_blocked(&url("https://[fc00::1]/x")));
    assert!(host_is_blocked(&url("https://[fe80::1]/x")));
    // Loopback + external are NOT blocked (the sidecar carve-out).
    assert!(!host_is_blocked(&url("http://127.0.0.1:8080/x")));
    assert!(!host_is_blocked(&url("http://localhost:8080/x")));
    assert!(!host_is_blocked(&url("https://[::1]:8080/x")));
    assert!(!host_is_blocked(&url("https://api.example.com/x")));
}

/// The classic SSRF bypass forms, driven through `host_is_blocked` itself rather than through the
/// helper predicates. Each class below is named as blocked by the module doc and by the README, and
/// each had NO test at the guard's entry point, which is the only place an operator's URL actually
/// flows through. Deleting any one of these branches left the whole suite green.
#[test]
fn host_is_blocked_covers_the_classic_bypass_forms() {
    // IPv4-MAPPED and IPv4-COMPATIBLE IPv6. The canonical way to smuggle a v4 internal address
    // past a guard that only pattern-matches v6. `Ipv6Addr::to_ipv4` covers both spellings.
    assert!(host_is_blocked(&url(
        "http://[::ffff:169.254.169.254]/latest"
    )));
    assert!(host_is_blocked(&url("https://[::ffff:10.0.0.1]/x")));
    assert!(host_is_blocked(&url("https://[::ffff:192.168.1.1]/x")));
    assert!(host_is_blocked(&url("https://[::ffff:100.100.100.200]/x")));
    // ...and the mapped form of loopback stays ALLOWED, matching the bare-v4 sidecar carve-out.
    assert!(!host_is_blocked(&url("http://[::ffff:127.0.0.1]:8080/x")));

    // ALTERNATE IPv4 ENCODINGS. Worth being precise about what this proves, because the obvious
    // reading is wrong: the URL parser canonicalizes every one of these to a dotted quad BEFORE the
    // guard sees the host, so these assertions exercise the ordinary IPv4 branch, not the
    // alternate-encoding branch. That is defence in depth working (the parser refuses to hand the
    // guard an obfuscated host at all), and it is worth pinning, because a parser change that
    // stopped canonicalizing would otherwise be silent. The alternate-encoding predicates
    // themselves are covered directly above; their branch here is unreachable for http/https URLs.
    assert!(host_is_blocked(&url("http://2852039166/latest"))); // 169.254.169.254 in decimal
    assert!(host_is_blocked(&url("http://0xa9fea9fe/latest"))); // the same, in hex
    assert!(host_is_blocked(&url("http://0251.0376.0251.0376/x"))); // the same, in octal
    assert!(host_is_blocked(&url("http://10.1/x"))); // short-dotted 10.0.0.1
                                                     // Alternate encodings OF loopback stay allowed, same carve-out as the dotted form.
    assert!(!host_is_blocked(&url("http://2130706433:8080/x")));
    assert!(!host_is_blocked(&url("http://127.1:8080/x")));

    // The SECOND metadata host. Half of METADATA_HOSTS had no fixture.
    assert!(host_is_blocked(&url("https://metadata.internal/x")));
    assert!(host_is_blocked(&url("https://metadata.google.internal/x")));
    // Case-insensitively, and with the FQDN root dot that `host_of` strips. Without that strip a
    // single trailing character walks straight past the metadata block.
    assert!(host_is_blocked(&url("https://METADATA.GOOGLE.INTERNAL/x")));
    assert!(host_is_blocked(&url("https://metadata.google.internal./x")));
    assert!(host_is_blocked(&url("https://metadata.internal./x")));

    // UNSPECIFIED and BROADCAST. `0.0.0.0` reaches loopback on Linux, so it is a live
    // loopback-adjacent form the sidecar carve-out was never meant to cover.
    assert!(host_is_blocked(&url("http://0.0.0.0:8080/x")));
    assert!(host_is_blocked(&url("http://[::]:8080/x")));
    assert!(host_is_blocked(&url("http://255.255.255.255/x")));

    // The MIDDLE RFC1918 block. Only 10.x and 192.168.x had fixtures, so 172.16/12 was unpinned.
    assert!(host_is_blocked(&url("https://172.16.0.1/x")));
    assert!(host_is_blocked(&url("https://172.31.255.254/x")));
    // ...and the addresses either side of it are NOT private, so the mask is pinned rather than
    // satisfied by a wider one.
    assert!(!host_is_blocked(&url("https://172.15.0.1/x")));
    assert!(!host_is_blocked(&url("https://172.32.0.1/x")));

    // A hostless URL is unusable as a target and must be refused rather than allowed by default.
    assert!(host_is_blocked(&url("file:///etc/passwd")));
}

/// IPv6 forms that CARRY an internal IPv4 target but that `Ipv6Addr::to_ipv4` does not unwrap.
/// Each of these was allowed: NAT64 is standard on IPv6-only clusters, which makes
/// `[64:ff9b::a9fe:a9fe]` a live route to the metadata endpoint.
#[test]
fn ipv6_embeddings_of_internal_ipv4_targets_are_blocked() {
    // NAT64, RFC 6052 well-known prefix.
    assert_eq!(
        embedded_v4(&"64:ff9b::a9fe:a9fe".parse().unwrap()),
        Some(Ipv4Addr::new(169, 254, 169, 254))
    );
    assert!(host_is_blocked(&url("https://[64:ff9b::a9fe:a9fe]/latest")));
    assert!(host_is_blocked(&url("https://[64:ff9b::a00:1]/x"))); // 10.0.0.1
                                                                  // RFC 8215 LOCAL-USE prefix. This is the one a deployment translating to RFC1918 space
                                                                  // actually uses, because the well-known prefix may not be used with non-global IPv4.
    assert_eq!(
        embedded_v4(&"64:ff9b:1::a9fe:a9fe".parse().unwrap()),
        Some(Ipv4Addr::new(169, 254, 169, 254))
    );
    assert!(host_is_blocked(&url("https://[64:ff9b:1::a9fe:a9fe]/x")));
    assert!(host_is_blocked(&url("https://[64:ff9b:1::a00:1]/x")));
    // 6to4, RFC 3056.
    assert_eq!(
        embedded_v4(&"2002:a00:1::".parse().unwrap()),
        Some(Ipv4Addr::new(10, 0, 0, 1))
    );
    assert!(host_is_blocked(&url("https://[2002:a00:1::]/x")));
    assert!(host_is_blocked(&url("https://[2002:a9fe:a9fe::]/x"))); // 169.254.169.254
                                                                    // Deprecated site-local, covered by neither the ULA nor the link-local mask.
    assert!(is_site_local_v6(&"fec0::1".parse().unwrap()));
    assert!(host_is_blocked(&url("https://[fec0::1]/x")));
    // A genuinely external IPv6 address is still allowed, so the new checks are not a blanket deny.
    assert!(!host_is_blocked(&url("https://[2606:4700:4700::1111]/x")));
    assert_eq!(embedded_v4(&"2606:4700:4700::1111".parse().unwrap()), None);
    // ...and a NAT64/6to4 form carrying LOOPBACK keeps the sidecar carve-out.
    assert!(!host_is_blocked(&url("http://[64:ff9b::7f00:1]:8080/x")));
}

/// `fe80::/10` is a /10, not a /16. The only previous fixture was `fe80::1`, whose first segment is
/// exactly `0xfe80`, so widening the mask to `0xffff` (a /16) kept it green while genuine
/// link-local addresses in the rest of the range stopped being blocked.
#[test]
fn link_local_v6_is_a_slash_10_not_a_slash_16() {
    for addr in ["fe80::1", "fe9f::1", "febf::1", "feb0::dead"] {
        assert!(
            is_link_local_v6(&addr.parse().unwrap()),
            "{addr} is inside fe80::/10 and must be link-local"
        );
        assert!(host_is_blocked(&url(&format!("https://[{addr}]/x"))));
    }
    // Just outside the /10 in both directions.
    assert!(!is_link_local_v6(&"fe7f::1".parse().unwrap()));
    assert!(!is_link_local_v6(&"fec0::1".parse().unwrap()));
}

#[test]
fn validate_rejects_scheme_and_plaintext_remote() {
    assert!(validate_target_url("ftp://example.com/x").is_err());
    // Plaintext http to a remote host is rejected (cleartext payload risk).
    assert!(validate_target_url("http://api.example.com/x").is_err());
    // Plaintext http to loopback is allowed (sidecar).
    assert!(validate_target_url("http://127.0.0.1:9000/route").is_ok());
    assert!(validate_target_url("http://localhost:9000/route").is_ok());
    // https to a remote host is allowed.
    assert!(validate_target_url("https://api.example.com/route").is_ok());
    // https to an internal host is rejected.
    assert!(validate_target_url("https://10.0.0.1/route").is_err());
}

#[test]
fn errors_mask_embedded_userinfo() {
    let err = validate_target_url("https://svc:hunter2@10.0.0.1/route").unwrap_err();
    assert!(
        !err.contains("hunter2"),
        "SSRF error leaked userinfo: {err}"
    );
    assert_eq!(
        mask_userinfo(&url("https://svc:hunter2@host/p?q=1")),
        "https://***@host/p?q=1"
    );
    assert_eq!(mask_userinfo(&url("https://host/p")), "https://host/p");
}

/// The status surface must not republish a query string. A sidecar authenticating by query
/// parameter is common, and `status.settings.url` is operator-visible over the admin API and lands
/// in any snapshot taken from it, so masking userinfo alone is not enough there.
#[test]
fn the_reportable_url_redacts_a_query_string_and_the_fragment() {
    assert_eq!(
        reportable_url(&url("https://hooks.example.com/route?token=eyJhbGciOi")),
        "https://hooks.example.com/route?<redacted>"
    );
    assert_eq!(
        reportable_url(&url(
            "https://svc:hunter2@hooks.example.com/route?token=abc"
        )),
        "https://***@hooks.example.com/route?<redacted>"
    );
    // No query means the value is reported in full, so the drift check still works for the common
    // case: the whole point of reporting `url` at all is that the engine compares it by name.
    assert_eq!(
        reportable_url(&url("https://hooks.example.com/route")),
        "https://hooks.example.com/route"
    );
    // The fragment never reaches the wire, so it is dropped rather than echoed.
    assert_eq!(
        reportable_url(&url("https://hooks.example.com/route#frag")),
        "https://hooks.example.com/route"
    );
}

/// Regression for the TAB-in-scheme-separator masking bypass: WHATWG URL parsing (which
/// `reqwest::Url::parse` uses, same as the real HTTP client) strips embedded TAB/CR/LF before the
/// scheme separator, so `"https:\t//svc:hunter2@10.0.0.1/route"` parses and resolves completely
/// normally to host `10.0.0.1` with userinfo `svc:hunter2` — even though the literal substring
/// `"://"` never appears in the raw string. A masking function keyed on `raw.find("://")` would
/// silently no-op here and leak `hunter2` verbatim into the SSRF-rejection error. Assert BOTH that the
/// credential never reaches the error string AND that the URL was actually recognized as targeting the
/// blocked host (i.e. this is exercising the real SSRF-rejection path, not an early scheme-parse bail).
#[test]
fn mask_userinfo_survives_tab_in_scheme_separator() {
    let raw = "https:\t//svc:hunter2@10.0.0.1/route";
    // Sanity: this raw string really does parse and really does resolve to the blocked host — proving
    // the reproduction is real, not a URL that simply fails to parse.
    let parsed = reqwest::Url::parse(raw).expect("WHATWG parsing accepts the embedded tab");
    assert_eq!(parsed.host_str(), Some("10.0.0.1"));

    let err = validate_target_url(raw).expect_err("10.0.0.1 must be SSRF-rejected");
    assert!(
        !err.contains("hunter2"),
        "mask_userinfo must mask a TAB-obfuscated scheme separator too, got: {err}"
    );
    assert_eq!(mask_userinfo(&parsed), "https://***@10.0.0.1/route");
}
