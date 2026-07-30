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
        mask_userinfo("https://svc:hunter2@host/p?q=1"),
        "https://***@host/p?q=1"
    );
    assert_eq!(mask_userinfo("https://host/p"), "https://host/p");
}
