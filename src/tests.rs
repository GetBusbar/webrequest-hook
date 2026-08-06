use super::*;

/// `open` fails closed on a missing/empty URL, a malformed config, and an SSRF-blocked URL; and
/// succeeds for a valid https target and a loopback http sidecar.
#[test]
fn open_fails_closed_on_bad_config() {
    assert!(open("").is_err(), "empty config (no url) must fail closed");
    assert!(open("{}").is_err(), "config without url must fail closed");
    assert!(
        open("{ not json").is_err(),
        "malformed config must fail closed"
    );
    assert!(
        open(r#"{"url":"http://169.254.169.254/x"}"#).is_err(),
        "an SSRF-blocked url must fail the load"
    );
    assert!(
        open(r#"{"url":"http://10.0.0.1/x"}"#).is_err(),
        "an RFC1918 url must fail the load"
    );
    assert!(
        open(r#"{"url":"http://api.example.com/x"}"#).is_err(),
        "plaintext http to a remote target must fail the load"
    );
    assert!(
        open(r#"{"url":"https://api.example.com/route"}"#).is_ok(),
        "a valid https target must load"
    );
    assert!(
        open(r#"{"url":"http://127.0.0.1:9000/route"}"#).is_ok(),
        "a loopback http sidecar must load"
    );
}

/// The reply parser caps depth and reports a LENGTH-ONLY error (never echoing the reply bytes).
#[test]
fn parse_reply_depth_and_length_only_errors() {
    // A ~150-deep body is rejected before a Value is built (well under the size cap).
    let mut deep = String::from(r#"{"order":"#);
    deep.push_str(&"[".repeat(150));
    deep.push_str(&"]".repeat(150));
    deep.push('}');
    assert!(deep.len() < MAX_REPLY_BYTES);
    assert!(parse_reply(deep.as_bytes()).is_err());

    // A malformed reply that echoes prompt content must not splash it into the error.
    let malformed = br#"{"order":[0,, "echo":"SENTINEL-PROMPT-TEXT"}"#;
    let err = parse_reply(malformed).unwrap_err();
    assert!(
        !err.contains("SENTINEL-PROMPT-TEXT"),
        "parse error echoed reply bytes: {err}"
    );
    assert!(
        err.contains("invalid JSON"),
        "expected length-only message: {err}"
    );

    // A well-formed reply parses.
    assert_eq!(
        parse_reply(br#"{"order":[1,0]}"#).unwrap(),
        serde_json::json!({"order": [1, 0]})
    );
}

/// The depth cap is exact at its OWN boundary, wherever that boundary actually is: every other test
/// only probes well-past-the-limit (150) or well-under, so an off-by-one in `exceeds_max_depth`'s
/// `depth > max` (e.g. changed to `>=`) would silently narrow the real contract by one and nothing
/// else here would catch it.
///
/// NOTE the boundary this test pins is depth 127, not `MAX_REPLY_DEPTH` (128) as the module doc
/// comment claims ("depth-guarded at 128 levels"): `serde_json`'s OWN internal recursion limit
/// rejects a depth-128 document before `exceeds_max_depth`'s pre-check is even the deciding factor
/// (depth 127 parses; depth 128 fails serde_json's own parse regardless of the pre-check's
/// `128 > 128` being false). The crate's real, usable ceiling is therefore one level lower than the
/// module doc states, and this test pins the observed behaviour.
#[test]
fn parse_reply_depth_boundary_is_exact() {
    let nested = |n: usize| {
        let mut s = String::from(r#"{"order":"#);
        s.push_str(&"[".repeat(n));
        s.push_str(&"]".repeat(n));
        s.push('}');
        s
    };
    // n array levels + the outer `{` = a max depth of n+1.
    let at_boundary = nested(MAX_REPLY_DEPTH - 2); // depth 127: accepted
    assert!(
        parse_reply(at_boundary.as_bytes()).is_ok(),
        "depth 127 (one below serde_json's own internal recursion limit) must still be accepted"
    );
    let one_over = nested(MAX_REPLY_DEPTH - 1); // depth 128: rejected
    assert!(
        parse_reply(one_over.as_bytes()).is_err(),
        "depth 128 must be rejected"
    );
}

/// The non-object-payload fallback branch of `Envelope::serialize` (wraps a non-object projection
/// under a `payload` key rather than dropping it) is live, reachable code with no prior coverage —
/// prove it actually does what its comment claims instead of trusting the comment.
#[test]
fn envelope_wraps_a_non_object_payload_under_payload_key() {
    let payload = serde_json::json!(["not", "an", "object"]);
    let value = request_envelope("notify", &payload);
    assert_eq!(value["op"], "notify");
    assert_eq!(value["payload"], payload);
}

/// The RAW BYTE serialization (what actually goes on the wire via `post_op`'s `serde_json::to_vec`,
/// not the `to_value`-based `request_envelope` test helper, which would hide this: `to_value` builds
/// a `Map` that naturally collapses duplicate keys regardless of what the `Serialize` impl emits) must
/// never contain the `op` key twice, even when the projected payload itself carries a top-level `op`
/// field.
///
/// Without the skip, the payload's own `"op":"whatever"` and the discriminator's `"op":"decide"`
/// are both written to the byte stream — two `"op":` occurrences. As implemented, the payload's `op`
/// key is skipped and only the discriminator's `op` is emitted.
#[test]
fn envelope_byte_serialization_never_duplicates_the_op_key() {
    let payload = serde_json::json!({
        "op": "whatever-the-payload-happened-to-carry",
        "request": {"pool": "p"}
    });
    let bytes = serde_json::to_vec(&Envelope {
        op: "decide",
        payload: &payload,
    })
    .expect("envelope always serializes");
    let raw = String::from_utf8(bytes).unwrap();
    let op_key_count = raw.matches("\"op\":").count();
    assert_eq!(
        op_key_count, 1,
        "expected exactly one \"op\" key on the wire, got {op_key_count} in: {raw}"
    );
    // And it must be the discriminator's value, not the payload's stale one.
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(parsed["op"], "decide");
}

/// The request envelope merges the `op` discriminator into the projection object, preserving every
/// projected key (so any opt-in prompt/user the core granted rides straight through).
#[test]
fn request_envelope_merges_op_and_preserves_projection() {
    let payload = serde_json::json!({
        "request": {"pool": "p", "messages": [{"role": "user", "text": "hi"}]},
        "candidates": [{"idx": 0}]
    });
    let env = request_envelope("decide", &payload);
    assert_eq!(env["op"], "decide");
    assert_eq!(env["request"]["pool"], "p");
    assert_eq!(env["request"]["messages"][0]["text"], "hi");
    assert_eq!(env["candidates"][0]["idx"], 0);
}

/// `post_op`'s transport-error string is masked even when the target URL embeds a credential. The
/// e2e test of the same property now works too (a `decide` failure reaches the engine rather than
/// being discarded as an `Abstain`), so this is the narrower unit-level twin of it.
///
/// NOT "without `.without_url()` this would contain `hunter2`" — it would not, and this comment used
/// to claim it did. reqwest strips `user:pass@` off the URL into an auth header before the request
/// is made, so the userinfo is gone whatever this crate does. What `.without_url()` actually removes
/// is the QUERY STRING, which reqwest preserves verbatim; `tests/e2e.rs`'s
/// `forward_transport_error_never_leaks_userinfo` is the one that asserts it, because that is where
/// a `?token=` can be injected through the real config seam.
#[test]
fn post_op_error_string_never_contains_url_userinfo() {
    let fwd = Forwarder::new(Config {
        // RFC 5737 TEST-NET-1: unroutable, so the POST fails fast without a real network hop.
        url: "https://svc:hunter2@192.0.2.1/route".to_string(),
        timeout_ms: Some(300),
    })
    .expect(
        "192.0.2.1 is a public IP over https, so it loads fine (the SSRF guard only blocks \
             plaintext http to a non-loopback host, and load-time RFC1918/link-local ranges)",
    );
    let err = fwd
        .post_op("decide", &serde_json::json!({}))
        .expect_err("192.0.2.1 is unroutable test-net space; the POST must fail");
    assert!(
        !err.contains("hunter2"),
        "post_op error leaked the URL's userinfo credential: {err}"
    );
    assert!(
        !err.contains("svc:"),
        "post_op error leaked the URL's userinfo username: {err}"
    );
}

/// `describe` returns the forwarder's own schema; `status` reports the target host and timeout with
/// no prompt/user content, and acks its own metrics shape.
#[test]
fn describe_and_status_report_own_state() {
    let fwd = Forwarder::new(Config {
        url: "https://api.example.com/route".to_string(),
        timeout_ms: Some(1234),
    })
    .expect("valid config");
    assert_eq!(fwd.describe()["schema"]["type"], "object");
    let status = fwd.status();
    assert_eq!(
        status["status"]["settings"]["target_host"],
        "api.example.com"
    );
    assert_eq!(status["status"]["settings"]["timeout_ms"], 1234);
}

/// `configure` RE-VALIDATES a pushed URL against the SSRF guard: a good URL ACKs (true), an
/// SSRF-blocked URL NACKs (false → the engine rejects the push), a missing url ACKs (nothing to check).
#[test]
fn configure_revalidates_pushed_url() {
    let fwd = Forwarder::new(Config {
        url: "https://api.example.com/route".to_string(),
        timeout_ms: None,
    })
    .expect("valid config");

    let mut ok = serde_json::Map::new();
    ok.insert(
        "url".into(),
        serde_json::json!("https://other.example.com/route"),
    );
    assert!(fwd.configure(&ok, 2), "a valid pushed url must ACK");

    let mut bad = serde_json::Map::new();
    bad.insert("url".into(), serde_json::json!("http://169.254.169.254/x"));
    assert!(
        !fwd.configure(&bad, 3),
        "an SSRF-blocked pushed url must NACK"
    );

    assert!(
        fwd.configure(&serde_json::Map::new(), 4),
        "a missing url ACKs"
    );
}

/// A pushed `url` that's PRESENT but not a string (a templating bug rendering it as a number or
/// null) must NACK, not be treated identically to an absent key.
///
/// A bare `settings.get("url").and_then(|v| v.as_str())` yields `None` for a non-string value
/// exactly as it does for a missing key, which would fall into the same "nothing to check, ACK" arm
/// as a genuinely absent url. As implemented, a present-but-wrong-typed url is distinguished and
/// NACKs.
#[test]
fn configure_nacks_a_present_but_wrong_typed_url() {
    let fwd = Forwarder::new(Config {
        url: "https://api.example.com/route".to_string(),
        timeout_ms: None,
    })
    .expect("valid config");

    let mut number_url = serde_json::Map::new();
    number_url.insert("url".into(), serde_json::json!(12345));
    assert!(
        !fwd.configure(&number_url, 5),
        "a non-string url must NACK, not be silently treated as absent"
    );

    let mut null_url = serde_json::Map::new();
    null_url.insert("url".into(), serde_json::Value::Null);
    assert!(
        !fwd.configure(&null_url, 6),
        "a null url must NACK, not be silently treated as absent"
    );
}

/// An operator-supplied `timeout_ms` is clamped to `[1, MAX_TIMEOUT_MS]` — MAX_TIMEOUT_MS must not
/// meaningfully exceed the engine's reference hook budget (see its doc comment), so a fat-fingered
/// huge value cannot pin the process-wide hook FFI permit for far longer than the engine itself
/// budgets for one hook call.
#[test]
fn timeout_ms_is_clamped_to_max_timeout_ms() {
    let fwd = Forwarder::new(Config {
        url: "https://api.example.com/route".to_string(),
        timeout_ms: Some(60_000),
    })
    .expect("valid config");
    assert_eq!(
        fwd.live.read().unwrap().timeout,
        Duration::from_millis(MAX_TIMEOUT_MS),
        "an oversized timeout_ms must clamp to MAX_TIMEOUT_MS, not pass through"
    );

    let fwd = Forwarder::new(Config {
        url: "https://api.example.com/route".to_string(),
        timeout_ms: Some(0),
    })
    .expect("valid config");
    assert_eq!(
        fwd.live.read().unwrap().timeout,
        Duration::from_millis(1),
        "a zero timeout_ms must clamp up to the 1ms floor"
    );
}

/// Validating a pushed `url` against the SSRF guard and ACKing without updating the live forwarder
/// would leave every subsequent `decide`/`transform`/`notify` posting to the URL from `open`,
/// silently, until an unrelated plugin reload. That would break busbar's documented contract for this
/// op (`docs/admin-api.md`'s `PATCH /hooks/{name}/settings`: "commit on ack", no restart-to-apply
/// carve-out for hooks) — an operator's PATCH would report success while nothing changed. As
/// implemented, a committed (ACKed) `url` push is visible immediately via `status()`.
#[test]
fn configure_commits_a_new_url_to_the_live_target() {
    let fwd = Forwarder::new(Config {
        url: "https://api.example.com/route".to_string(),
        timeout_ms: None,
    })
    .expect("valid config");
    assert_eq!(
        fwd.status()["status"]["settings"]["target_host"],
        "api.example.com"
    );

    let mut push = serde_json::Map::new();
    push.insert(
        "url".into(),
        serde_json::json!("https://other.example.com/route"),
    );
    assert!(fwd.configure(&push, 2), "a valid pushed url must ACK");

    assert_eq!(
        fwd.status()["status"]["settings"]["target_host"],
        "other.example.com",
        "an ACKed url push must take effect on the live forwarder, not just validate and discard"
    );
}

/// A committed `timeout_ms` push (with no `url` key in the same push) updates the live timeout and
/// leaves the live url untouched — the two settings commit independently.
#[test]
fn configure_commits_a_new_timeout_without_touching_the_url() {
    let fwd = Forwarder::new(Config {
        url: "https://api.example.com/route".to_string(),
        timeout_ms: Some(1234),
    })
    .expect("valid config");

    let mut push = serde_json::Map::new();
    push.insert("timeout_ms".into(), serde_json::json!(500));
    assert!(
        fwd.configure(&push, 2),
        "a valid pushed timeout_ms must ACK"
    );

    let status = fwd.status();
    assert_eq!(status["status"]["settings"]["timeout_ms"], 500);
    assert_eq!(
        status["status"]["settings"]["target_host"], "api.example.com",
        "a timeout_ms-only push must not disturb the live url"
    );
}

/// A pushed `timeout_ms` that's PRESENT but not a non-negative integer (a string, a float, a negative
/// number) must NACK the whole push — including any `url` key in the SAME push, which must not commit
/// partially.
#[test]
fn configure_nacks_a_present_but_wrong_typed_timeout_and_does_not_partially_apply() {
    let fwd = Forwarder::new(Config {
        url: "https://api.example.com/route".to_string(),
        timeout_ms: None,
    })
    .expect("valid config");

    let mut push = serde_json::Map::new();
    push.insert(
        "url".into(),
        serde_json::json!("https://other.example.com/route"),
    );
    push.insert("timeout_ms".into(), serde_json::json!("soon"));
    assert!(
        !fwd.configure(&push, 2),
        "a non-integer timeout_ms must NACK"
    );
    assert_eq!(
        fwd.status()["status"]["settings"]["target_host"],
        "api.example.com",
        "a NACKed push must not partially commit the url from the same push"
    );
}

/// Dropping a `Forwarder` from INSIDE an async context (a tokio worker thread) must NOT panic.
/// This reproduces the hot-reload drop path: on config reload the last `Arc<App>` — and this
/// forwarder with it — can drop on a tokio async thread. A bare `Runtime` dropped there panics
/// ("Cannot drop a runtime in a context where blocking is not allowed"), which the SDK's
/// `ffi_guard` would catch and LEAK the handle. The `Drop` impl's `shutdown_background()` makes
/// the drop non-blocking, so no panic fires.
#[test]
fn drop_in_async_context_does_not_panic() {
    // A MULTI-thread runtime with worker threads: `block_on` here runs on a thread that IS a
    // tokio runtime context, so the inner forwarder's owned current-thread runtime would hit the
    // forbidden blocking-drop if `Drop` did not use `shutdown_background()`.
    let outer = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("build outer runtime");
    outer.block_on(async {
        let fwd = Forwarder::new(Config {
            url: "https://api.example.com/route".to_string(),
            timeout_ms: None,
        })
        .expect("valid config");
        // Dropping `fwd` here is the operation under test — it must not panic in this async context.
        drop(fwd);
    });
}
