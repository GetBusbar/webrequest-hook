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
        fwd.timeout,
        Duration::from_millis(MAX_TIMEOUT_MS),
        "an oversized timeout_ms must clamp to MAX_TIMEOUT_MS, not pass through"
    );

    let fwd = Forwarder::new(Config {
        url: "https://api.example.com/route".to_string(),
        timeout_ms: Some(0),
    })
    .expect("valid config");
    assert_eq!(
        fwd.timeout,
        Duration::from_millis(1),
        "a zero timeout_ms must clamp up to the 1ms floor"
    );
}

/// Dropping a `Forwarder` from INSIDE an async context (a tokio worker thread) must NOT panic.
/// This reproduces the hot-reload drop path: on config reload the last `Arc<App>` — and this
/// forwarder with it — can drop on a tokio async thread. A bare `Runtime` dropped there panics
/// ("Cannot drop a runtime in a context where blocking is not allowed"), which the SDK's
/// `ffi_guard` would catch and LEAK the handle. The `Drop` impl's `shutdown_background()` makes
/// the drop non-blocking, so no panic fires. Before the fix this test panicked/aborted.
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
