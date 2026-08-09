// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE 1.5.3 STAGE FAN-OUT PROOF: an UNSCOPED hook, registered over the real admin API into a real
//! running `busbar`, observes one request at EVERY core stage, and the stage envelopes are
//! shape-only while the request envelope is the one carrying prompt content.
//!
//! `tests/full_stack_e2e.rs` (the sibling file) proves the install -> load -> invoke -> webhook
//! chain for the REQUEST stage specifically, and pins its tap there with `at: "request"` so it
//! observes exactly one call. That pin is the documented opt-out from the change this file exists
//! to cover:
//!
//!   busbarAI CHANGELOG.md, "[1.5.3] Breaking changes":
//!     "A hand-written hook with no stage list now fires at all four stages rather than once per
//!      request; set `phase: [request]` for the old behaviour."
//!
//! Without this file the plugin repo would merely TOLERATE that change: `full_stack_e2e` would go
//! green because it opted out, and nothing anywhere would assert that the fan-out actually happens
//! or that its envelopes have the shape a sidecar author is told to expect. That is the gap this
//! closes. It is a POSITIVE test: it registers a tap with no stage scoping at all, the exact
//! configuration an operator writes when they have not thought about stages, and asserts what such
//! a hook really receives.
//!
//! What is asserted, and why each part matters to a sidecar author:
//!
//!   1. All four core stages arrive for ONE request: the stage-less request envelope, plus
//!      `stage.at` values covering `candidate`, `routing` and `response`. A sidecar sized for
//!      one call per request is sized wrong by a factor of four.
//!   2. Exactly ONE envelope carries prompt text, and it is the stage-less (request-stage) one.
//!      The engine sends `system`/`messages`/`user` as absent on stage taps regardless of grant,
//!      so a `prompt: ro` hook does NOT get content four times over. A sidecar that screens or
//!      logs content keys off the request envelope; one that assumed every notify carries content
//!      would silently screen nothing on three quarters of its traffic.
//!   3. The stage envelopes are shape-only in the other direction too: no `candidates`, and the
//!      documented per-stage fields are present (`remaining_candidates` on `candidate`,
//!      `attempt_number` + `model` on `routing`, `outcome` + `status` on `response`).
//!   4. Every envelope carries the SAME `request.request_id`. That is the documented join key, and
//!      it is the only thing that lets a sidecar correlate four separate POSTs back into one
//!      request. If it ever drifted per stage, stage taps would be unusable for audit.
//!
//! The harness below (binary discovery, signing, boot, mocks) is a deliberate copy of
//! `full_stack_e2e.rs`'s, following this repo's established convention for integration tests: each
//! `tests/*.rs` is its own independent test binary and carries its own helpers rather than sharing
//! a `tests/common` module (see the `plugin_path()` doc comment in `tests/e2e.rs`, which makes the
//! same call for the same reason). Only the hook REGISTRATION and the ASSERTIONS differ, and both
//! differences are the point of the file.

use axum::routing::post;
use axum::Router;
use busbar_plugin_sign::{HookNeeds, Manifest, NeedLevel, SigningKey};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Fixed ed25519 signing secret (64 hex = 32 bytes) for this e2e test. 1.5.1 requires an
/// explicit signing key to mint virtual keys; busbar no longer auto-generates one.
const TEST_SIGNING_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The sibling `busbarAI` monorepo checkout - same interim path convention as `Cargo.toml`'s
/// `busbar-plugin-sdk` dependency.
fn busbarai_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../busbarAI")
}

/// Locate (building on demand) the real `busbar` engine binary from the sibling checkout. Same
/// discipline as `full_stack_e2e.rs`: under CI a missing checkout or a failed build is a hard
/// panic, never a silent skip, because a test that quietly no-ops is worse than no test.
fn busbar_bin() -> Option<PathBuf> {
    let root = busbarai_root();
    if !root.join("Cargo.toml").exists() {
        if std::env::var_os("CI").is_some() {
            panic!(
                "stage_fanout_e2e: sibling busbarAI checkout not found at {} under CI; refusing to \
                 silently skip the only coverage of the 1.5.3 per-stage notify fan-out",
                root.display()
            );
        }
        eprintln!(
            "skip: sibling busbarAI checkout not found at {} (run under the plugin-ci layout)",
            root.display()
        );
        return None;
    }
    let bin = root.join("target").join("debug").join("busbar");
    if !bin.exists() {
        eprintln!(
            "stage_fanout_e2e: building the busbar binary from the sibling checkout (first run \
             only)..."
        );
        let status = Command::new("cargo")
            .args(["build", "--bin", "busbar"])
            .current_dir(&root)
            .status()
            .expect("run `cargo build --bin busbar` in the sibling checkout");
        if !status.success() || !bin.exists() {
            if std::env::var_os("CI").is_some() {
                panic!(
                    "stage_fanout_e2e: failed to build the busbar binary from the sibling checkout \
                     under CI"
                );
            }
            eprintln!("skip: failed to build the busbar binary locally");
            return None;
        }
    }
    Some(bin)
}

/// Locate the built `webrequest` cdylib. Checks BOTH the uplifted `<profile_dir>/<name>` copy and
/// the raw `<profile_dir>/deps/<name>` compiler output, newest wins - a bare `cargo test` does not
/// uplift the top-level copy, so checking only that path finds nothing or something stale and this
/// test silently no-ops. See `tests/e2e.rs`'s `plugin_path()` for the full story.
fn webrequest_cdylib() -> Option<PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_webrequest_hook_plugin");
        let uplifted = profile_dir.join(&name);
        let raw = profile_dir.join("deps").join(&name);
        [uplifted, raw]
            .into_iter()
            .filter_map(|p| {
                std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (p, mtime))
            })
            .max_by_key(|(_, mtime)| *mtime)
            .map(|(p, _)| p)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "stage_fanout_e2e: the webrequest-hook plugin cdylib is not built under CI: \
             `cargo test` must build busbar_webrequest_hook_plugin (checked both the uplifted \
             target dir and target/deps)."
        );
    }
    candidate
}

/// Grab an ephemeral free TCP port by binding to port 0 and reading it back, then dropping the
/// listener. Small TOCTOU window, acceptable for a test: a real collision fails loudly.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// A local mock HTTP server standing in for the operator's webhook target. Captures every POSTed
/// body (parsed as JSON) and always replies `{}`.
async fn mock_webhook() -> (String, Arc<Mutex<Vec<serde_json::Value>>>) {
    let captured: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = captured.clone();
    let app = Router::new().route(
        "/",
        post(move |body: axum::body::Bytes| {
            let sink = sink.clone();
            async move {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) {
                    sink.lock().unwrap().push(v);
                }
                (
                    axum::http::StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    "{}",
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/"), captured)
}

/// A mock upstream "model" server: replies to `POST /v1/messages` with a minimal valid Anthropic
/// Messages response, enough for busbar's ingress/egress translation to produce a real 200.
async fn mock_upstream() -> String {
    let app = Router::new().route(
        "/v1/messages",
        post(|| async {
            (
                axum::http::StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                r#"{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":11,"output_tokens":7}}"#,
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// Build a GENUINELY signed plugin tarball around `lib_bytes`, the exact way the release pipeline
/// does, so the REAL signature-verification path runs rather than the `allow_unsigned` escape.
fn build_signed_tarball(lib_bytes: &[u8]) -> (Vec<u8>, String) {
    let seed = [0x42u8; 32];
    let key = SigningKey::from_bytes(&seed);
    let manifest = Manifest {
        name: "busbar-webrequest-hook-plugin".to_string(),
        alias: "webrequest".to_string(),
        kind: "hook".to_string(),
        version: "1.5.0".to_string(),
        publisher: "acme-e2e".to_string(),
        abi_version: *busbar_plugin_loader::supported_abi("hook")
            .iter()
            .max()
            .unwrap(),
        sha256: String::new(),
        signature: String::new(),
        description: "stage_fanout_e2e signed test tarball".to_string(),
        homepage: String::new(),
        license: "Apache-2.0".to_string(),
        needs: HookNeeds {
            prompt: NeedLevel::Ro,
            user: NeedLevel::No,
        },
        settings_schema: None,
        schema_derived: false,
        host: None,
    };
    let signed = busbar_plugin_sign::sign(&key, manifest, lib_bytes);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "lib.so", lib_bytes)
        .expect("package signed tarball");
    let pubkey_hex = hex_encode(&key.verifying_key().to_bytes());
    (tarball, pubkey_hex)
}

/// Lowercase-hex encode - avoids pulling in a `hex` crate for one call site.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A child-process guard: always kill + reap `busbar` on drop (including on test panic), so a
/// failing assertion never leaks a live busbar process holding ports open.
struct BusbarProcess {
    child: Child,
}

impl Drop for BusbarProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Poll `GET /healthz` on the admin listener until it answers, or panic after a generous timeout.
async fn wait_for_healthz(admin_addr: &str) {
    let client = reqwest::Client::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(resp) = client
            .get(format!("http://{admin_addr}/healthz"))
            .timeout(Duration::from_secs(2))
            .send()
            .await
        {
            if resp.status().is_success() {
                return;
            }
        }
        if std::time::Instant::now() > deadline {
            panic!("busbar did not become healthy within 30s");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Poll the captured-webhook sink until the observed CALL COUNT has stopped moving, then return the
/// settled batch. Same helper (and same reasoning) as `full_stack_e2e.rs`'s.
///
/// This test needs the settle even more than that one does: it asserts a SET of stages, so reading
/// the sink the moment it turns non-empty would routinely see the request and candidate envelopes
/// and miss routing and response, failing for a reason that has nothing to do with the contract.
/// A late arrival resets the streak, so an unexpected EXTRA envelope is surfaced to the assertions
/// rather than raced past.
async fn settle_captured(
    captured: &Arc<Mutex<Vec<serde_json::Value>>>,
    timeout: Duration,
) -> Vec<serde_json::Value> {
    /// Gap between polls.
    const POLL: Duration = Duration::from_millis(100);
    /// Consecutive equal, non-zero counts required before the batch is considered settled.
    const STABLE_POLLS: u32 = 5;

    let deadline = std::time::Instant::now() + timeout;
    let mut last_len = 0usize;
    let mut stable = 0u32;
    loop {
        tokio::time::sleep(POLL).await;
        let len = captured.lock().unwrap().len();
        if len > 0 && len == last_len {
            stable += 1;
            if stable >= STABLE_POLLS {
                return captured.lock().unwrap().clone();
            }
        } else {
            stable = 0;
            last_len = len;
        }
        if std::time::Instant::now() > deadline {
            if last_len > 0 {
                return captured.lock().unwrap().clone();
            }
            panic!(
                "the mock webhook target never received a call from the real, admin-API-installed \
                 webrequest hook within {timeout:?}: the real install -> load -> invoke -> webhook \
                 chain did not complete"
            );
        }
    }
}

/// The 1.5.3 fan-out proof. `#[ignore]`-free and part of the normal `cargo test` run.
#[tokio::test(flavor = "multi_thread")]
async fn unscoped_hook_observes_every_core_stage() {
    let Some(busbar_bin) = busbar_bin() else {
        return; // logged above; CI already hard-panics instead of reaching here
    };
    let Some(cdylib_path) = webrequest_cdylib() else {
        return; // logged above; CI already hard-panics instead of reaching here
    };

    // --- 1. A genuinely signed tarball around the REAL built cdylib -----------------------------
    let lib_bytes = std::fs::read(&cdylib_path).expect("read webrequest cdylib");
    let (tarball, publisher_pubkey_hex) = build_signed_tarball(&lib_bytes);

    // --- 2. Mock targets: the webhook this hook forwards to, and the upstream model -------------
    let (webhook_url, captured) = mock_webhook().await;
    let upstream_base = mock_upstream().await;

    // --- 3. Generate a real config.yaml/providers.yaml and boot a real busbar process -----------
    let workdir = std::env::temp_dir().join(format!(
        "busbar-webrequest-stage-fanout-e2e-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&workdir);
    let plugins_dir = workdir.join("plugins");
    std::fs::create_dir_all(&plugins_dir).expect("create plugins dir");

    let data_port = free_port();
    let admin_port = free_port();
    let admin_addr = format!("127.0.0.1:{admin_port}");
    let admin_token = format!("stage-fanout-admin-token-{}", std::process::id());

    let providers_yaml = format!(
        r#"
mockup:
  protocol: anthropic
  base_url: "{upstream_base}"
  error_map: {{}}
"#
    );
    std::fs::write(workdir.join("providers.yaml"), providers_yaml).expect("write providers.yaml");

    // `auth.chain: []` (open relay) on purpose, and `admin-tokens` DEFINED once under
    // `identity-providers:` then REFERENCED by bare name from `auth.admin_auth` - busbar 1.5.3
    // retired the inline-module form and refuses to boot a config still carrying it.
    let config_yaml = format!(
        r#"
listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
identity-providers:
  admin-tokens: {{ module: admin-tokens, token: {{ env: BUSBAR_E2E_ADMIN_TOKEN }} }}
auth:
  chain: []
  signing_key: {{ env: BUSBAR_SIGNING_KEY }}
  admin_auth: [admin-tokens]
plugins:
  enabled: true
  dir: "{plugins_dir}"
  trust:
    publishers:
      - name: acme-e2e
        public_key: "{publisher_pubkey_hex}"
providers:
  mockup:
    api_key: {{ env: BUSBAR_E2E_UPSTREAM_KEY }}
models:
  m:
    provider: mockup
    max_concurrent: 5
    max_requests: -1
"#,
        plugins_dir = plugins_dir.display(),
    );
    std::fs::write(workdir.join("config.yaml"), config_yaml).expect("write config.yaml");

    let mut cmd = Command::new(&busbar_bin);
    cmd.env("BUSBAR_CONFIG", workdir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", workdir.join("providers.yaml"))
        .env("BUSBAR_E2E_ADMIN_TOKEN", &admin_token)
        .env("BUSBAR_E2E_UPSTREAM_KEY", "sk-e2e-fake-upstream-key")
        .env("BUSBAR_SIGNING_KEY", TEST_SIGNING_KEY)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn busbar");
    // Mirror the real busbar process's stdout/stderr onto this test's stderr, prefixed, so
    // `cargo test`'s capture shows them whenever this test fails.
    for (label, pipe) in [
        (
            "busbar/out",
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        ),
        (
            "busbar/err",
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        ),
    ] {
        if let Some(pipe) = pipe {
            std::thread::spawn(move || {
                use std::io::BufRead;
                for line in std::io::BufReader::new(pipe).lines().map_while(Result::ok) {
                    eprintln!("[{label}] {line}");
                }
            });
        }
    }
    let _busbar = BusbarProcess { child };

    wait_for_healthz(&admin_addr).await;

    let client = reqwest::Client::new();
    let admin = format!("http://{admin_addr}/api/v1/admin");

    // --- 4. POST the signed tarball to the REAL admin API ---------------------------------------
    let install_body = serde_json::json!({
        "file": "webrequest-stage-fanout.tar.gz",
        "tarball_b64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &tarball),
    });
    let resp = client
        .post(format!("{admin}/plugins"))
        .header("x-admin-token", &admin_token)
        .json(&install_body)
        .send()
        .await
        .expect("POST /plugins");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("install response json");
    assert_eq!(
        status, 201,
        "plugin install must return 201 Created, got {status}: {body}"
    );
    assert_eq!(
        body["trust"], "trusted",
        "a validly signed, allowlisted-publisher plugin must install as trusted: {body}"
    );

    // --- 5. Reload the plugin registry so the freshly installed tarball is actually loaded -------
    let resp = client
        .post(format!("{admin}/plugins/reload"))
        .header("x-admin-token", &admin_token)
        .send()
        .await
        .expect("POST /plugins/reload");
    assert!(
        resp.status().is_success(),
        "plugin reload must succeed: {}",
        resp.status()
    );

    // --- 6. Register an UNSCOPED global tap: NO `at:`, NO `phase:` ------------------------------
    // This is the whole point of the file. The omission is deliberate, not an oversight, and it is
    // the configuration an operator writes when they have not thought about stages at all. Under
    // busbar 1.5.3 that means the hook fires at every core stage rather than once per request (see
    // the CHANGELOG quote in this file's header). If either key is ever added here, this test stops
    // testing anything and the assertions below will say so rather than pass vacuously.
    let hook_body = serde_json::json!({
        "name": "webrequest-stage-fanout-tap",
        "config": {
            "kind": "tap",
            "plugin": "webrequest",
            "global": true,
            "prompt": "ro",
            "settings": { "url": webhook_url },
        }
    });
    let resp = client
        .post(format!("{admin}/hooks"))
        .header("x-admin-token", &admin_token)
        .json(&hook_body)
        .send()
        .await
        .expect("POST /hooks");
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(
        status, 201,
        "hook registration must return 201 Created, got {status}: {body}"
    );

    // --- 7. Drive a REAL data-plane request through the REAL router ------------------------------
    // Registering a hook with a CONTENT grant (`prompt: ro`) flips governance on even though
    // `auth.chain` is empty, so a real client request needs a real minted key.
    let resp = client
        .post(format!("{admin}/keys"))
        .header("x-admin-token", &admin_token)
        .json(&serde_json::json!({ "name": "stage-fanout-e2e-client" }))
        .send()
        .await
        .expect("POST /keys");
    let status = resp.status();
    let mint: serde_json::Value = resp.json().await.expect("mint key json");
    assert!(
        status.is_success(),
        "minting a client key must succeed: {status}: {mint}"
    );
    let client_key = mint["token"]
        .as_str()
        .unwrap_or_else(|| panic!("mint response carries no token: {mint}"))
        .to_string();

    let prompt_text = "hello from stage_fanout_e2e - prove the per-stage notify fan-out";
    let chat_body = serde_json::json!({
        "model": "m",
        "max_tokens": 16,
        "messages": [ { "role": "user", "content": prompt_text } ],
    });
    let resp = client
        .post(format!("http://127.0.0.1:{data_port}/m/v1/messages"))
        .header("x-api-key", &client_key)
        .json(&chat_body)
        .send()
        .await
        .expect("POST /m/v1/messages");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("chat response json");
    assert!(
        status.is_success(),
        "the real chat request must succeed (proves the request actually reached the mock \
         upstream and came back through busbar): {status}: {body}"
    );

    // --- 8. The fan-out assertions ---------------------------------------------------------------
    let received = settle_captured(&captured, Duration::from_secs(15)).await;

    // Every delivery is a `notify`. A tap is never asked to decide or transform, so an envelope
    // with any other `op` here would mean the engine routed the wrong message kind to a tap.
    for envelope in &received {
        assert_eq!(
            envelope["op"], "notify",
            "every stage delivery to a tap must be a notify: {envelope}"
        );
    }

    // Split by the presence of the top-level `stage` key. Its ABSENCE is what marks the
    // request-stage envelope: the engine omits `stage` entirely there (and on every gate payload),
    // which is what keeps the pre-1.5.3 request-stage wire byte-identical. Keying on presence, not
    // on a null or a sentinel `at` value, is exactly what the contract tells sidecar authors to do.
    let (staged, unstaged): (Vec<_>, Vec<_>) = received
        .iter()
        .partition(|e| e.get("stage").is_some_and(|s| !s.is_null()));

    assert_eq!(
        unstaged.len(),
        1,
        "exactly one stage-less (request-stage) envelope expected for one request: {received:?}"
    );

    let stages: BTreeSet<&str> = staged
        .iter()
        .filter_map(|e| e["stage"]["at"].as_str())
        .collect();
    let expected: BTreeSet<&str> = ["candidate", "routing", "response"].into_iter().collect();
    assert_eq!(
        stages, expected,
        "an unscoped hook must observe the candidate, routing and response stages (plus the \
         stage-less request envelope asserted above): {received:?}"
    );

    // One dispatch attempt against a one-member pool that answers 200: no failover, so exactly one
    // envelope per stage and four in total. Asserted AFTER the set comparison so a duplicate stage
    // is reported as a count mismatch here rather than being swallowed by the set dedup above.
    assert_eq!(
        received.len(),
        4,
        "one request, one successful dispatch attempt: one envelope per core stage: {received:?}"
    );

    // PROMPT CONTENT lands on the request stage and NOWHERE else. Stage taps are shape-only by
    // construction in the engine (`system`/`messages`/`user` are sent as absent regardless of the
    // hook's grant), so a `prompt: ro` hook does not receive content four times over. A sidecar
    // that screens or logs content keys off this envelope.
    let request_envelope = unstaged[0];
    assert!(
        request_envelope.to_string().contains(prompt_text),
        "the request-stage envelope must carry the real prompt content (granted via prompt: ro): \
         {request_envelope}"
    );
    for envelope in &staged {
        assert!(
            !envelope.to_string().contains(prompt_text),
            "a stage envelope must be shape-only and must never carry prompt content: {envelope}"
        );
        assert!(
            envelope["request"].get("messages").is_none(),
            "a stage envelope must omit `messages` entirely, not send it empty: {envelope}"
        );
        assert!(
            envelope["request"].get("user").is_none(),
            "a stage envelope must omit `user` entirely: {envelope}"
        );
        assert_eq!(
            envelope["candidates"],
            serde_json::json!([]),
            "a stage envelope carries no candidate projection: {envelope}"
        );
    }

    // The documented per-stage payload fields. These are what make each stage worth observing at
    // all: without them a stage notify is an empty ping.
    let by_stage = |at: &str| -> &serde_json::Value {
        staged
            .iter()
            .find(|e| e["stage"]["at"] == at)
            .unwrap_or_else(|| panic!("no `{at}` stage envelope in {received:?}"))
    };

    // `candidate`: the surviving candidate count after the decision reconcile. One member pool,
    // no gate restricted anything, so one candidate survived.
    assert_eq!(
        by_stage("candidate")["stage"]["remaining_candidates"],
        1,
        "the candidate stage reports the post-reconcile surviving candidate count"
    );

    // `routing`: the failover story for this dispatch attempt. First attempt, so `attempt_number`
    // is 1 and `previous_failure` is absent (there is no previous attempt to report).
    let routing = by_stage("routing");
    assert_eq!(
        routing["stage"]["attempt_number"], 1,
        "the first dispatch attempt is attempt_number 1: {routing}"
    );
    assert_eq!(
        routing["stage"]["model"], "m",
        "the routing stage names the DISPATCHED member: {routing}"
    );
    assert!(
        routing["stage"].get("previous_failure").is_none(),
        "there is no previous failure on the first attempt, so the field is absent: {routing}"
    );

    // `response`: the outcome. The upstream answered 200, and no gate rejected, so this is the
    // plain `ok` outcome rather than a synthetic `rejected_by_gate` / `rejected_by_auth`.
    let response = by_stage("response");
    assert_eq!(
        response["stage"]["outcome"], "ok",
        "a served 200 is the `ok` outcome: {response}"
    );
    assert_eq!(
        response["stage"]["status"], 200,
        "the response stage carries the real response status: {response}"
    );

    // THE JOIN KEY. Four separate POSTs are only usable if a sidecar can correlate them back to one
    // request, and `request.request_id` is the documented handle for that. If it ever varied per
    // stage, stage taps would be useless for audit and nothing else in this test would notice.
    let ids: BTreeSet<u64> = received
        .iter()
        .filter_map(|e| e["request"]["request_id"].as_u64())
        .collect();
    assert_eq!(
        ids.len(),
        1,
        "every stage envelope for one request must carry the SAME request_id join key: {received:?}"
    );

    let _ = std::fs::remove_dir_all(&workdir);
}
