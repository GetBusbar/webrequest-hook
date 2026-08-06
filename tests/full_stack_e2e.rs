// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REAL end-to-end proof: install THIS plugin over the REAL admin HTTP API into a REAL, running
//! `busbar` process, wire it into a REAL hook chain, drive a REAL data-plane request through the REAL
//! router, and confirm the REAL webhook target received the REAL HTTP round trip.
//!
//! `tests/e2e.rs` (the sibling file) proves the loader ABI seam — the cdylib loaded via
//! `busbar_plugin_loader::hook::load_hook_from_bytes` behind hand-rolled projectors standing in for
//! the engine's own `hooks::wire`. That is real coverage of the plugin's own contract, but it never
//! boots busbar itself, never touches `POST /api/v1/admin/plugins`, and never proves the engine's
//! REAL wire projection is what lands on the wire. This file closes that gap: it is the "installed
//! over api and actually tested" bar applied to a `kind: hook` plugin, mirroring the pattern
//! `GetBusbar/busbar/.github/workflows/plugin-ci.yml`'s INSTALL-AND-SERVE step already applies to
//! `kind: store` plugins (that step is gated `if: inputs.plugin_kind == 'store'` and does not cover
//! hooks at all, so the hook-shaped equivalent lives here, in this repo's own `cargo test`).
//!
//! The proof chain, all real:
//!   1. Build a genuinely SIGNED plugin tarball (ed25519, `busbar_plugin_sign::sign`, the exact
//!      function the release pipeline / `busbar-plugin-pack` uses) around the actual built cdylib.
//!   2. Boot a real `busbar` binary (built from the sibling `../busbarAI` checkout) against a
//!      generated `config.yaml`/`providers.yaml`, admin listener up, WITHOUT the plugin present.
//!   3. `POST /api/v1/admin/plugins` the signed tarball — confirm `201` + `trust: "trusted"`.
//!   4. `POST /api/v1/admin/plugins/reload` — confirm the plugin registry picks it up.
//!   5. `POST /api/v1/admin/hooks` — register a `global` tap naming this plugin's alias
//!      (`webrequest`), `settings.url` pointing at a local mock HTTP server standing in for the
//!      operator's webhook target (this repo's own established mocking convention — see
//!      `tests/e2e.rs`'s `mock_target`/`capturing_target`).
//!   6. `POST /{model}/v1/messages` — a real Anthropic-shaped chat request through the real router,
//!      against a real (mocked) upstream model.
//!   7. Confirm the mock webhook server received REAL POSTs with the REAL engine-built envelopes
//!      (`{"op":"notify", "request": {...}}`) carrying the real prompt text — the full round trip:
//!      real admin install -> real plugin load -> real hook invocation -> real webhook call. Since
//!      1.5.3 a tap that names no `phase:` fires at all FOUR core stages (request, candidate,
//!      routing, response), so ONE request produces FOUR calls sharing one `request.request_id`;
//!      the prompt text rides the REQUEST-stage payload.
//!
//! Requires the sibling `../busbarAI` checkout (same interim path-dependency convention as
//! `Cargo.toml`). The `busbar` binary is built on demand (cached under its own `target/`) the first
//! time this test runs; under CI this is a hard failure, not a silent skip — mirroring `tests/e2e.rs`'s
//! own `plugin_path()` CI-hard-fail discipline for the cdylib.

use axum::routing::post;
use axum::Router;
use busbar_plugin_sign::{HookNeeds, Manifest, NeedLevel, SigningKey};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Fixed ed25519 signing secret (64 hex = 32 bytes) for this e2e test. 1.5.1 requires an
/// explicit signing key to mint virtual keys; busbar no longer auto-generates one.
const TEST_SIGNING_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The sibling `busbarAI` monorepo checkout — same interim path convention as `Cargo.toml`'s
/// `busbar-plugin-sdk` dependency.
fn busbarai_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../busbarAI")
}

/// Locate (building on demand) the real `busbar` engine binary from the sibling checkout. This is a
/// SEPARATE Cargo workspace from this plugin repo — `cargo test` here has no automatic knowledge of
/// it — so unlike the cdylib (built as a byproduct of THIS crate's own `cargo test`), the binary is
/// built explicitly here, cached under the sibling's own `target/debug/`. Under CI a failed/missing
/// build is a hard panic, never a silent skip: this is the only proof in this repo that the plugin
/// actually installs and runs inside a real busbar process, so it must never quietly no-op.
fn busbar_bin() -> Option<PathBuf> {
    let root = busbarai_root();
    if !root.join("Cargo.toml").exists() {
        if std::env::var_os("CI").is_some() {
            panic!(
                "full_stack_e2e: sibling busbarAI checkout not found at {} under CI; refusing to \
                 silently skip the only real admin-API-install + real-hook-invocation coverage",
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
        eprintln!("full_stack_e2e: building the busbar binary from the sibling checkout (first run only)...");
        let status = Command::new("cargo")
            .args(["build", "--bin", "busbar"])
            .current_dir(&root)
            .status()
            .expect("run `cargo build --bin busbar` in the sibling checkout");
        if !status.success() || !bin.exists() {
            if std::env::var_os("CI").is_some() {
                panic!("full_stack_e2e: failed to build the busbar binary from the sibling checkout under CI");
            }
            eprintln!("skip: failed to build the busbar binary locally");
            return None;
        }
    }
    Some(bin)
}

/// Locate the built `webrequest` cdylib — identical logic to `tests/e2e.rs`'s `plugin_path()` (kept
/// as its own copy rather than shared: these are two independent integration-test binaries, and
/// duplicating this helper here is cheaper than inventing a `tests/common` module for it).
///
/// Checks BOTH the "uplifted" `<profile_dir>/<name>` copy (only refreshed when `[lib]` is a ROOT
/// build target, e.g. `cargo build --all-targets`) and the raw `<profile_dir>/deps/<name>` compiler
/// output (refreshed on every build that recompiles the lib) — see `tests/e2e.rs`'s `plugin_path()`
/// doc comment for the detail: a bare `cargo test` with no explicit prior build does NOT uplift the
/// top-level copy, so checking only that path finds nothing / something stale and this test silently
/// no-ops.
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
            "full_stack_e2e: the webrequest-hook plugin cdylib is not built under CI: `cargo test` \
             must build busbar_webrequest_hook_plugin (checked both the uplifted target dir and \
             target/deps)."
        );
    }
    candidate
}

/// Grab an ephemeral free TCP port by binding to port 0 and reading it back, then dropping the
/// listener. Small TOCTOU window (another process could grab it before busbar binds) — acceptable
/// for a test; a real collision would fail loudly (busbar refuses to boot / axum::serve errors),
/// never silently pass.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// A local mock HTTP server standing in for the operator's webhook target — the SAME mocking
/// convention `tests/e2e.rs` already uses (`capturing_target`), applied here against the REAL engine
/// wire instead of a hand-rolled projector. Captures every POSTed body (parsed as JSON) and always
/// replies `{}` (a `notify` reply is never read, but a hook op reply must still be valid JSON so a
/// stray `decide`/`transform` probe against this same URL wouldn't itself break the forwarder).
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
/// Messages response (same fixture shape busbar's own `hook_seam_tests.rs` uses), just enough for
/// busbar's ingress/egress translation to produce a real 200 back to our real client request.
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

/// Build a GENUINELY signed plugin tarball around `lib_bytes`, the exact way the release pipeline /
/// `busbar-plugin-pack` does (`busbar_plugin_sign::sign` + `busbar_plugin_loader::tarball::package`).
/// A fixed test-only signing key (deterministic, never used outside this process) — the point isn't
/// key secrecy, it's exercising the REAL signature-verification path (`plugins.trust.publishers`)
/// rather than the `allow_unsigned` escape hatch.
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
        description: "full_stack_e2e signed test tarball".to_string(),
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

/// Lowercase-hex encode — avoids pulling in a `hex` crate for one call site.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A child-process guard: always kill + reap `busbar` on drop (including on test panic/early
/// return via `?`/`assert!`), so a failing assertion never leaks a live busbar process holding
/// ports open for the rest of the test run.
struct BusbarProcess {
    child: Child,
}

impl Drop for BusbarProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Poll `GET /healthz` on the admin listener until it answers (or panic after a generous timeout —
/// a real process boot, not an in-memory router, so give it real wall-clock time).
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

/// THE full-stack proof. `#[ignore]`-free and part of the normal `cargo test` run: this is the
/// "prod ready" bar, not an opt-in extra.
#[tokio::test(flavor = "multi_thread")]
async fn install_over_admin_api_and_drive_a_real_hook_invocation() {
    let Some(busbar_bin) = busbar_bin() else {
        return; // logged above; CI already hard-panics instead of reaching here
    };
    let Some(cdylib_path) = webrequest_cdylib() else {
        return; // logged above; CI already hard-panics instead of reaching here
    };

    // ── 1. A genuinely signed tarball around the REAL built cdylib ──────────────────────────────
    let lib_bytes = std::fs::read(&cdylib_path).expect("read webrequest cdylib");
    let (tarball, publisher_pubkey_hex) = build_signed_tarball(&lib_bytes);

    // ── 2. Mock targets: the webhook this hook forwards to, and the upstream model ──────────────
    let (webhook_url, captured) = mock_webhook().await;
    let upstream_base = mock_upstream().await;

    // ── 3. Generate a real config.yaml/providers.yaml and boot a real busbar process ────────────
    let workdir = std::env::temp_dir().join(format!(
        "busbar-webrequest-full-stack-e2e-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&workdir);
    let plugins_dir = workdir.join("plugins");
    std::fs::create_dir_all(&plugins_dir).expect("create plugins dir");

    let data_port = free_port();
    let admin_port = free_port();
    let admin_addr = format!("127.0.0.1:{admin_port}");
    let admin_token = format!("e2e-admin-token-{}", std::process::id());

    let providers_yaml = format!(
        r#"
mockup:
  protocol: anthropic
  base_url: "{upstream_base}"
  error_map: {{}}
"#
    );
    std::fs::write(workdir.join("providers.yaml"), providers_yaml).expect("write providers.yaml");

    // `auth.chain: []` (open relay) on purpose: this test's whole point is the admin-install ->
    // plugin-load -> hook-invocation -> webhook round trip, not the client auth chain (covered
    // elsewhere in busbar's own suite) — narrowing scope here keeps the failure surface honest.
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
    // Mirror the real busbar process's own stdout/stderr onto THIS test's stderr, prefixed, on
    // background threads — `cargo test`'s default output capture then shows them automatically
    // whenever this test fails (and always under `--nocapture`), without any Drop-time plumbing.
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

    // ── 4. POST the signed tarball to the REAL admin API ────────────────────────────────────────
    let install_body = serde_json::json!({
        "file": "webrequest-e2e.tar.gz",
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
    assert_eq!(body["name"], "busbar-webrequest-hook-plugin");

    // ── 5. Reload the plugin registry so the freshly installed tarball is actually loaded ───────
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

    // NOTE: `GET /plugins?type=hooks` lists hook INSTANCES (registered hooks + the compiled-in
    // ranking strategies), not the `kind: hook` PLUGIN registry — there is no separate listing
    // endpoint for that. The real proof that reload picked up the plugin is the hook registration
    // below: `HookCfg.plugin` is resolved against the SAME validated plugin registry reload just
    // rebuilt, fail-closed on an unresolved name — so a 201 there is a stronger, FUNCTIONAL proof
    // than a listing row would be.

    // ── 6. Register a global hook naming this plugin, over the REAL admin API ───────────────────
    let hook_body = serde_json::json!({
        "name": "webrequest-e2e-tap",
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

    // ── 7. Drive a REAL data-plane request through the REAL router ──────────────────────────────
    // `auth.chain: []` is normally an open relay (no key needed) — but registering a hook with a
    // CONTENT grant (`prompt: ro` above) flips governance on regardless (confirmed by busbar's own
    // boot warning: "auth.chain is empty (open relay) with governance enabled: governance
    // supersedes the open-relay mode"), so a real client request now needs a real minted key. Mint
    // one over the admin API — the SAME `POST /api/v1/admin/keys` real operators use.
    let resp = client
        .post(format!("{admin}/keys"))
        .header("x-admin-token", &admin_token)
        .json(&serde_json::json!({ "name": "full-stack-e2e-client" }))
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

    let prompt_text = "hello from full_stack_e2e — prove the real webhook round trip";
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

    // ── 8. Confirm the mock webhook ACTUALLY received the real HTTP round trip ──────────────────
    // A `phase:`-less tap fires at ALL FOUR core stages (1.5.3: request, candidate, routing,
    // response — busbar's `CORE_HOOK_PHASES`, frozen so a later stage is strictly additive), so ONE
    // real request produces FOUR real webhook calls, not one. `response` is the last of them, so
    // waiting for it is what makes this poll deterministic rather than a race on whichever stage
    // happened to land first.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let received = loop {
        let snapshot = captured.lock().unwrap().clone();
        if snapshot.iter().any(|e| e["stage"]["at"] == "response") {
            break snapshot;
        }
        if std::time::Instant::now() > deadline {
            panic!(
                "the mock webhook target never received the full four-stage tap sequence from the \
                 real, admin-API-installed webrequest hook within 10s — the real install -> load \
                 -> invoke -> webhook chain did not complete. Got: {snapshot:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    // Every stage is a `notify` (a tap is never answered), whatever the stage.
    for envelope in &received {
        assert_eq!(
            envelope["op"], "notify",
            "the REAL engine wire envelope must carry the op discriminator: {envelope}"
        );
    }

    // All four core stages, exactly once each. The REQUEST stage is the one with NO `stage` key
    // (the pre-1.5.3 wire, kept byte-identical); the other three name themselves.
    let mut stages: Vec<&str> = received
        .iter()
        .map(|e| e["stage"]["at"].as_str().unwrap_or("request"))
        .collect();
    stages.sort_unstable();
    assert_eq!(
        stages,
        vec!["candidate", "request", "response", "routing"],
        "one real request must produce exactly the four core-stage taps: {received:?}"
    );

    // The 1.5.3 JOIN KEY: every stage of the same request carries the SAME `request.request_id`,
    // which is what lets a tap stitch a routing decision to its eventual outcome.
    let request_ids: std::collections::HashSet<u64> = received
        .iter()
        .map(|e| {
            e["request"]["request_id"]
                .as_u64()
                .unwrap_or_else(|| panic!("every tap payload must carry request_id: {e}"))
        })
        .collect();
    assert_eq!(
        request_ids.len(),
        1,
        "all four stage taps for ONE request must share ONE request_id: {received:?}"
    );

    // The real engine's own hook wire projection — not a hand-rolled test stub — actually carried
    // the real prompt text through to the real webhook target. Only the REQUEST-stage payload
    // carries the granted prompt; the stage taps project shape + stage, not content.
    let envelope = received
        .iter()
        .find(|e| e["stage"].is_null())
        .unwrap_or_else(|| panic!("no request-stage tap in {received:?}"));
    let envelope_text = envelope.to_string();
    assert!(
        envelope_text.contains(prompt_text),
        "the real webhook payload must carry the real prompt content (granted via prompt: ro): {envelope}"
    );

    let _ = std::fs::remove_dir_all(&workdir);
}
