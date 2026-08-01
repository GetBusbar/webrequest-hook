// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The first-party **`webrequest`** `kind: hook` plugin — a signed, trusted, dlopen'd HTTP forwarder.
//!
//! It is a `cdylib` that implements the SDK's [`HookHandler`] trait and, on each hook op
//! (`decide`/`transform`/`notify`/`configure`/`describe`/`status`), POSTs the op envelope to an
//! operator-configured URL and returns the capped JSON reply VERBATIM. The engine parses that reply
//! through its own fail-closed `hooks::wire` normalizers, so this forwarder is a transparent relay for
//! the hook wire contract — it adds a network hop, never a second copy of the reply semantics.
//!
//! ## What it is for
//!
//! - **Migration** off the retired socket/webhook hook transport: point `settings.url` at the same
//!   service a `route: webhook` pool used and the wire is compatible (`{op, ...projection}` POST → a
//!   `{order|abstain|reject|restrict|rewrite}` reply).
//! - **Isolation** of untrusted hook logic: the untrusted brain runs REMOTELY behind this trusted,
//!   signed, dlopen'd forwarder. The forwarder — not busbar core — owns the outbound HTTP call.
//!
//! ## The security stance
//!
//! - **SSRF**: the configured URL is validated at `open`/`configure` against [`net_guard`] — the same
//!   policy the old webhook hook used (loopback sidecars allowed; link-local / IMDS / RFC1918 / CGNAT /
//!   ULA / cloud-metadata / alternate-IPv4-encodings blocked; plaintext `http://` only to loopback).
//! - **Redirects disabled** on the client (`redirect::none`): a target cannot 30x-redirect us to an
//!   internal host at runtime.
//! - **Tight timeouts**; the response body is **capped before allocation** (a hostile target cannot
//!   drive unbounded allocation) and **depth-guarded** before parse (a deeply-nested reply cannot blow
//!   the stack on deserialize).
//! - **Userinfo stripped** from every error string: any `user:pass@` an operator embedded in the URL
//!   never reaches an error the engine might log.
//! - **Grants are CORE-enforced**, never plugin-driven: this forwarder only relays whatever `payload`
//!   the core chose to project. It cannot cause prompt/user content to be sent. Its signed manifest
//!   declares `needs` = the intent it must relay (a forwarder that must relay prompt content for a
//!   `prompt: rw` gate declares `needs.prompt = rw`); the core STILL sends content only if the operator
//!   also grants it. See the crate README / packaging notes for the recommended manifest `needs`.

mod net_guard;

use busbar_plugin_sdk::HookHandler;
use serde::Deserialize;
use std::sync::RwLock;
use std::time::Duration;

/// Maximum reply body accepted from the target, in bytes. Matches the old webhook transport's
/// `MAX_HOOK_REPLY_BYTES` (64 KiB) — the reply is a small ranking/verdict object, so a body past this
/// is a hostile/buggy target and is refused BEFORE the bytes are allocated.
const MAX_REPLY_BYTES: usize = 64 * 1024;

/// Maximum JSON nesting depth accepted in a reply. Matches busbar's `MAX_JSON_DEPTH` (128) — a security
/// floor, not a tunable. A reply deeper than this is refused before any `serde_json::Value` is built,
/// so it can neither be recursively deserialized nor recursively dropped (either overflows the stack).
const MAX_REPLY_DEPTH: usize = 128;

/// Default per-op wall-clock timeout when the operator does not set `timeout_ms`. Tight on purpose: a
/// gate is on the request path, so a slow target must fail fast (→ the engine coerces to `on_error`).
const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// Upper bound an operator-supplied `timeout_ms` is clamped to. Deliberately equal to
/// [`DEFAULT_TIMEOUT_MS`] — the engine's reference hook budget is 5s, and hook FFI calls are gated by
/// a process-wide, fixed-size semaphore permit that is released only when the blocking `busbar_call`
/// closure RETURNS, not when the caller gives up waiting on its own deadline. If this were allowed up
/// to (say) 60s, an operator setting a large `timeout_ms` would let one slow target hold a permit for
/// up to ~55s past every OTHER caller's deadline, starving hook execution process-wide for every other
/// plugin — a single misconfigured `webrequest` target should never be able to do that. Keeping the
/// ceiling at the reference hook budget means a fat-fingered large value can, at worst, make this
/// specific op run exactly as long as the engine already budgets for a hook, never past it.
const MAX_TIMEOUT_MS: u64 = DEFAULT_TIMEOUT_MS;

/// The plugin's `settings` config (the operator-owned `settings:` map the engine passes at `open`, and
/// re-pushes on `configure`).
#[derive(Deserialize, Default)]
struct Config {
    /// The target URL each op envelope is POSTed to. Validated against the SSRF guard at open/configure.
    url: String,
    /// Optional per-op wall-clock timeout override (milliseconds). Bounded to a sane ceiling so a
    /// fat-fingered huge value cannot make a gate hang the request path.
    #[serde(default)]
    timeout_ms: Option<u64>,
}

/// The forwarding target: a validated URL and its wall-clock timeout, taken together so `configure`
/// swaps both atomically (a caller never observes a new url paired with a stale timeout or vice versa).
struct LiveTarget {
    url: reqwest::Url,
    timeout: Duration,
}

impl LiveTarget {
    /// Validate a `Config` into a `LiveTarget`. Shared by `Forwarder::new` (the `open` path) and
    /// `configure` (the live-reconfigure path) so both apply IDENTICAL SSRF/timeout rules — see
    /// [`HookHandler::configure`]'s doc comment for why `configure` needs this too, not just `open`.
    fn validate(cfg: &Config) -> Result<Self, String> {
        if cfg.url.trim().is_empty() {
            return Err("webrequest: settings.url is required".to_string());
        }
        let url = net_guard::validate_target_url(&cfg.url)?;
        // Bound the operator timeout to [1ms, MAX_TIMEOUT_MS] — a gate that could block the request
        // path past the engine's own hook budget is a foot-gun (and a process-wide permit-starvation
        // hazard, see MAX_TIMEOUT_MS's doc comment), not a feature.
        let timeout_ms = cfg
            .timeout_ms
            .unwrap_or(DEFAULT_TIMEOUT_MS)
            .clamp(1, MAX_TIMEOUT_MS);
        Ok(Self {
            url,
            timeout: Duration::from_millis(timeout_ms),
        })
    }
}

/// The live forwarder: a validated target URL, its own `reqwest::Client` (redirect-disabled), and a
/// dedicated current-thread tokio runtime to drive the async HTTP call from the SYNC `HookHandler`
/// methods (the engine already runs each `busbar_call` on its own `spawn_blocking` thread, so blocking
/// here never touches the engine's runtime workers).
struct Forwarder {
    // `RwLock`, not a plain field: `configure` (see its doc comment) REPLACES this on a committed
    // settings push, and `post_op`/`status` read it on every call from potentially-concurrent
    // `spawn_blocking` threads (the engine gates up to `MAX_INFLIGHT_HOOK_CALLS` calls in flight at
    // once). Read-mostly (many decide/transform/notify readers, an occasional configure writer), so a
    // `RwLock` over a `Mutex`. A poisoned lock (a panic while holding the write half, which nothing in
    // the critical section below can actually cause) is recovered from rather than propagated — a
    // long-lived singleton plugin instance must not brick itself for its remaining lifetime over a
    // panic in an unrelated call.
    live: RwLock<LiveTarget>,
    client: reqwest::Client,
    // Wrapped in `Option` SOLELY so `Drop` can move the runtime out and shut it down NON-blockingly.
    // A bare `tokio::runtime::Runtime` dropped in place runs its blocking `Drop`, which PANICS when
    // the drop happens on a tokio worker thread ("Cannot drop a runtime in a context where blocking
    // is not allowed"). On a hot config reload the last `Arc<App>` — and thus this forwarder via the
    // SDK's `hook_close` → plugin drop chain — can drop on an async thread, so that panic would fire,
    // be caught by the SDK's `ffi_guard`, and LEAK the runtime + reqwest client every reload. Instead
    // `Drop` takes the runtime and calls `shutdown_background()`, which never blocks. Always `Some`
    // between construction and drop.
    //
    // KNOWN HAZARD (documented, not fixed here): `shutdown_background()` detaches teardown onto a
    // background thread and returns immediately — `Drop` does not wait for that thread to finish. If
    // the engine ever `dlclose`s this cdylib right after dropping the last `Forwarder` (rather than
    // only at process exit), that detached thread can end up executing code/vtables that belonged to
    // the now-unloaded library — a use-after-free-adjacent hazard. A bounded join (or a shutdown flag
    // plus a short blocking join) would close this, but doing so safely requires either joining from a
    // context where blocking is provably allowed (the whole reason `shutdown_background` is used here
    // instead of a blocking `Runtime::drop` is that `Drop` can run on a tokio worker thread where
    // blocking is FORBIDDEN and would panic — see above) or restructuring how/where teardown happens.
    // That's a deeper change than this fix pass attempts; flagged here for whoever next touches
    // reload/unload behavior, and tracked as a known LOW-probability (dlclose-on-hot-reload is not
    // this loader's current behavior) but real hazard if that ever changes.
    rt: Option<tokio::runtime::Runtime>,
}

impl Drop for Forwarder {
    /// Shut the owned runtime down WITHOUT blocking, so dropping the forwarder on a tokio worker
    /// thread (the hot-reload path — see the `rt` field doc) can never panic. `shutdown_background`
    /// drops the runtime's driver on a detached thread rather than blocking-joining its workers here,
    /// which is exactly what a blocking `Runtime::drop` in an async context is forbidden from doing.
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

impl Forwarder {
    /// Build a forwarder from validated config. Fails closed if the URL is missing, malformed, blocked
    /// by the SSRF guard, or the client/runtime cannot be built.
    fn new(cfg: Config) -> Result<Self, String> {
        let target = LiveTarget::validate(&cfg)?;
        let client = reqwest::Client::builder()
            // Disable redirects so a target cannot 30x us onto an internal host at runtime (the
            // validated URL only guarantees the FIRST hop is safe).
            .redirect(reqwest::redirect::Policy::none())
            // Pinned to the OPEN-time timeout, not re-read on a later `configure` (see `configure`'s doc
            // comment): this only bounds the connect sub-phase, and the per-request `.timeout(...)` in
            // `post_op` (which DOES read the live, possibly-reconfigured value on every call) always
            // bounds the whole request at or under it. A connect_timeout that is stale-high is a no-op
            // (the smaller per-request timeout still cuts the call off on schedule); stale-low only makes
            // the connect sub-phase fail slightly earlier than a later, larger configured timeout would
            // strictly require — never a foot-gun in either direction, so rebuilding the client (and
            // losing its warm connection pool) on every `configure` push is not needed to stay correct.
            .connect_timeout(target.timeout)
            .build()
            .map_err(|e| format!("webrequest: failed to build HTTP client: {e}"))?;
        // A current-thread runtime is enough: one blocking op at a time per engine spawn_blocking call.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("webrequest: failed to build async runtime: {e}"))?;
        Ok(Self {
            live: RwLock::new(target),
            client,
            rt: Some(rt),
        })
    }

    /// POST the `op` envelope (the engine's `payload` projection plus the `op` discriminator) to the
    /// target and return the parsed reply `Value`. Bounded by `timeout`, redirect-disabled, body capped
    /// before allocation and depth-guarded before parse. Any error is a stable, userinfo-masked string —
    /// the caller degrades it to the safe reply for the op (the engine then fails open/closed exactly as
    /// it does for the retired transports).
    ///
    /// Serializes straight from the borrowed `payload` via [`Envelope`]'s hand-written `Serialize`
    /// rather than first cloning it into an owned `Map` just to splice in the `op` key — this runs on
    /// every `decide`/`transform`/`notify` call on the request hot path, so avoiding a full deep clone
    /// of the (potentially prompt-carrying) projected payload on every call is worth the small amount of
    /// hand-written serialization code.
    fn post_op(&self, op: &str, payload: &serde_json::Value) -> Result<serde_json::Value, String> {
        let body = serde_json::to_vec(&Envelope { op, payload })
            .map_err(|e| format!("webrequest: failed to serialize op envelope: {e}"))?;
        // Read the LIVE (possibly `configure`-updated) target ONCE, under a single lock acquisition, so
        // a settings push that commits mid-call can never tear this request across an old url paired
        // with a new timeout (or vice versa). Snapshotted outside `block_on`'s async block so the lock
        // is never held across an await point.
        let (target_url, target_timeout) = {
            let live = read_live(&self.live);
            (live.url.clone(), live.timeout)
        };
        // Safe: `rt` is `Some` for the whole lifetime between `new` and `Drop` (only `Drop` takes it).
        let rt = self
            .rt
            .as_ref()
            .expect("forwarder runtime present until drop");
        rt.block_on(async {
            // `.without_url()` on every reqwest error: a reqwest error's Display carries the request URL
            // WITH any embedded `user:pass@` userinfo. This error can reach operator logs, so the URL is
            // stripped before it is formatted. Parity with the old webhook hardening.
            let resp = self
                .client
                .post(target_url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
                .timeout(target_timeout)
                .send()
                .await
                .map_err(|e| format!("webrequest: request failed: {}", e.without_url()))?;
            let resp = resp.error_for_status().map_err(|e| {
                format!(
                    "webrequest: target returned an error status: {}",
                    e.without_url()
                )
            })?;
            let buf = read_capped(resp).await?;
            parse_reply(&buf)
        })
    }
}

/// Read `live`, recovering from a poisoned lock rather than panicking: nothing in either critical
/// section (a field clone/read, a plain field assignment) can itself panic, so poisoning here would only
/// ever come from an unrelated bug; propagating it would brick this long-lived singleton's routing for
/// the rest of the process's life over a panic that had nothing to do with the target it guards.
fn read_live(live: &RwLock<LiveTarget>) -> std::sync::RwLockReadGuard<'_, LiveTarget> {
    live.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Write `live`, recovering from a poisoned lock — see [`read_live`].
fn write_live(live: &RwLock<LiveTarget>) -> std::sync::RwLockWriteGuard<'_, LiveTarget> {
    live.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Read a response body under the [`MAX_REPLY_BYTES`] cap, ABORTING (rather than allocating) once the
/// cap is exceeded. Chunk-read errors are userinfo-masked (`.without_url()`).
async fn read_capped(mut resp: reqwest::Response) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("webrequest: response read failed: {}", e.without_url()))?
    {
        if buf.len() + chunk.len() > MAX_REPLY_BYTES {
            return Err(format!(
                "webrequest: response exceeded {MAX_REPLY_BYTES} byte cap"
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Parse a reply body into a `Value`, rejecting a pathologically-nested body BEFORE building the
/// `Value` (see [`MAX_REPLY_DEPTH`]). The parse-error path is LENGTH-ONLY: a target that echoed granted
/// prompt content into a malformed reply must not splash it into an error the engine might log.
fn parse_reply(bytes: &[u8]) -> Result<serde_json::Value, String> {
    if exceeds_max_depth(bytes, MAX_REPLY_DEPTH) {
        return Err(format!(
            "webrequest: reply exceeded max nesting depth ({} bytes)",
            bytes.len()
        ));
    }
    serde_json::from_slice(bytes)
        .map_err(|_| format!("webrequest: invalid JSON reply ({} bytes)", bytes.len()))
}

/// Single-pass, string-aware scan for the maximum `{`/`[` nesting depth in `bytes`. Brackets inside
/// JSON string literals (and `\`-escaped quotes) do not count. Short-circuits once `max` is exceeded.
/// Copied from busbar's `json::exceeds_max_depth` (the plugin must not dep on busbar core).
fn exceeds_max_depth(bytes: &[u8], max: usize) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// The POST envelope for a per-request op: the engine's opaque `payload` projection (BORROWED, not
/// cloned) with an `op` discriminator merged in on the wire, mirroring the old webhook wire (`{op,
/// request, candidates, context, ...}`). The projection is carried through UNCHANGED — the forwarder
/// never inspects or mutates it, so any opt-in `prompt`/`user` keys the CORE granted ride straight
/// through to the target. `Serialize` is hand-written (see impl below) so `post_op` can serialize
/// straight from `&Forwarder`'s borrowed `payload` reference without first cloning it into an owned
/// `Map` just to splice in `op` — see [`Forwarder::post_op`]'s doc comment for why that matters.
struct Envelope<'a> {
    op: &'a str,
    payload: &'a serde_json::Value,
}

impl serde::Serialize for Envelope<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        match self.payload {
            serde_json::Value::Object(m) => {
                let mut map = serializer.serialize_map(Some(m.len() + 1))?;
                // The `op` discriminator always wins: if the projection itself ever carries a
                // top-level `op` key (a future wire change, an operator-visible passthrough field),
                // skip it here rather than emitting it twice — a duplicate JSON key is ambiguous on
                // the wire (some parsers keep the first occurrence, some the last), and this crate's
                // own `op` must be the one the target sees, matching v1.0.0's `request_envelope`
                // (`obj.insert("op", ...)`, which overwrote rather than duplicated).
                for (k, v) in m.iter().filter(|(k, _)| k.as_str() != "op") {
                    map.serialize_entry(k, v)?;
                }
                map.serialize_entry("op", self.op)?;
                map.end()
            }
            // A non-object projection is unexpected, but relay it under a `payload` key rather than
            // dropping it.
            other => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("payload", other)?;
                map.serialize_entry("op", self.op)?;
                map.end()
            }
        }
    }
}

/// Build the POST envelope for a per-request op as an OWNED [`serde_json::Value`] — the same wire shape
/// [`Envelope`] serializes, used where an owned/indexable `Value` is actually wanted (currently: the
/// unit test asserting the envelope's shape). NOT on the hot per-call path; see [`Envelope`] for that.
#[cfg(test)]
fn request_envelope(op: &str, payload: &serde_json::Value) -> serde_json::Value {
    serde_json::to_value(Envelope { op, payload }).expect("envelope always serializes")
}

impl HookHandler for Forwarder {
    /// `decide` — POST the projection, return the reply verbatim. On any transport/parse error, return
    /// `{}` (abstain): the engine's normalizer maps that to `Abstain`, and the fail-closed
    /// on_error/on_empty chain takes over — the retired webhook's "no opinion on error" guarantee.
    fn decide(&self, payload: &serde_json::Value) -> serde_json::Value {
        match self.post_op("decide", payload) {
            Ok(reply) => reply,
            Err(_) => serde_json::json!({}),
        }
    }

    /// `transform` — POST the projection, return the reply verbatim. On error return `{}` (abstain →
    /// proceed with the ORIGINAL body); a parsed `reject` in the reply is honored by the engine.
    fn transform(&self, payload: &serde_json::Value) -> serde_json::Value {
        match self.post_op("transform", payload) {
            Ok(reply) => reply,
            Err(_) => serde_json::json!({}),
        }
    }

    /// `notify` — fire-and-forget POST of the tap projection. The reply is not read and every error is
    /// swallowed: a tap can NEVER delay or fail the served request.
    fn notify(&self, payload: &serde_json::Value) {
        let _ = self.post_op("notify", payload);
    }

    /// `configure` — RE-VALIDATE the (possibly changed) `settings.url`/`settings.timeout_ms` and, if
    /// valid, COMMIT them as the live target before ACKing. Busbar's own contract for this op is
    /// "commit on ack" (`docs/admin-api.md`'s `PATCH /hooks/{name}/settings`: only a version-echoing ACK
    /// commits the push, and nothing there scopes hook settings as restart-to-apply the way `store` is) —
    /// so an ACK that left the forwarder still POSTing to the OLD target would silently break that
    /// contract: the operator's PATCH would report success while every request kept routing to whatever
    /// was configured at `open`, until an unrelated future plugin reload happened to pick the change up.
    /// Each key is independently optional (an absent key means "leave the live value alone", matching a
    /// push that only changes one of `url`/`timeout_ms`); a key that IS present but fails validation (a
    /// wrong type or an SSRF-blocked url) NACKs the WHOLE push and commits neither, so a bad `timeout_ms`
    /// can never slip a validated `url` through partially-applied, or vice versa.
    fn configure(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
        _settings_version: u64,
    ) -> bool {
        let new_url = match settings.get("url") {
            None => None,
            // Present but not a string (e.g. a templating bug renders it as a number or null) is a
            // malformed push, not an absent one — treating the two identically would silently ACK a
            // garbage config with no NACK signal for the operator to notice. NACK it explicitly.
            Some(v) if v.as_str().is_none() => {
                eprintln!("webrequest: configure() rejected: settings.url is present but not a string ({v})");
                return false;
            }
            Some(v) => match net_guard::validate_target_url(v.as_str().expect("checked above")) {
                Ok(url) => Some(url),
                Err(reason) => {
                    // The `HookHandler::configure` ABI contract is a bare `bool` ACK/NACK — there is no
                    // return-message channel to thread the specific (already userinfo-masked) rejection
                    // reason back to the operator through. This crate has no logging dependency (no
                    // `log`/`tracing`, and the plugin-sdk exposes no host-side log bridge either) to add
                    // one for; `eprintln!` to stderr is the only zero-dependency way to make the reason
                    // discoverable rather than silently dropping it, so an operator whose reconfigure
                    // NACKs at least has somewhere to look.
                    eprintln!("webrequest: configure() rejected: {reason}");
                    return false;
                }
            },
        };
        let new_timeout = match settings.get("timeout_ms") {
            None => None,
            // Same present-but-wrong-typed NACK rule as `url` above — `as_u64()` also correctly rejects
            // a negative number, which JSON permits but a millisecond duration cannot represent.
            Some(v) => match v.as_u64() {
                Some(ms) => Some(Duration::from_millis(ms.clamp(1, MAX_TIMEOUT_MS))),
                None => {
                    eprintln!(
                        "webrequest: configure() rejected: settings.timeout_ms is present but not a non-negative integer ({v})"
                    );
                    return false;
                }
            },
        };
        if new_url.is_none() && new_timeout.is_none() {
            return true; // Nothing pushed that changes the live target — ACK, nothing to commit.
        }
        let mut live = write_live(&self.live);
        if let Some(url) = new_url {
            live.url = url;
        }
        if let Some(timeout) = new_timeout {
            live.timeout = timeout;
        }
        true
    }

    /// `describe` — the forwarder's OWN self-description envelope. It does not proxy `describe` to the
    /// target (the schema is the forwarder's config schema: `url` + `timeout_ms`).
    fn describe(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": {
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The https:// (or loopback http://) URL each hook op envelope is POSTed to."
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "description": "Per-op wall-clock timeout in milliseconds (default 5000, clamped to [1, 5000] — cannot exceed the engine's reference hook budget)."
                    }
                }
            }
        })
    }

    /// `status` — the forwarder's OWN observed state (it reports the target host it forwards to and its
    /// timeout; it does not proxy `status` to the target, which may not implement it). No prompt/user
    /// content is ever surfaced here.
    fn status(&self) -> serde_json::Value {
        let live = read_live(&self.live);
        serde_json::json!({
            "status": {
                "settings": {
                    // Host only (no path/query/userinfo) — enough for an operator to see WHERE it forwards.
                    "target_host": live.url.host_str().unwrap_or(""),
                    "timeout_ms": live.timeout.as_millis() as u64
                },
                "metrics": []
            }
        })
    }
}

/// Construct the forwarder from the engine-passed JSON config (the `settings:` map). An empty/missing
/// URL, a malformed config, or an SSRF-blocked URL is a fail-closed LOAD error — never a live forwarder
/// that could be pointed at an internal target.
fn open(cfg: &str) -> Result<Box<dyn HookHandler>, String> {
    let config: Config = if cfg.trim().is_empty() {
        Config::default()
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("webrequest: invalid plugin config: {e}"))?
    };
    Ok(Box::new(Forwarder::new(config)?))
}

busbar_plugin_sdk::export_hook_plugin!(open);

#[cfg(test)]
mod tests;
