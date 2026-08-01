# webrequest-hook

**v1.5.0.** The first-party, signed `kind: hook` plugin for
[busbar](https://getbusbar.com): a transparent HTTP forwarder that POSTs
each hook op envelope (`decide` / `transform` / `notify` / `configure` /
`describe` / `status`) to an operator-configured URL and returns the
capped JSON reply verbatim. Busbar's own `hooks::wire` normalizers parse
that reply, so this plugin is a pure network relay — it adds a hop, never
a second copy of the hook wire semantics.

It is a `cdylib` that implements busbar's `HookHandler` trait (via
[`busbar-plugin-sdk`](https://github.com/GetBusbar/busbarAI/tree/main/crates/plugin-sdk))
and is loaded in-process by busbar over the signed hybrid plugin ABI —
`dlopen`'d, not spawned as a separate process.

## What it is for

- **Migration** off the retired socket/webhook hook transport: point
  `settings.url` at the same service a `route: webhook` pool used and the
  wire is compatible (`{op, ...projection}` POST → a
  `{order|abstain|reject|restrict|rewrite}` reply).
- **Isolation** of untrusted hook logic: the untrusted brain runs
  *remotely* behind this trusted, signed, `dlopen`'d forwarder. The
  forwarder — not busbar core — owns the outbound HTTP call.

## The security stance

- **SSRF-guarded** (`src/net_guard.rs`): the configured URL is validated
  at `open`/`configure` — loopback sidecars are allowed; link-local /
  IMDS / RFC1918 / CGNAT / ULA / cloud-metadata / alternate-IPv4
  encodings are blocked; plaintext `http://` is permitted only to
  loopback.
- **Redirects disabled** on the client (`redirect::none`): a target
  cannot 30x-redirect the plugin to an internal host at runtime.
- **Tight timeouts**; the reply body is capped before allocation (64
  KiB) and depth-guarded before parse (127 levels — one below
  serde_json's own internal recursion limit, which binds first) — a
  hostile or buggy target can neither exhaust memory nor blow the
  stack.
- **Userinfo stripped** from every error string, so a `user:pass@`
  embedded in the operator's URL never reaches a logged error.
- **Grants are core-enforced, never plugin-driven**: this forwarder only
  relays whatever `payload` busbar core chose to project. Its signed
  manifest declares `needs` (the intent it must relay); core still sends
  content only if the operator also grants it.

See the doc comments at the top of [`src/lib.rs`](src/lib.rs) and
[`src/net_guard.rs`](src/net_guard.rs) for the full design rationale.

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs)), and — interim,
until [busbarAI](https://github.com/GetBusbar/busbarAI) ships publicly —
a sibling checkout of `busbarAI` at `../busbarAI` (see
[Dependencies](#dependencies) below).

```sh
cargo build --release      # cdylib: target/release/libbusbar_webrequest_hook_plugin.{so,dylib}
cargo test                 # unit tests + the end-to-end loader test (see tests/e2e.rs)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Dependencies

This crate depends on `busbar-plugin-sdk` (and, as dev-dependencies for
the end-to-end test, `busbar-plugin-loader` and `busbar-api`) from the
[busbarAI](https://github.com/GetBusbar/busbarAI) monorepo. Because
busbarAI is not yet public, `Cargo.toml` points at these as **local path
dependencies** (`../busbarAI/crates/...`), which means this repo expects
to be checked out as a sibling of `busbarAI`:

```
some-parent-dir/
├── busbarAI/
└── webrequest-hook/
```

This is an interim measure — once busbarAI ships publicly, these should
become git (pinned rev/tag) or crates.io dependencies instead. Grep
`Cargo.toml` for the `INTERIM` comments when doing that migration.

## Pack and sign

Once built, the cdylib is packed and signed like any other busbar plugin
— see
[`docs/plugins.md`](https://github.com/GetBusbar/busbarAI/blob/main/docs/plugins.md#signing-and-packaging)
in busbarAI for the full reference. In short:

```sh
BUSBAR_SIGN_KEY=<signing key> busbar-plugin-pack pack \
    --lib target/release/libbusbar_webrequest_hook_plugin.so \
    --name busbar-webrequest-hook-plugin --alias webrequest --kind hook \
    --version 1.5.0 --publisher busbar \
    --license Apache-2.0 \
    --needs-prompt rw --needs-user ro \
    --out busbar-webrequest-hook-plugin-1.5.0-x86_64-linux.tar.gz
```

`--needs-prompt` / `--needs-user` declare this plugin's grant intent in
the signed manifest — set them to whatever the deployment's hook
`prompt:`/`user:` grant requires; core enforces the actual projection, so
the plugin can never receive more than it declares. For local
development without a signing key, `busbar-plugin-pack pack
--allow-unsigned` produces a tarball busbar loads only under
`plugins.trust.allow_unsigned: true`.

Drop the resulting tarball into busbar's configured `plugins.dir` and
reference it as a hook module — see
[`docs/plugins.md`](https://github.com/GetBusbar/busbarAI/blob/main/docs/plugins.md#hook-plugins-kind-hook)
for the `hooks:` wiring (`kind: hook`, `settings: { url: ... }`).

## Config

| Setting | Required | Default | Notes |
|---|---|---|---|
| `url` | yes | — | The `https://` (or loopback `http://`) URL each hook op envelope is POSTed to. Validated against the SSRF guard at load and on every `configure` push; a committed push takes effect immediately (the next `decide`/`transform`/`notify` uses it), not only after a future plugin reload. |
| `timeout_ms` | no | `5000` | Per-op wall-clock timeout, clamped to `[1, 5000]` — cannot exceed the engine's reference hook budget, since a hook FFI call holds a process-wide permit until the blocking call returns (see `MAX_TIMEOUT_MS`'s doc comment in `src/lib.rs`). Independently pushable via `configure`, applied immediately. |

## Tests

`cargo test` runs both the pure unit tests (`src/lib.rs`, `src/net_guard.rs`
— SSRF predicates, reply parsing/depth guard, envelope shaping) and the
end-to-end test in `tests/e2e.rs`, which loads the *built* cdylib over
the real `busbar-plugin-loader` ABI seam against a local mock HTTP
target — the same seam busbar's engine uses, so it exercises the actual
`dlopen`/FFI path rather than calling Rust functions directly. Build
under `cargo test --workspace`-equivalent (i.e. a normal `cargo build`
first, or just `cargo test`, which builds the cdylib as part of the
test run) so the e2e test finds the library; it self-skips with a
message if the cdylib isn't present.
