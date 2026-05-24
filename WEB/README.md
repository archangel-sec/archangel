# archangel-web

The marketing / documentation site for the **archangel** package — a humble,
nginx/apache-docs-style site with help, docs, and `.deb`/`.rpm` downloads.

Built with **Leptos (SSR)** + **Axum**. It renders HTML on the server (no
WASM / hydration — a package site is content and downloads), so it builds with
plain `cargo`, no `cargo-leptos`/`trunk`/wasm toolchain needed.

## Why it lives here but is a separate project

`./WEB` is a **standalone Cargo project**, intentionally **excluded** from the
archangel workspace (`exclude = ["WEB"]` in the root `Cargo.toml`). The
archangel daemon/executor are the security TCB — strict lints,
`forbid(unsafe_code)`, `cargo deny/audit`, MSRV policy. The website carries
frontend dependencies that must never enter that audit surface. Keeping it
isolated means it has its own `Cargo.lock` and release cadence; moving it to
its own repo later is a `git mv` away.

## Run it

```sh
cd WEB
cargo run                       # http://127.0.0.1:8080
ARCHANGEL_WEB_ADDR=0.0.0.0:8080 cargo run --release   # bind elsewhere
```

## Serve the downloads

The download buttons link to `/dist/<file>`. Drop the built packages into
`WEB/dist/` and the links go live:

```sh
# from the repo root, after building the packages:
cp target/debian/archangel*_0.4.0-1_amd64.deb        WEB/dist/
cp target/generate-rpm/archangel-0.4.0-1.x86_64.rpm  WEB/dist/   # path per cargo-generate-rpm
```

If `WEB/dist/` is empty the buttons return 404 and the Downloads page tells
visitors to build from source — honest by default.

## Layout

```
WEB/
  Cargo.toml          # standalone; not a workspace member
  src/main.rs         # Axum server + Leptos SSR pages
  static/
    style.css         # the (single, humble) stylesheet
    logo.jpg          # the package icon (favicon + brand)
  dist/               # drop built .deb/.rpm here to serve them
```

## Routes

`/` home · `/features` defense layers · `/install` · `/docs` ·
`/downloads` · `/static/*` assets · `/dist/*` packages.

## Notes

- Content is intentionally aligned with the repo docs (threat model,
  architecture, sandbox, egress, readiness) and links to them on GitHub.
- The pre-alpha "do not run in production" notice is shown on every page by
  design — it must not be removed while the v1.0 gates (external audit, etc.)
  are unmet.
- The logo (`static/logo.jpg`) is used as-is as the brand/icon; no separate
  wordmark banner is rendered. Replace the file to rebrand.
