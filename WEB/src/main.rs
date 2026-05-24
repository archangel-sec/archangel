//! archangel-web — the package's marketing/documentation site.
//!
//! Leptos **SSR** (server-rendered HTML, no WASM/hydration — a package site is
//! content + downloads) served by Axum. Deliberately a standalone Cargo
//! project, NOT a member of the archangel security workspace: its frontend
//! dependencies must never enter the audited TCB.

use axum::{response::Html, routing::get, Router};
use leptos::prelude::*;
use tower_http::services::ServeDir;

const VERSION: &str = "0.4.0";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let app = Router::new()
        .route("/", get(|| page("home", home())))
        .route("/features", get(|| page("features", features())))
        .route("/install", get(|| page("install", install())))
        .route("/docs", get(|| page("docs", docs())))
        .route("/downloads", get(|| page("downloads", downloads())))
        // Static assets (logo, stylesheet) and built packages (drop .deb/.rpm
        // into WEB/dist to make the download buttons live).
        .nest_service("/static", ServeDir::new("static"))
        .nest_service("/dist", ServeDir::new("dist"));

    let addr = std::env::var("ARCHANGEL_WEB_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    tracing::info!("archangel-web listening on http://{addr}");
    axum::serve(listener, app).await.expect("serve");
}

/// Render a page body inside the shared shell and full HTML document.
async fn page(active: &'static str, content_view: impl IntoView + 'static) -> Html<String> {
    let body = shell(active, content_view).to_html();
    Html(document(body))
}

/// Doctype + head + the rendered body. The head is templated (it is outside
/// the reactive view); the body comes from Leptos SSR.
fn document(body: String) -> String {
    format!(
        "<!DOCTYPE html>\n\
         <html lang=\"en\">\n\
         <head>\n\
         <meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"description\" content=\"archangel — AI-driven Linux administration, security-first. Pre-alpha.\">\n\
         <title>archangel</title>\n\
         <link rel=\"icon\" href=\"/static/logo.jpg\">\n\
         <link rel=\"stylesheet\" href=\"/static/style.css\">\n\
         </head>\n\
         <body>{body}</body>\n\
         </html>\n"
    )
}

/// Header (logo + nav) + the pre-alpha banner + main content + footer.
fn shell(active: &'static str, content: impl IntoView) -> impl IntoView {
    let link = move |href: &'static str, label: &'static str, key: &'static str| {
        let class = if key == active { "nav-link active" } else { "nav-link" };
        view! { <a href=href class=class>{label}</a> }
    };
    view! {
        <header class="site-header">
            <a class="brand" href="/">
                <img src="/static/logo.jpg" alt="archangel" class="brand-logo"/>
                <span class="brand-name">"archangel"</span>
            </a>
            <nav class="site-nav">
                {link("/", "Home", "home")}
                {link("/features", "Features", "features")}
                {link("/install", "Install", "install")}
                {link("/docs", "Docs", "docs")}
                {link("/downloads", "Downloads", "downloads")}
            </nav>
        </header>
        <div class="banner" role="note">
            <strong>"Pre-alpha (v"{VERSION}")."</strong>
            " Do not run in production. No external security audit yet — see "
            <a href="/docs">"the readiness notes"</a>"."
        </div>
        <main class="content">{content}</main>
        <footer class="site-footer">
            <span>"archangel v"{VERSION}" · Apache-2.0"</span>
            <span>
                <a href="https://github.com/archangel-sec/archangel">"source"</a>
                " · it never bypasses its own security gates"
            </span>
        </footer>
    }
}

fn home() -> impl IntoView {
    view! {
        <section class="hero">
            <img src="/static/logo.jpg" alt="" class="hero-logo"/>
            <h1>"AI-driven Linux administration, security-first"</h1>
            <p class="lead">
                "archangel lets a language model observe, propose, and — under strict, \
                 layered policy — execute administrative actions on a Linux host. Every \
                 byte of model output is treated as untrusted by construction."
            </p>
            <div class="cta">
                <a class="btn primary" href="/install">"Install"</a>
                <a class="btn" href="/downloads">"Downloads"</a>
                <a class="btn ghost" href="https://github.com/archangel-sec/archangel">"Source"</a>
            </div>
        </section>

        <section class="card-row">
            <article class="card">
                <h3>"Three modes"</h3>
                <p>"read-only inspection · interactive (you approve each action) · autonomous (bounded by policy)."</p>
            </article>
            <article class="card">
                <h3>"Privilege separation"</h3>
                <p>"An LLM-facing daemon that never mutates, and a tiny executor that is the only thing that can."</p>
            </article>
            <article class="card">
                <h3>"Fail-closed"</h3>
                <p>"No snapshot, no sandbox, no rate budget, or read-only mode? The action is refused, never run."</p>
            </article>
        </section>

        <section>
            <h2>"What the model can never do unchecked"</h2>
            <p>"Every action it can take is bounded by:"</p>
            <ul class="checks">
                <li>"a signed, declarative " <code>".exec"</code> " bundle with an argument schema and sandbox profile;"</li>
                <li>"an immutable, compiled " <strong>"denylist"</strong> " that rejects anything that could destroy the host, sever SSH, or modify archangel itself;"</li>
                <li>"a per-action " <strong>"seccomp + cgroup sandbox"</strong> " (network, mount, ptrace, module-load and fs-mutation syscalls are fatal);"</li>
                <li>"a filesystem " <strong>"snapshot"</strong> " before any persistent change;"</li>
                <li>"host-wide " <strong>"rate limits"</strong> ", a tamper-evident " <strong>"hash-chained audit log"</strong> ", and a kernel " <strong>"egress allowlist"</strong> "."</li>
            </ul>
        </section>
    }
}

fn features() -> impl IntoView {
    let layer = |n: &'static str, title: &'static str, desc: &'static str| {
        view! {
            <article class="layer">
                <span class="layer-n">{n}</span>
                <div><h3>{title}</h3><p>{desc}</p></div>
            </article>
        }
    };
    view! {
        <h1>"Defense layers"</h1>
        <p class="lead">
            "archangel is built as defense in depth: an attacker (or a confused model) \
             has to defeat every layer, and each one fails closed."
        </p>
        <div class="layers">
            {layer("1–5", "Prompt-injection defenses", "Defensive system prompt, spotlighting untrusted content behind per-session random delimiters, a canary that aborts on leak, per-task isolation, and bounded structured output. Exercised by a red-team corpus in CI (#18).")}
            {layer("6–7", "Signed action bundles", "Actions are operator-signed .exec bundles with a declared argument schema; the daemon and executor both re-verify the signature.")}
            {layer("8–9", "Denylist + allowlist", "An immutable compiled denylist (linear-time, anti-ReDoS) plus a per-profile allowlist; deny-first.")}
            {layer("10", "Privilege separation", "T3 daemon talks to the model and never mutates; T2 executor is the only mutator, behind a 0600 socket with peer-credential + per-request signature checks.")}
            {layer("11", "Per-action sandbox", "seccomp-bpf syscall allowlist (kill on mismatch), capability drop, and cgroup v2 cpu/memory limits — the project's single audited unsafe block.")}
            {layer("12", "Rate limits", "Host-wide sliding-window ceilings on total / mutating / critical actions, enforced by the executor.")}
            {layer("13–14", "Approval + two-person", "Interactive mode requires human approval per action; critical-risk actions require two independent operator signatures.")}
            {layer("15", "Audit log", "Append-only, hash-chained, Ed25519-signed record of every decision and action.")}
            {layer("16", "Snapshots", "A filesystem recovery point is taken before any persistent mutation, or the action is refused.")}
            {layer("17", "Egress allowlist", "A fail-closed egress policy compiled to a kernel-enforced systemd filter, so exfiltration is structurally bounded.")}
            {layer("T6", "Hostile logs", "Logs the model reads in autonomous mode are treated as attacker-controlled input: bounded, rate-limited, and spotlighted.")}
        </div>
    }
}

fn install() -> impl IntoView {
    view! {
        <h1>"Install"</h1>
        <p class="lead">"No distribution packages yet — build the DEB/RPM from source. RPM-based and DEB-based distributions are the supported targets."</p>

        <h2>"Prerequisites"</h2>
        <ul>
            <li>"A recent stable Rust toolchain and " <code>"cargo"</code> "."</li>
            <li>"For DEB: " <code>"cargo install cargo-deb"</code> ". For RPM: " <code>"cargo install cargo-generate-rpm"</code> "."</li>
            <li>"A Linux host with systemd and cgroup v2 (the executor sandboxes per action)."</li>
        </ul>

        <h2>"Build the packages"</h2>
        <pre><code>{"cargo build --release\nfor p in archangeld archangel-execd archangelctl archangel; do\n  cargo deb --no-build -p \"$p\"\ndone"}</code></pre>

        <h2>"Three-step setup"</h2>
        <pre><code>{"sudo dpkg -i ./target/debian/archangel*_0.4.0-1_amd64.deb\nsudo archangel setup --backend ollama        # or: --backend anthropic\nsudo systemctl enable --now archangel-execd archangeld"}</code></pre>
        <p>
            <code>"archangel setup"</code>
            " is idempotent and fail-closed: it creates the operator key, trust store, a \
             read-only allowlist, and a schema-validated config, and never overwrites an \
             existing one. The LLM token is read from a no-echo prompt (never on argv) and \
             written 0600. Start in "<code>"read_only"</code>"; opt into mutation or \
             autonomous monitoring deliberately."
        </p>
        <p class="note">"Full configuration reference: see the Docs page and the configuration guide (.docx)."</p>
    }
}

fn docs() -> impl IntoView {
    let doc = |href: String, title: &'static str, desc: &'static str| {
        view! {
            <article class="card">
                <h3><a href=href>{title}</a></h3>
                <p>{desc}</p>
            </article>
        }
    };
    let base = "https://github.com/archangel-sec/archangel/blob/main";
    view! {
        <h1>"Documentation"</h1>
        <p class="lead">"The architecture and threat model are the load-bearing documents — read them before trusting archangel with anything."</p>

        <div class="card-row">
            {doc(format!("{base}/docs/THREAT_MODEL.md"), "Threat model", "The 18 defense layers, trust tiers, and STRIDE analysis.")}
            {doc(format!("{base}/docs/ARCHITECTURE.md"), "Architecture", "Trust boundaries, the daemon/executor split, IPC, and crate layout.")}
            {doc(format!("{base}/docs/SANDBOX.md"), "Sandbox (#11)", "seccomp profiles, capabilities, cgroups, and the unsafe discipline.")}
            {doc(format!("{base}/docs/EGRESS.md"), "Egress (#17)", "The allowlist policy and the kernel-enforced systemd drop-in.")}
            {doc(format!("{base}/docs/RELEASE_READINESS.md"), "Readiness", "An honest v1.0 gap analysis — what is and is not production-ready.")}
        </div>

        <h2>"Configuration at a glance"</h2>
        <p>"The daemon and executor share one fail-closed schema, " <code>"/etc/archangel/archangel.toml"</code> ":"</p>
        <table class="cfg">
            <thead><tr><th>"Section"</th><th>"Controls"</th></tr></thead>
            <tbody>
                <tr><td><code>"[daemon]"</code></td><td>"Trust store, audit log/key, allowlist, bundle dir, session key path."</td></tr>
                <tr><td><code>"[sockets]"</code></td><td>"Control + executor socket paths and the operator/daemon UIDs the peer-credential gates enforce."</td></tr>
                <tr><td><code>"[modes]"</code></td><td>"default = read_only | interactive | autonomous (the executor's own mutation ceiling)."</td></tr>
                <tr><td><code>"[llm]"</code></td><td>"Backend (anthropic | ollama) and model. Tokens never live here."</td></tr>
                <tr><td><code>"[rate_limits]"</code></td><td>"Host-wide blast-rate ceilings (#12)."</td></tr>
                <tr><td><code>"[monitor]"</code></td><td>"Autonomous log monitoring: sources, trigger patterns, cooldown. Off by default."</td></tr>
                <tr><td><code>"[egress]"</code></td><td>"Egress allowlist (#17); compile it to a kernel filter with archangelctl egress-sync."</td></tr>
            </tbody>
        </table>
        <p class="note">"A complete, page-by-page configuration guide ships as a .docx in the repository."</p>
    }
}

fn downloads() -> impl IntoView {
    view! {
        <h1>"Downloads"</h1>
        <div class="banner" role="note">
            <strong>"Pre-alpha."</strong>
            " These are review/evaluation artifacts, not a supported release. Verify checksums and read the threat model before installing."
        </div>

        <div class="card-row">
            <article class="card dl">
                <h3>"Debian / Ubuntu (.deb)"</h3>
                <p>"For DEB-based distributions."</p>
                <a class="btn primary" href="/dist/archangel_0.4.0-1_amd64.deb">"archangel_0.4.0-1_amd64.deb"</a>
                <p class="hint">"Install all four together: " <code>"sudo dpkg -i ./archangel*_0.4.0-1_amd64.deb"</code></p>
            </article>
            <article class="card dl">
                <h3>"Fedora / RHEL (.rpm)"</h3>
                <p>"For RPM-based distributions."</p>
                <a class="btn primary" href="/dist/archangel-0.4.0-1.x86_64.rpm">"archangel-0.4.0-1.x86_64.rpm"</a>
                <p class="hint">"Install with " <code>"sudo dnf install ./archangel-0.4.0-1.x86_64.rpm"</code></p>
            </article>
        </div>

        <h2>"No artifact yet? Build from source"</h2>
        <p>"If the buttons 404, no prebuilt package has been published to this site. Build them yourself (it is one command set) — see "<a href="/install">"Install"</a>"."</p>
        <p class="note">
            "Operators host their own artifacts: drop the built " <code>".deb"</code> "/" <code>".rpm"</code>
            " into the site's " <code>"dist/"</code> " directory and these links go live."
        </p>
    }
}
