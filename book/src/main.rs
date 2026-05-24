//! Generates `archangel-configuration-guide.docx` — a complete, page-by-page
//! guide to configuring the archangel package. No pandoc needed: the content
//! is authored as `Block`s and rendered with `docx-rs`.
//!
//! Run with `cargo run` (the .docx lands next to this crate's Cargo.toml).

use docx_rs::*;

/// One unit of guide content.
enum Block {
    /// Chapter title (starts on a new page).
    H1(&'static str),
    /// Section.
    H2(&'static str),
    /// Sub-section.
    H3(&'static str),
    /// Body paragraph.
    P(&'static str),
    /// Monospace block (each line preserved); rendered line by line.
    Code(&'static str),
    /// Bullet item.
    Li(&'static str),
    /// Highlighted note / warning paragraph.
    Note(&'static str),
}

fn render(doc: Docx, blocks: &[Block]) -> Docx {
    let mut doc = doc;
    let mut first_h1 = true;
    for b in blocks {
        match b {
            Block::H1(t) => {
                if !first_h1 {
                    doc = doc.add_paragraph(
                        Paragraph::new().add_run(Run::new().add_break(BreakType::Page)),
                    );
                }
                first_h1 = false;
                doc = doc.add_paragraph(
                    Paragraph::new().add_run(Run::new().add_text(*t).bold().size(34)),
                );
            }
            Block::H2(t) => {
                doc = doc.add_paragraph(
                    Paragraph::new().add_run(Run::new().add_text(*t).bold().size(28)),
                );
            }
            Block::H3(t) => {
                doc = doc.add_paragraph(
                    Paragraph::new().add_run(Run::new().add_text(*t).bold().size(24)),
                );
            }
            Block::P(t) => {
                doc = doc.add_paragraph(
                    Paragraph::new().add_run(Run::new().add_text(*t).size(22)),
                );
            }
            Block::Note(t) => {
                doc = doc.add_paragraph(
                    Paragraph::new()
                        .add_run(Run::new().add_text(*t).size(22).italic().bold()),
                );
            }
            Block::Li(t) => {
                doc = doc.add_paragraph(
                    Paragraph::new()
                        .add_run(Run::new().add_text(format!("•  {t}")).size(22)),
                );
            }
            Block::Code(t) => {
                for line in t.lines() {
                    doc = doc.add_paragraph(Paragraph::new().add_run(
                        Run::new()
                            .add_text(line)
                            .size(19)
                            .fonts(RunFonts::new().ascii("Consolas").hi_ansi("Consolas")),
                    ));
                }
            }
        }
    }
    doc
}

fn main() -> Result<(), DocxError> {
    let mut blocks: Vec<Block> = Vec::new();
    cover(&mut blocks);
    intro(&mut blocks);
    architecture(&mut blocks);
    installation(&mut blocks);
    config_file(&mut blocks);
    section_daemon(&mut blocks);
    section_sockets(&mut blocks);
    section_session(&mut blocks);
    section_modes(&mut blocks);
    section_llm(&mut blocks);
    section_rate_limits(&mut blocks);
    section_monitor(&mut blocks);
    section_egress(&mut blocks);
    keys_and_trust(&mut blocks);
    bundles_and_allowlist(&mut blocks);
    systemd_units(&mut blocks);
    permissions(&mut blocks);
    modes_in_practice(&mut blocks);
    snapshots(&mut blocks);
    sandbox(&mut blocks);
    audit_log(&mut blocks);
    troubleshooting(&mut blocks);
    security_checklist(&mut blocks);
    appendix(&mut blocks);

    let doc = render(Docx::new(), &blocks);
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/archangel-configuration-guide.docx");
    let file = std::fs::File::create(path).expect("create docx");
    doc.build().pack(file)?;
    println!("wrote {path} ({} blocks)", blocks.len());
    Ok(())
}

fn cover(b: &mut Vec<Block>) {
    b.push(Block::H1("Archangel — Configuration Guide"));
    b.push(Block::P("Version 0.4.0 (pre-alpha). This guide covers how to configure the archangel package on a Linux host: every configuration section and key, the operating modes, the security model, action bundles, egress, autonomous monitoring, the systemd units, file permissions, and troubleshooting."));
    b.push(Block::Note("Pre-alpha — do not run in production. archangel grants a language model bounded administrative control of a Linux host; mis-configuring it is a security event. Read the Safety chapter before changing anything, and keep the default fail-closed posture unless you understand the consequences."));
}

fn intro(b: &mut Vec<Block>) {
    b.push(Block::H1("1. Introduction & safety posture"));
    b.push(Block::P("archangel lets a language model observe, propose, and — under strict, layered policy — execute administrative actions on a Linux server. Every byte of model output is treated as untrusted by construction. The configuration you write decides how much latitude the model has; the defaults are deliberately the safest."));
    b.push(Block::H2("Who should read this"));
    b.push(Block::P("Operators who will install and run archangel on a host they control. Familiarity with systemd, Unix permissions, and the basics of your distribution's package manager is assumed."));
    b.push(Block::H2("The golden rules"));
    b.push(Block::Li("Start in read-only mode. Opt into mutation or autonomy deliberately, one step at a time."));
    b.push(Block::Li("Never put secrets (the LLM token) in the config file. They live in /etc/archangel/llm.env, mode 0600."));
    b.push(Block::Li("The config is fail-closed: anything the daemon cannot prove safe is a startup refusal, not a silent downgrade."));
    b.push(Block::Li("Test every change on a host you can rebuild before trusting it anywhere that matters."));
    b.push(Block::H2("What 'fail-closed' means here"));
    b.push(Block::P("If a required safety mechanism is missing — no snapshot backend for a mutating action, an unbuildable sandbox profile, an exceeded rate ceiling, an unresolved egress target, or read-only mode — the action is refused, never run unprotected. The same applies to configuration: a malformed value refuses startup."));
}

fn architecture(b: &mut Vec<Block>) {
    b.push(Block::H1("2. Architecture in one page"));
    b.push(Block::P("Two privilege-separated processes read the same configuration file:"));
    b.push(Block::Li("archangeld (trust tier T3) — talks to the LLM, builds prompts, evaluates policy, and in autonomous mode monitors logs. It NEVER mutates the system. Assumed compromisable."));
    b.push(Block::Li("archangel-execd (trust tier T2) — the only component that mutates the host. It re-verifies everything the daemon claims (signature, bundle, args, denylist/allowlist, mode ceiling, rate limits, snapshot, sandbox) before running an action."));
    b.push(Block::P("They communicate over a 0600 Unix socket (boundary B), with a per-session Ed25519 signature on every request and a peer-credential (UID) check. The operator talks to the daemon over a separate control socket (boundary A), also signature- and UID-gated."));
    b.push(Block::P("Consequence for configuration: settings such as the mutation ceiling and rate limits are enforced by the EXECUTOR from its own copy of the config, so they hold even if the daemon is compromised. The daemon cannot lift them by lying."));
}

fn installation(b: &mut Vec<Block>) {
    b.push(Block::H1("3. Installation & first setup"));
    b.push(Block::P("There are no distribution packages yet; build the DEB/RPM from source. RPM-based and DEB-based distributions are the supported targets. A host with systemd and cgroup v2 is required (the executor sandboxes each action)."));
    b.push(Block::H2("Build the packages"));
    b.push(Block::Code("cargo build --release\nfor p in archangeld archangel-execd archangelctl archangel; do\n  cargo deb --no-build -p \"$p\"\ndone\n# RPM: cargo install cargo-generate-rpm; cargo generate-rpm -p crates/<pkg>"));
    b.push(Block::H2("Three-step install"));
    b.push(Block::Code("sudo dpkg -i ./target/debian/archangel*_0.4.0-1_amd64.deb\nsudo archangel setup --backend ollama        # or: --backend anthropic\nsudo systemctl enable --now archangel-execd archangeld"));
    b.push(Block::H2("What 'archangel setup' does"));
    b.push(Block::P("setup is idempotent and fail-closed. It creates the operator Ed25519 key, the trust store, signs the sample bundle, generates a read-only allowlist, and writes a schema-validated /etc/archangel/archangel.toml — but it NEVER overwrites an existing operator key, allowlist, or config. For the Anthropic backend it prompts for the API token with echo OFF and writes it 0600 to /etc/archangel/llm.env; the token never appears on the command line."));
    b.push(Block::Note("Run setup with sudo. It detects the operator UID from SUDO_UID and the daemon UID from the 'archangel' system user. If you later see the executor reject the daemon as an unauthorized peer, the daemon_uid in your config does not match the user the daemon actually runs as — see the Troubleshooting chapter."));
}

fn config_file(b: &mut Vec<Block>) {
    b.push(Block::H1("4. The configuration file"));
    b.push(Block::P("Both processes read one file: /etc/archangel/archangel.toml. It is the single source of truth for paths, sockets, the peer-credential UIDs, the operating mode, rate limits, monitoring, and egress. One schema, one validator — so the daemon and executor can never disagree."));
    b.push(Block::H2("Format and validation"));
    b.push(Block::P("Standard TOML, grouped into sections shown in the following chapters. On load the file is parsed and then validated against a security baseline; ANY failure is a refusal to start (you will see 'config rejected (fail-closed): ...' in the journal). It is never silently downgraded."));
    b.push(Block::H2("Sections at a glance"));
    b.push(Block::Li("[daemon] — trust store, audit log/key, allowlist, bundle dir, session key path."));
    b.push(Block::Li("[sockets] — control + executor socket paths and the operator/daemon UIDs."));
    b.push(Block::Li("[session] — per-task isolation and session lifetime."));
    b.push(Block::Li("[modes] — default mode = read_only | interactive | autonomous (the mutation ceiling)."));
    b.push(Block::Li("[llm] — backend and model. Tokens are NOT here."));
    b.push(Block::Li("[rate_limits] — host-wide blast-rate ceilings (#12)."));
    b.push(Block::Li("[monitor] — autonomous log monitoring (off by default)."));
    b.push(Block::Li("[egress] — egress allowlist (#17)."));
    b.push(Block::H2("Editing safely"));
    b.push(Block::P("Edit with `sudoedit /etc/archangel/archangel.toml` (preserves ownership and mode). Edit the existing sections in place — do NOT paste duplicate [section] headers, which TOML rejects. After any change, restart the affected service(s) and watch the journal. When in doubt, validate by restarting and reading `journalctl -u archangeld -n 20`."));
    b.push(Block::Note("Re-running `archangel setup` will NOT overwrite an existing config, so feature flags you add by hand are safe across re-runs."));
}

fn section_daemon(b: &mut Vec<Block>) {
    b.push(Block::H1("5. [daemon] — paths and trust"));
    b.push(Block::P("The [daemon] section tells both processes where the trust material, audit log, allowlist, and signed bundles live. All paths must be absolute; relative paths refuse startup."));
    b.push(Block::Code("[daemon]\ntrust_store     = \"/etc/archangel/trust/operators.pub\"\naudit_log       = \"/var/log/archangel/audit.log.jsonl\"\naudit_key       = \"/etc/archangel/trust/audit.key\"\noperator_pubkey = \"/etc/archangel/trust/operator.pub\"\nallowlist       = \"/etc/archangel/policies/allowlist.toml\"\nbundle_dir      = \"/etc/archangel/exec\"\nsession_pub     = \"/run/archangel/session.pub\""));
    b.push(Block::H3("Keys"));
    b.push(Block::Li("trust_store — the operator public keys allowed to sign .exec bundles and policies. Required."));
    b.push(Block::Li("audit_log — append-only, hash-chained, signed log path. Required."));
    b.push(Block::Li("audit_key — the daemon's own Ed25519 signing key for the audit chain; generated 0600 if absent. Must be readable only by the daemon user."));
    b.push(Block::Li("operator_pubkey — the pinned operator public key for control-plane (boundary A) auth."));
    b.push(Block::Li("allowlist — the per-profile list of permitted .exec bundles (layer #9)."));
    b.push(Block::Li("bundle_dir — directory of signed .exec bundles (and their .sig files)."));
    b.push(Block::Li("session_pub — where the daemon publishes its per-run session public key for the executor to read (rotated each restart). A public key; its integrity comes from the directory's permissions."));
    b.push(Block::Note("Everything under /etc/archangel except private keys is operator-public (config, trust, allowlist, signed bundles). Private keys (operator.key, audit.key) are 0600. Both daemons must be able to READ the public tree — see the Permissions chapter; a wrong group here is the most common reason the services fail to start."));
}

fn section_sockets(b: &mut Vec<Block>) {
    b.push(Block::H1("6. [sockets] — sockets and the UID gates"));
    b.push(Block::P("Defines the two Unix sockets and, crucially, the UIDs the peer-credential checks enforce. These UIDs are a security control: the executor accepts boundary-B connections only from daemon_uid; the daemon accepts control connections only from operator_uid."));
    b.push(Block::Code("[sockets]\ncontrol       = \"/run/archangel/ctl.sock\"\ncontrol_mode  = 0o660\ncontrol_group = \"archangel\"\nexec          = \"/run/archangel/exec.sock\"\noperator_uid  = 1000\ndaemon_uid    = 997"));
    b.push(Block::Li("control — operator control socket (boundary A)."));
    b.push(Block::Li("control_mode — octal mode of the control socket; must not grant access to 'other' (validated)."));
    b.push(Block::Li("control_group — group owning the control socket."));
    b.push(Block::Li("exec — executor socket (boundary B). The executor creates it 0660 in /run/archangel so the daemon (a different user, in the shared group) can connect; the real auth is the UID check plus the per-request signature."));
    b.push(Block::Li("operator_uid — REQUIRED. The UID allowed to connect to the control socket; i.e. the user that runs archangelctl. With sudo, setup detects it from SUDO_UID."));
    b.push(Block::Li("daemon_uid — REQUIRED. The UID archangeld runs as; the executor accepts the exec socket only from this UID."));
    b.push(Block::Note("If you install via systemd, archangeld runs as the 'archangel' system user. daemon_uid MUST equal `id -u archangel` (e.g. 997), NOT your login UID. A mismatch shows up as 'rejecting unauthorized peer uid=...' in the executor journal and the daemon's actions fail at boundary B."));
}

fn section_session(b: &mut Vec<Block>) {
    b.push(Block::H1("7. [session]"));
    b.push(Block::P("Per-session behaviour. Defaults are safe; most operators leave this untouched."));
    b.push(Block::Code("[session]\nper_task_isolation = true\nttl_seconds        = 3600"));
    b.push(Block::Li("per_task_isolation — keep each task's model context isolated (layer #4). Leave true."));
    b.push(Block::Li("ttl_seconds — session lifetime in seconds (default 3600)."));
}

fn section_modes(b: &mut Vec<Block>) {
    b.push(Block::H1("8. [modes] — the mutation ceiling"));
    b.push(Block::P("The single most important security knob. `default` is BOTH the session start mode and the executor's mutation ceiling: the executor reads it from its own config and refuses every mutating action unless the mode is interactive or autonomous — independent of, and not overridable by, the daemon."));
    b.push(Block::Code("[modes]\ndefault            = \"read_only\"   # read_only | interactive | autonomous\nautonomous_allowed = false"));
    b.push(Block::H3("The three modes"));
    b.push(Block::Li("read_only — the model may invoke only bundles marked read_only = true. No mutation is possible, structurally. The safest posture and the default."));
    b.push(Block::Li("interactive — the model may PROPOSE mutating actions, but each one queues for explicit operator approval (layers #13/#14) before it runs."));
    b.push(Block::Li("autonomous — actions run without per-action approval, still bounded by the denylist, allowlist, signed bundle, snapshot, sandbox, and rate limits."));
    b.push(Block::Li("autonomous_allowed — must be true for default = \"autonomous\" (validated). A second switch so autonomy is never enabled by a single edit."));
    b.push(Block::Note("An omitted [modes] section defaults to read_only (fail-closed). Enabling mutation does not bypass anything: a mutating action still must be operator-signed, denylisted-checked, snapshotted (if it touches persistent state), sandboxed, and rate-limited. Move read_only → interactive → autonomous one step at a time, testing each."));
}

fn section_llm(b: &mut Vec<Block>) {
    b.push(Block::H1("9. [llm] — backend and model"));
    b.push(Block::P("Selects the model backend. The API token is NEVER configured here."));
    b.push(Block::Code("[llm]\ndefault_backend = \"anthropic\"   # anthropic | ollama\nmodel           = \"claude-opus-4-7\"\nmax_tokens      = 1024"));
    b.push(Block::Li("default_backend — \"anthropic\" (hosted) or \"ollama\" (local/offline). An unsupported value refuses startup."));
    b.push(Block::Li("model — model id. Omit to use the per-backend default (Anthropic: claude-opus-4-7; Ollama: llama3)."));
    b.push(Block::Li("max_tokens — completion size cap."));
    b.push(Block::H3("The token (Anthropic)"));
    b.push(Block::P("The Anthropic token is read from the ARCHANGEL_LLM_TOKEN environment variable, supplied to the daemon via the systemd unit's `EnvironmentFile=-/etc/archangel/llm.env`. `archangel setup --backend anthropic` writes it 0600 with a no-echo prompt. To set it by hand without leaking it to your shell history:"));
    b.push(Block::Code("sudo install -m 600 -o root -g root /dev/null /etc/archangel/llm.env\nread -rs TOKEN\nprintf 'ARCHANGEL_LLM_TOKEN=%s\\n' \"$TOKEN\" | sudo tee /etc/archangel/llm.env >/dev/null\nunset TOKEN"));
    b.push(Block::Note("Never put the token in archangel.toml, never pass it on a command line. If a token is ever exposed, rotate it immediately at the provider console. Ollama needs no token."));
    b.push(Block::P("Network note: the daemon must be able to reach the backend. Anthropic (api.anthropic.com:443) requires egress (see chapter 12); Ollama (127.0.0.1:11434) is loopback and always reachable."));
}

fn section_rate_limits(b: &mut Vec<Block>) {
    b.push(Block::H1("10. [rate_limits] — blast-rate ceilings (#12)"));
    b.push(Block::P("Host-wide ceilings enforced by the EXECUTOR, so they bound the action rate even if the daemon is compromised — no number of forged sessions can exceed them. A value of 0 means 'none permitted' (fail-closed), NOT 'unlimited'."));
    b.push(Block::Code("[rate_limits]\nactions_per_minute          = 20\nmutating_actions_per_minute = 5\ncritical_actions_per_hour   = 2\napproval_requests_per_minute = 10"));
    b.push(Block::Li("actions_per_minute — total admitted actions per 60s (any kind)."));
    b.push(Block::Li("mutating_actions_per_minute — admitted non-read-only actions per 60s."));
    b.push(Block::Li("critical_actions_per_hour — admitted risk=critical actions per hour."));
    b.push(Block::Li("approval_requests_per_minute — enforced by the daemon (approvals never reach the executor)."));
    b.push(Block::P("Sliding windows; a shed action is refused with a RateLimited stage and consumes no budget. Tune conservatively — these cap the damage rate of a successful attack."));
}

fn section_monitor(b: &mut Vec<Block>) {
    b.push(Block::H1("11. [monitor] — autonomous log monitoring"));
    b.push(Block::P("Real-time log monitoring is the heart of autonomous mode: the daemon tails files, and lines matching operator-defined patterns are assessed by the model, which may propose an action through the full gate stack. OFF by default — the daemon watches nothing until you opt in."));
    b.push(Block::Code("[monitor]\nenabled            = false\npoll_interval_secs = 5\ncooldown_secs      = 300\nsources            = [\"/var/log/syslog\"]\nmax_line_bytes     = 4096\nmax_lines_per_poll = 256\n\n[[monitor.patterns]]\nlabel = \"oom-killer\"\nregex = \"Out of memory: Killed process\"\n\n[[monitor.patterns]]\nlabel = \"ssh-bruteforce\"\nregex = \"(?i)failed password for\""));
    b.push(Block::Li("enabled — master switch. False ⇒ no files watched, no loop, no model calls from logs."));
    b.push(Block::Li("poll_interval_secs — how often to poll the watched files (must be > 0 when enabled)."));
    b.push(Block::Li("cooldown_secs — per-trigger cooldown: the same trigger will not be acted on again within this window. The anti-runaway rail that stops a persistent log condition from driving repeated actions. 0 disables it."));
    b.push(Block::Li("sources — absolute paths of log files to tail. Only NEW lines (written after start) are seen."));
    b.push(Block::Li("max_line_bytes / max_lines_per_poll — anti-flood bounds: overlong lines are truncated, and a burst is shed to the per-poll cap."));
    b.push(Block::Li("[[monitor.patterns]] — one per trigger: a human label and a linear-time regex (anti-ReDoS). `(?i)` is case-insensitive. ONLY matching lines reach the model — you, not the model, decide what it looks at."));
    b.push(Block::Note("Logs are hostile input (threat model T6): a process that can write to a watched log can plant a prompt-injection payload. The line is spotlighted (fenced as untrusted data) before the model sees it, and the action it might propose still passes every gate. Even so: cost matters — on Anthropic, every matching line is an API call. Do not point this at a noisy log in autonomous mode without a cooldown. The systemd unit must also be able to READ the watched paths (it runs with ProtectSystem=strict + PrivateTmp=true, so a /tmp scratch log is invisible; use /var/log/archangel/ or a real /var/log file)."));
}

fn section_egress(b: &mut Vec<Block>) {
    b.push(Block::H1("12. [egress] — egress allowlist (#17)"));
    b.push(Block::P("Bounds where the daemon may connect, so exfiltration is structurally limited. Fail-closed: default_policy = \"deny\" means only the listed hosts may be reached."));
    b.push(Block::Code("[egress]\ndefault_policy = \"deny\"   # deny | allow\nallow = [\n  \"api.anthropic.com\",      # the LLM endpoint (omit for Ollama)\n  \"127.0.0.1:11434\",        # Ollama, if used\n]"));
    b.push(Block::Li("default_policy — \"deny\" (secure default) or \"allow\" (permit everything; dev only)."));
    b.push(Block::Li("allow — entries are \"host\" (any port) or \"host:port\". Matching is exact and case-insensitive; there is NO implicit subdomain matching. Malformed entries refuse startup."));
    b.push(Block::H3("Making it structural: egress-sync"));
    b.push(Block::P("The allowlist above is the decision. To enforce it at the kernel, compile it into a systemd drop-in with archangelctl:"));
    b.push(Block::Code("archangelctl egress-sync                 # preview the drop-in (dry run)\nsudo archangelctl egress-sync --write    # install it for archangeld\nsudo systemctl daemon-reload && sudo systemctl restart archangeld"));
    b.push(Block::P("This resolves each allowlisted host to its current IPs and writes IPAddressDeny=any + IPAddressAllow=localhost <ips>. The kernel then refuses any other destination, regardless of what the process attempts."));
    b.push(Block::Note("Two honest limits: it is IP-granular (systemd has no port concept here) and IP-pinned — re-run egress-sync when a CDN-fronted host's IPs rotate (a systemd timer is reasonable), or the daemon loses access. A hostname-native egress proxy is planned but not yet shipped."));
}

fn keys_and_trust(b: &mut Vec<Block>) {
    b.push(Block::H1("13. Trust & keys"));
    b.push(Block::P("archangel uses Ed25519 keys for three distinct jobs. Keep them straight; mixing them up is a common setup mistake."));
    b.push(Block::H2("The operator key"));
    b.push(Block::P("/etc/archangel/trust/operator.key (private, 0600) signs .exec bundles and every operator control request. Its public half is operator.pub, and it is recorded in the trust store operators.pub. Generated by `archangel setup` or `archangelctl init`; never overwritten."));
    b.push(Block::Li("Sign a bundle:  archangelctl bundle-sign /etc/archangel/exec/NAME.exec --secret /etc/archangel/trust/operator.key"));
    b.push(Block::Li("It must be readable by whoever signs (the operator). Under sudo-created setups it is root-owned; sign with sudo or adjust ownership deliberately."));
    b.push(Block::H2("The trust store"));
    b.push(Block::P("daemon.trust_store (operators.pub) lists the operator public keys the daemon and executor trust to have signed bundles/policies. Both processes must be able to READ it. Add keys here; never drop one silently."));
    b.push(Block::H2("The audit key"));
    b.push(Block::P("daemon.audit_key (audit.key, 0600) is the daemon's own key for signing the hash-chained audit log. It belongs to the daemon user (archangel) and is created automatically if absent. If you ran the daemon manually before installing the service, chown it back to the service user (a frequent 'Permission denied: read audit key' cause)."));
    b.push(Block::Note("Three keys, three owners: operator.key = the operator; audit.key = the daemon; the executor verifies signatures with PUBLIC keys only. No process needs another's private key."));
}

fn bundles_and_allowlist(b: &mut Vec<Block>) {
    b.push(Block::H1("14. Action bundles & the allowlist"));
    b.push(Block::P("Everything the model can run is a signed .exec bundle in daemon.bundle_dir. A bundle is a declarative TOML manifest: identity + risk, an argument schema, a sandbox profile, and the payload. Changing the payload invalidates the signature (the manifest pins its SHA-256)."));
    b.push(Block::H2("Anatomy of a bundle"));
    b.push(Block::Code("[meta]\nname = \"check-disk\"\nversion = \"1.0.0\"\nrisk = \"low\"           # low | medium | high | critical\nread_only = true        # false ⇒ mutating; needs interactive/autonomous mode\n# mutates_persistent_state = true   # ⇒ a snapshot is required (#16)\n\n[sandbox]\nsyscall_profile = \"inspect\"   # the audited seccomp profile\nnetwork = \"none\"              # none | loopback | egress\ntimeout_seconds = 10\n\n[payload]\ntype = \"bash\"\nsha256 = \"<sha256 of the inline payload bytes>\"\ninline = \"df -h /\""));
    b.push(Block::P("Compute the payload hash exactly over the inline bytes (no trailing newline): `printf 'df -h /' | sha256sum`. The bundle name must equal the file stem (check-disk.exec)."));
    b.push(Block::H2("Authoring and signing a new bundle"));
    b.push(Block::Code("sudo tee /etc/archangel/exec/check-disk.exec >/dev/null <<'EOF'\n# ...manifest with the correct sha256...\nEOF\nsudo archangelctl bundle-sign /etc/archangel/exec/check-disk.exec \\\n  --secret /etc/archangel/trust/operator.key\nsudo chgrp archangel /etc/archangel/exec/check-disk.exec*\nsudo chmod 0644 /etc/archangel/exec/check-disk.exec*"));
    b.push(Block::H2("The allowlist"));
    b.push(Block::P("/etc/archangel/policies/allowlist.toml lists, per profile and mode, which bundles may run. A bundle is permitted only if its profile's mode matches the SESSION mode exactly."));
    b.push(Block::Code("[[profile]]\nname = \"default\"\nmode = \"read_only\"          # must match the active session mode\nallowed_exec = [\"read-uptime\", \"check-disk\"]"));
    b.push(Block::Note("Mode must match: a profile with mode = \"read_only\" does NOT permit actions when the session runs autonomous. To run check-disk autonomously, the profile needs mode = \"autonomous\" and the bundle's name in allowed_exec. The daemon re-discovers bundles at startup, so restart after adding one."));
}

fn systemd_units(b: &mut Vec<Block>) {
    b.push(Block::H1("15. systemd units & hardening"));
    b.push(Block::P("Two hardened units ship with the package: archangel-execd.service (T2) and archangeld.service (T3). Enable both; execd starts first."));
    b.push(Block::Code("sudo systemctl enable --now archangel-execd archangeld\nsudo systemctl status archangel-execd archangeld\nsudo journalctl -u archangeld -f"));
    b.push(Block::H2("Key directives (and why)"));
    b.push(Block::Li("User/Group — execd runs as archangel-exec, archangeld as archangel. This is the privilege separation; do not collapse them."));
    b.push(Block::Li("Type=exec — the binaries do not implement the sd_notify readiness protocol, so the units use Type=exec (active once exec'd) and set no WatchdogSec. (An earlier Type=notify caused a restart loop.)"));
    b.push(Block::Li("Delegate=cpu memory pids (execd) — lets the executor create a per-action cgroup for the resource limits in a bundle's sandbox profile."));
    b.push(Block::Li("ProtectSystem=strict, ProtectHome=true, PrivateTmp=true (daemon) — strong filesystem isolation. Consequence: a monitored log must be in a path the daemon can read (e.g. /var/log/archangel/), not a private /tmp."));
    b.push(Block::Li("IPAddressDeny=any + IPAddressAllow=localhost (daemon) — egress is closed by default. Open it precisely with `archangelctl egress-sync` (chapter 12), not by hand-editing to 'any'."));
    b.push(Block::H2("Overrides"));
    b.push(Block::P("Customize with drop-ins under /etc/systemd/system/<unit>.service.d/ rather than editing the shipped unit (which an upgrade replaces). Run `systemctl daemon-reload` after."));
    b.push(Block::Note("systemd unit files do NOT support inline comments after a directive value (`Key=value  # note` breaks parsing). Put comments on their own line."));
}

fn permissions(b: &mut Vec<Block>) {
    b.push(Block::H1("16. Filesystem layout & permissions"));
    b.push(Block::P("Getting ownership right is the difference between the services starting and a wall of 'Permission denied'. The package's postinst sets this up; the rules below let you verify and repair it."));
    b.push(Block::H2("The layout"));
    b.push(Block::Code("/etc/archangel/            root:archangel  2750  (config tree, setgid)\n  archangel.toml           root:archangel  0640\n  trust/operator.key       <op>:<op>       0600  (operator private)\n  trust/operator.pub       root:archangel  0640\n  trust/operators.pub      root:archangel  0640  (trust store)\n  trust/audit.key          archangel:...   0600  (daemon private)\n  policies/allowlist.toml  root:archangel  0640\n  exec/*.exec(.sig)        root:archangel  0644\n  llm.env                  root:root       0600  (token; read by systemd)\n/var/lib/archangel         archangel:archangel        0750\n/var/lib/archangel-exec    archangel-exec:archangel-exec  0750\n/var/log/archangel         archangel:archangel-audit  2750\n/run/archangel             archangel:archangel-audit  2770  (sockets + session.pub)"));
    b.push(Block::H2("The rules"));
    b.push(Block::Li("Both daemons must READ the /etc/archangel public tree — it is group archangel, and archangel-exec is added to that group. Private keys stay 0600, so group membership never exposes them."));
    b.push(Block::Li("The config dirs are setgid (2750) so files created later by `archangel setup` (run as root via sudo) inherit group archangel rather than root."));
    b.push(Block::Li("The audit log dir is group archangel-audit, of which both daemons are members."));
    b.push(Block::Note("If you ran the binaries manually as your own user before installing the services, files (config, audit.key, logs) may be owned by you and unreadable by the service users. Repair with `sudo chgrp -R archangel /etc/archangel/<public files>` (never the private keys) and `sudo chown archangel:archangel /etc/archangel/trust/audit.key`. See Troubleshooting."));
}

fn modes_in_practice(b: &mut Vec<Block>) {
    b.push(Block::H1("17. Operating modes in practice"));
    b.push(Block::P("A recommended progression. Validate each step before advancing; revert to a safer mode when you are done experimenting."));
    b.push(Block::H2("read_only"));
    b.push(Block::P("default = \"read_only\". The model can run only read-only bundles (status, metrics, log inspection). Nothing mutates. Use this to build confidence in the prompts and allowlist."));
    b.push(Block::H2("interactive"));
    b.push(Block::P("default = \"interactive\". The model proposes actions; each queues for your approval. With autonomous monitoring enabled, a matched log event produces a proposal you see as 'awaiting operator approval'. Approve/reject via an archangelctl session. Nothing runs without you."));
    b.push(Block::H2("autonomous"));
    b.push(Block::P("default = \"autonomous\", autonomous_allowed = true. Actions run without per-action approval, still bounded by every gate. Recommended first test: enable [monitor] over a SCRATCH log (e.g. /var/log/archangel/test.log), allowlist a single read-only bundle, and watch the loop execute it end to end:"));
    b.push(Block::Code("echo \"WARNING: disk almost full on /\" | sudo tee -a /var/log/archangel/test.log\nsudo journalctl -u archangeld -f\n# expect: autonomous action executed  exec=check-disk  exit_code=0"));
    b.push(Block::Note("Autonomous mode is the highest-blast-radius setting. Keep the allowlist minimal, the cooldown sane, and the rate limits tight. For day-to-day, interactive or read_only is the safer default — switch back when you finish testing."));
}

fn snapshots(b: &mut Vec<Block>) {
    b.push(Block::H1("18. Snapshots & recovery (#16)"));
    b.push(Block::P("Before any action that declares mutates_persistent_state = true, the executor takes a filesystem snapshot. No snapshot backend, no mutation: the action is refused fail-closed (you will see a SnapshotUnavailable rejection)."));
    b.push(Block::Li("A BTRFS state directory yields a snapshot backend automatically. On filesystems without one, persistent-mutating actions are refused (read-only and runtime-only actions are unaffected)."));
    b.push(Block::Li("Snapshots are the recovery point if an action misbehaves; the snapshot id is recorded in the audit log."));
    b.push(Block::P("This is a containment-and-recovery layer, not a backup system. It bounds the cost of a bad action; it does not replace real backups."));
}

fn sandbox(b: &mut Vec<Block>) {
    b.push(Block::H1("19. The per-action sandbox (#11)"));
    b.push(Block::P("Every executed action runs under a per-action sandbox built from its bundle's [sandbox] profile: a seccomp-bpf syscall allowlist (kill on mismatch), a dropped capability set, and cgroup v2 cpu/memory limits."));
    b.push(Block::Li("syscall_profile — the named profile to install. The audited 'inspect' profile permits what bash + common read-only coreutils need and makes network, mount, ptrace, module-load, privilege-change, and filesystem-mutation syscalls fatal."));
    b.push(Block::Li("network — none | loopback | egress. For non-network profiles, socket(AF_INET) is denied at the syscall level, so an action cannot reach the network at all."));
    b.push(Block::Li("cpu_max / memory_max (optional, in the profile) — cgroup ceilings; a declared limit that cannot be enforced refuses the action (requires Delegate= on the unit)."));
    b.push(Block::P("You normally do not hand-tune this: bundles ship with a sensible profile. If you author a bundle, use syscall_profile = \"inspect\" unless you have a specific, reviewed need for more."));
    b.push(Block::Note("The sandbox is the one place the project uses audited `unsafe` (a single reviewed pre_exec block); everything else is forbid(unsafe_code). See docs/SANDBOX.md."));
}

fn audit_log(b: &mut Vec<Block>) {
    b.push(Block::H1("20. The audit log (#15)"));
    b.push(Block::P("Every decision and action is recorded in an append-only, hash-chained, Ed25519-signed log at daemon.audit_log. Tampering breaks the chain and is detectable."));
    b.push(Block::H2("Reading and verifying it"));
    b.push(Block::P("At startup the daemon prints the audit public key — pin it. Then verify and view the log:"));
    b.push(Block::Code("archangelctl audit-tail --log /var/log/archangel/audit.log.jsonl --key <audit-public-key-hex>"));
    b.push(Block::P("The chain links each entry to the previous; the tool reports any break. Keep the public key somewhere outside the host so a compromise cannot rewrite history and re-sign undetected."));
}

fn troubleshooting(b: &mut Vec<Block>) {
    b.push(Block::H1("21. Troubleshooting"));
    b.push(Block::P("The most common failures are configuration/permission issues, especially right after a first install or after running the binaries manually. Always start with the journal:"));
    b.push(Block::Code("sudo journalctl -u archangel-execd -n 30 --no-pager\nsudo journalctl -u archangeld     -n 30 --no-pager"));
    b.push(Block::H3("'cannot read config: Permission denied'"));
    b.push(Block::P("A service user cannot read /etc/archangel/archangel.toml (or the trust/allowlist files). The config tree must be group archangel and readable; the executor must be in that group. Fix the file group/mode (0640 root:archangel) and `usermod -aG archangel archangel-exec`. See chapter 16."));
    b.push(Block::H3("'read audit key: Permission denied'"));
    b.push(Block::P("audit.key is not owned by the daemon user. `sudo chown archangel:archangel /etc/archangel/trust/audit.key` (keep 0600)."));
    b.push(Block::H3("Service stuck 'activating (start)' then restart-loops"));
    b.push(Block::P("A Type=notify unit without sd_notify times out. The shipped units use Type=exec; if you have an old unit, add a drop-in `[Service]\\nType=exec\\nWatchdogSec=0` and daemon-reload."));
    b.push(Block::H3("'connect exec socket: Permission denied'"));
    b.push(Block::P("The daemon cannot connect to the executor socket. It should be mode 0660 in /run/archangel (group archangel-audit). The current executor creates it 0660; rebuild/reinstall if you are on an older 0600 build."));
    b.push(Block::H3("'rejecting unauthorized peer uid=...'"));
    b.push(Block::P("sockets.daemon_uid does not match the UID the daemon runs as (the 'archangel' system user). Set daemon_uid = `id -u archangel` and restart both services. See chapter 6."));
    b.push(Block::H3("'autonomous assessment failed: ... connect ...' (egress)"));
    b.push(Block::P("The daemon cannot reach the LLM. For Anthropic, generate the egress drop-in (chapter 12) so the endpoint IPs are allowed; for Ollama, ensure it is on localhost. Confirm with `systemctl show archangeld -p IPAddressAllow`."));
    b.push(Block::H3("The model 'declined to act'"));
    b.push(Block::P("Not an error — the model judged no allowlisted action relevant. Provide a relevant signed, allowlisted bundle (chapter 14), or refine the trigger."));
}

fn security_checklist(b: &mut Vec<Block>) {
    b.push(Block::H1("22. Security checklist"));
    b.push(Block::P("Before trusting archangel beyond a rebuildable lab host:"));
    b.push(Block::Li("Mode is the least-permissive that meets your need (prefer read_only / interactive)."));
    b.push(Block::Li("The allowlist is minimal and every bundle is operator-signed; the denylist is intact."));
    b.push(Block::Li("The LLM token is only in /etc/archangel/llm.env (0600); never in the config or a command line. Rotate it if it was ever exposed."));
    b.push(Block::Li("[egress] is deny-by-default and the kernel drop-in is installed (egress-sync); no 'allow'/'any'."));
    b.push(Block::Li("Rate limits are set; autonomous monitoring (if on) watches only intended sources with a cooldown."));
    b.push(Block::Li("File ownership/permissions match chapter 16; private keys are 0600; the audit public key is pinned off-host."));
    b.push(Block::Li("You have backups and snapshots; the host is one you can rebuild."));
    b.push(Block::Note("Per the project roadmap, true production readiness (v1.0) also requires an external security audit, a public red-team, a stable-release track record, and an unaffiliated production deployment — none of which a configuration can substitute. Until then: not for production."));
}

fn appendix(b: &mut Vec<Block>) {
    b.push(Block::H1("Appendix A — Full example configuration"));
    b.push(Block::P("A complete, conservative /etc/archangel/archangel.toml. Start from what `archangel setup` generates and adjust deliberately."));
    b.push(Block::Code("[daemon]\ntrust_store     = \"/etc/archangel/trust/operators.pub\"\naudit_log       = \"/var/log/archangel/audit.log.jsonl\"\naudit_key       = \"/etc/archangel/trust/audit.key\"\noperator_pubkey = \"/etc/archangel/trust/operator.pub\"\nallowlist       = \"/etc/archangel/policies/allowlist.toml\"\nbundle_dir      = \"/etc/archangel/exec\"\nsession_pub     = \"/run/archangel/session.pub\"\n\n[sockets]\ncontrol       = \"/run/archangel/ctl.sock\"\ncontrol_mode  = 0o660\ncontrol_group = \"archangel\"\nexec          = \"/run/archangel/exec.sock\"\noperator_uid  = 1000\ndaemon_uid    = 997\n\n[session]\nper_task_isolation = true\nttl_seconds        = 3600\n\n[modes]\ndefault            = \"read_only\"\nautonomous_allowed = false\n\n[llm]\ndefault_backend = \"anthropic\"\nmodel           = \"claude-opus-4-7\"\nmax_tokens      = 1024\n\n[rate_limits]\nactions_per_minute           = 20\nmutating_actions_per_minute  = 5\ncritical_actions_per_hour    = 2\napproval_requests_per_minute = 10\n\n[monitor]\nenabled            = false\npoll_interval_secs = 5\ncooldown_secs      = 300\nsources            = []\nmax_line_bytes     = 4096\nmax_lines_per_poll = 256\n\n[egress]\ndefault_policy = \"deny\"\nallow          = [\"api.anthropic.com\"]"));
    b.push(Block::H1("Appendix B — archangelctl command reference"));
    b.push(Block::Li("archangel setup --backend <ollama|anthropic> — one-command bootstrap (keys, trust, allowlist, config, token)."));
    b.push(Block::Li("archangelctl init — generate the operator keypair."));
    b.push(Block::Li("archangelctl bundle-sign <manifest> --secret <key> — sign a .exec bundle."));
    b.push(Block::Li("archangelctl doctor — check host readiness."));
    b.push(Block::Li("archangelctl session --secret <key> --socket <ctl.sock> — interactive operator session (propose/approve/reject)."));
    b.push(Block::Li("archangelctl ping — liveness check against the daemon."));
    b.push(Block::Li("archangelctl policy-reload — ask the daemon to reload policy."));
    b.push(Block::Li("archangelctl audit-tail --log <path> --key <hex> — verify and view the audit log."));
    b.push(Block::Li("archangelctl egress-sync [--write] — compile [egress] into a kernel-enforced systemd drop-in."));
    b.push(Block::P("End of guide. For the threat model, architecture, sandbox, egress, and readiness details, see the documents under docs/ in the source repository."));
}
