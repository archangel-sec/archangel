# archangel — Configuration Guide (.docx generator)

Generates **`archangel-configuration-guide.docx`**, a complete, page-by-page
guide to configuring the archangel package.

There is no pandoc/LibreOffice dependency: the content is authored as `Block`s
in `src/main.rs` and rendered to a real `.docx` with the `docx-rs` crate.

## Generate it

```sh
cd book
cargo run        # writes book/archangel-configuration-guide.docx
```

Open the resulting file in Word, LibreOffice, Google Docs, etc.

## Why it lives here but is a separate project

Like `WEB/`, `book/` is a **standalone Cargo project** intentionally excluded
from the archangel workspace (`exclude = ["book"]` in the root `Cargo.toml`).
The guide's tooling (`docx-rs` and its dependencies) must not enter the
security TCB's audit surface. It has its own `Cargo.lock`.

## What it covers (23 chapters)

Safety posture · architecture · installation & `archangel setup` · the config
file · every section (`[daemon]`, `[sockets]`, `[session]`, `[modes]`,
`[llm]`, `[rate_limits]`, `[monitor]`, `[egress]`) key by key · trust & keys ·
`.exec` bundles & the allowlist · systemd units & hardening · filesystem
layout & permissions · the three operating modes in practice · snapshots ·
the sandbox · the audit log · troubleshooting (the real install pitfalls) · a
security checklist · and appendices with a full example config and the
`archangelctl` command reference.

## Editing

Add or change content by editing the chapter functions in `src/main.rs`
(`Block::H1/H2/H3/P/Code/Li/Note`) and re-running. The `.docx` is a build
artifact (git-ignored); regenerate it rather than committing drafts.

## Note

The guide is intentionally complete rather than padded to a fixed page count.
It tracks the v0.4.0 configuration surface; keep it in sync when config keys
change. The pre-alpha "not for production" posture is stated up front and must
remain while the v1.0 gates are unmet.
