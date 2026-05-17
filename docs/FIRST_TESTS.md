# First tests — running archangel locally (read-only, v0.1)

> **Pre-alpha.** Read-only milestone, local test tree, no production use.
> The executor uses process-level hardening only (the kernel sandbox,
> layer #11, is v0.2) and runs **read-only** bundles.

Both daemons are **config-driven**: you start each with just
`--config /path/archangel.toml`. `archangeld` publishes its per-run
session public key to a file; `archangel-execd` reads it automatically —
**no copying keys between terminals**.

```
archangelctl  ──signed──▶  archangeld  ──signed──▶  archangel-execd
 (you, terminal 3)         (terminal 1)             (terminal 2)
```

The LLM backend is **local Ollama** (no API key, offline). Anthropic/
Claude alternative is noted at the end.

---

## 0. Prerequisites

```sh
ollama serve &            # if not already running
ollama pull llama3.1:8b   # small models often fail the strict JSON
                          # contract — that's layer #5 working (see §7)
cargo build               # → target/debug/{archangeld,archangel-execd,archangelctl}
```

## 1. Local test tree

```sh
export A="$HOME/archangel-test"
export BIN="$PWD/target/debug"
export UID_ME="$(id -u)"
mkdir -p "$A"/etc/archangel/{trust,policies,exec} \
         "$A"/var/log/archangel "$A"/run/archangel
```

## 2. Config (`archangel.toml`)

`operator_uid` and `daemon_uid` are **required**. For a single-user
local test both are just your own uid.

```sh
cat > "$A/etc/archangel/archangel.toml" <<EOF
[daemon]
trust_store     = "$A/etc/archangel/trust/operators.pubkeys"
audit_log       = "$A/var/log/archangel/audit.log.jsonl"
audit_key       = "$A/etc/archangel/trust/audit.key"
operator_pubkey = "$A/etc/archangel/trust/operator.pub"
allowlist       = "$A/etc/archangel/policies/allowlist.toml"
bundle_dir      = "$A/etc/archangel/exec"
session_pub     = "$A/run/archangel/session.pub"

[sockets]
control      = "$A/run/archangel/ctl.sock"
control_mode = 0o660
exec         = "$A/run/archangel/exec.sock"
operator_uid = $UID_ME
daemon_uid   = $UID_ME

[modes]
default = "read_only"

[llm]
default_backend = "ollama"
EOF
```

## 3. Operator key + trust + sample bundle + allowlist

```sh
"$BIN/archangelctl" init \
  --secret "$A/etc/archangel/trust/operator.key" \
  --public "$A/etc/archangel/trust/operator.pub"
cp "$A/etc/archangel/trust/operator.pub" \
   "$A/etc/archangel/trust/operators.pubkeys"

cp packaging/etc-archangel/exec/read-uptime.exec "$A/etc/archangel/exec/"
"$BIN/archangelctl" bundle-sign \
  "$A/etc/archangel/exec/read-uptime.exec" \
  --secret "$A/etc/archangel/trust/operator.key"

cat > "$A/etc/archangel/policies/allowlist.toml" <<'EOF'
[[profile]]
name = "default"
mode = "read_only"
allowed_exec = ["read-uptime"]
EOF

"$BIN/archangelctl" doctor \
  --etc "$A/etc/archangel" \
  --operator-key "$A/etc/archangel/trust/operator.key"
```

(`WARN` for systemd/cgroup on WSL is fine; any `FAIL` must be fixed.)

---

## 4. Run it (3 terminals, config-driven)

**Terminal 1 — daemon:**

```sh
ARCHANGEL_OLLAMA_URL="http://127.0.0.1:11434" RUST_LOG=info \
"$BIN/archangeld" --config "$A/etc/archangel/archangel.toml"
```

It logs (note: you do **not** need to copy the session key anymore — it
is written to `session_pub`):

```
session public key published to .../run/archangel/session.pub (...)
audit log public key (pin this ...): <AUDIT_HEX>
control plane listening
```

Copy only `<AUDIT_HEX>` (for step 5).

**Terminal 2 — executor** (same config; reads the session key file itself):

```sh
RUST_LOG=info "$BIN/archangel-execd" \
  --config "$A/etc/archangel/archangel.toml"
```

**Terminal 3 — you, the operator:**

```sh
"$BIN/archangelctl" session \
  --secret "$A/etc/archangel/trust/operator.key" \
  --socket "$A/run/archangel/ctl.sock"
```

At the `›` prompt:

- `/ping` → `pong` (proves operator signature + boundary A).
- `show me the system uptime` → the model picks `read-uptime`; the
  executor runs `uptime` and its output is shown in a sanitized block.
- `/quit`.

## 5. Verify the audit trail

```sh
"$BIN/archangelctl" audit-tail \
  --log "$A/var/log/archangel/audit.log.jsonl" \
  --key <AUDIT_HEX>
```

Expect `AUDIT CHAIN VERIFIED` and the full decision chain.

---

## 6. Installing the `.deb` — the 3-step path

No pre-built release yet; build the packages once, then it is 3 steps.

```sh
cargo install cargo-deb
cargo build --release -p archangeld -p archangel-execd -p archangelctl -p archangel
for p in archangeld archangel-execd archangelctl archangel; do
  cargo deb -p "$p" --no-build
done
```

**Step 1 — install** (the `archangel` meta-package pulls the other three;
installing all the local .debs together lets apt resolve order):

```sh
sudo apt install ./target/debian/archangel*_0.0.0-1_amd64.deb
```

**Step 2 — bootstrap** (one command: keys, trust, sample bundle,
allowlist, validated config, preflight; idempotent, never clobbers):

```sh
# Ollama (offline):
sudo archangel setup --backend ollama
# …or Anthropic/Opus 4.7 (prompts for the token with echo OFF; or pass
# --token-file PATH). The token is written 0600 to /etc/archangel/llm.env,
# never to argv or the config:
sudo archangel setup --backend anthropic
```

`setup` auto-detects the operator UID (via `SUDO_UID`) and the
`archangel` daemon UID. `archangel <cmd>` is just a friendly alias for
`archangelctl <cmd>` (`archangel doctor`, `archangel session`, …).

**Step 3 — run** (systemd; units are config-driven and hardened):

```sh
sudo systemctl enable --now archangel-execd archangeld
archangel session --secret /etc/archangel/trust/operator.key \
                   --socket /run/archangel/ctl.sock
```

> Anthropic under systemd: the hardened unit has `IPAddressDeny=any`
> (no egress). Allow the API with a drop-in (`sudo systemctl edit
> archangeld` → `[Service]` → `IPAddressAllow=<anthropic ip/cidr>`), or
> use the offline Ollama backend. The manual run (sections 1–5) has no IP
> filter and needs no drop-in.

---

## 7. "Failures" that are actually successes

- **`Denied: model-contract`** — the model returned prose, not the exact
  JSON action. Layer #5 working. Use a more capable model.
- **`Denied: policy / not allowlisted`** — the model picked an action
  not in your allowlist. Working as designed.
- **`session aborted ... canary`** — the model leaked the canary; the
  session is correctly killed (#3).
- Edit `read-uptime.exec`'s `inline` to `rm -rf /` (keep
  `read_only = true`), `bundle-sign` again, run it: the **denylist (#8)**
  stops it *before* the executor — a validly-signed bundle still cannot
  bypass the authoritative layer.

If the executor logs `session key unavailable; dropping connection`,
`archangeld` has not published `session_pub` yet (start it first, or
check the `session_pub` path matches in the config).

Run terminals 1/2 with `RUST_LOG=debug` for detail. Confirm the socket
and `session_pub` paths in the config all point inside `$A/run/archangel`.
