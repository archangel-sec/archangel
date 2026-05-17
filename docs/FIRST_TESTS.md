# First tests — running archangel locally (read-only, v0.1)

> **Pre-alpha.** This runs the read-only milestone with a *local* test
> tree (no root, no `/etc`, no systemd). It is for trying the system, not
> for production. The executor in v0.1 uses process-level hardening only
> (the kernel sandbox, layer #11, is v0.2) and runs **read-only** bundles.

You will run three processes in three terminals:

```
archangelctl  ──signed──▶  archangeld  ──signed──▶  archangel-execd
 (you, terminal 3)         (terminal 1)             (terminal 2)
```

The LLM backend is **local Ollama** — no API key, fully offline.

---

## 0. Prerequisites

- Rust toolchain (the repo's `rust-toolchain.toml` pins it).
- [Ollama](https://ollama.com) running locally with a capable
  instruction-following model pulled, e.g.:

  ```sh
  ollama serve &              # if not already running
  ollama pull llama3.1:8b     # smaller models often fail the strict
                              # JSON contract — that is expected, see §7
  ```

- Build the binaries:

  ```sh
  cargo build
  # → target/debug/{archangeld, archangel-execd, archangelctl}
  ```

---

## 1. Create a local test tree

```sh
export A="$HOME/archangel-test"
mkdir -p "$A"/etc/archangel/{trust,policies,exec} \
         "$A"/var/log/archangel "$A"/run/archangel
export BIN="$PWD/target/debug"
```

## 2. Main config (`archangel.toml`)

Paths must be **absolute**; `control_mode` must not grant "other"
(fail-closed validation will refuse otherwise).

```sh
cat > "$A/etc/archangel/archangel.toml" <<EOF
[daemon]
trust_store = "$A/etc/archangel/trust/operators.pubkeys"
audit_log   = "$A/var/log/archangel/audit.log.jsonl"

[sockets]
control      = "$A/run/archangel/ctl.sock"
control_mode = 0o660
exec         = "$A/run/archangel/exec.sock"

[modes]
default = "read_only"

[llm]
default_backend = "ollama"
EOF
```

## 3. Operator key + trust store

```sh
"$BIN/archangelctl" init \
  --secret "$A/etc/archangel/trust/operator.key" \
  --public "$A/etc/archangel/trust/operator.pub"

# For first tests the operator is also the .exec bundle signer:
cp "$A/etc/archangel/trust/operator.pub" \
   "$A/etc/archangel/trust/operators.pubkeys"
```

## 4. A signed read-only `.exec` bundle

```sh
cp packaging/etc-archangel/exec/read-uptime.exec "$A/etc/archangel/exec/"
"$BIN/archangelctl" bundle-sign \
  "$A/etc/archangel/exec/read-uptime.exec" \
  --secret "$A/etc/archangel/trust/operator.key"
# → writes read-uptime.exec.sig
```

## 5. Allowlist

```sh
cat > "$A/etc/archangel/policies/allowlist.toml" <<'EOF'
[[profile]]
name = "default"
mode = "read_only"
allowed_exec = ["read-uptime"]
EOF
```

## 6. Preflight

```sh
"$BIN/archangelctl" doctor \
  --etc "$A/etc/archangel" \
  --operator-key "$A/etc/archangel/trust/operator.key"
```

On WSL/desktop you may see `WARN` for systemd/cgroup — that is fine for
first tests. Any `FAIL` must be resolved.

---

## 7. Run it

**Terminal 1 — the daemon.** It prints two keys you need next.

```sh
ARCHANGEL_OLLAMA_URL="http://127.0.0.1:11434" RUST_LOG=info \
"$BIN/archangeld" \
  --config         "$A/etc/archangel/archangel.toml" \
  --allowlist      "$A/etc/archangel/policies/allowlist.toml" \
  --bundle-dir     "$A/etc/archangel/exec" \
  --operator-pubkey "$A/etc/archangel/trust/operator.pub" \
  --audit-key      "$A/etc/archangel/trust/audit.key" \
  --operator-uid   "$(id -u)"
```

It logs:

```
archangel-execd must be started with --session-pubkey-hex <SESSION_HEX>
audit log public key (pin this ...): <AUDIT_HEX>
control plane listening
```

Copy `<SESSION_HEX>` and `<AUDIT_HEX>`.

**Terminal 2 — the executor** (uses `<SESSION_HEX>` from terminal 1):

```sh
"$BIN/archangel-execd" \
  --socket            "$A/run/archangel/exec.sock" \
  --peer-uid          "$(id -u)" \
  --session-pubkey-hex <SESSION_HEX> \
  --operators         "$A/etc/archangel/trust/operators.pubkeys" \
  --allowlist         "$A/etc/archangel/policies/allowlist.toml" \
  --bundle-dir        "$A/etc/archangel/exec"
```

**Terminal 3 — you, the operator:**

```sh
"$BIN/archangelctl" session \
  --secret "$A/etc/archangel/trust/operator.key" \
  --socket "$A/run/archangel/ctl.sock"
```

At the `›` prompt:

- `/ping` — should print `pong` (proves the signed boundary-A path).
- `show me the system uptime` — the model should choose the
  `read-uptime` action; the pipeline runs it in the executor and prints
  the real `uptime` output in a sanitized block.
- `/quit` to exit.

## 8. Verify the audit trail

```sh
"$BIN/archangelctl" audit-tail \
  --log "$A/var/log/archangel/audit.log.jsonl" \
  --key <AUDIT_HEX>
```

You should see `AUDIT CHAIN VERIFIED` and the full decision chain
(session start → LLM request/response → policy decision → exec
requested → exec completed).

---

## What you are actually testing

- **`/ping`** exercises the operator Ed25519 signature + peer-cred gate
  (boundary A).
- A task exercises the whole spine: defended prompt (#1–#4) → LLM →
  canary/bounded-parse (#3/#5) → signed bundle verify (#6/#7) → denylist
  + allowlist (#8/#9) → signed boundary-B request → the executor
  re-verifying everything → the hash-chained audit log (#15).

### Expected "failures" that are actually successes

- **`Denied: model-contract`** — the model returned prose instead of the
  exact JSON action. That is layer #5 working. Use a more capable model.
- **`Denied: policy / not allowlisted`** — the model picked an action
  not in your allowlist. Working as designed.
- **`session aborted ... canary`** — the model leaked the canary; the
  session is correctly killed (#3).
- Try editing `read-uptime.exec`'s payload to something destructive like
  `rm -rf /` (keep `read_only = true`), re-sign, and run it: the
  **denylist (#8)** must stop it *before* the executor — proof the
  authoritative layer holds even for a validly-signed bundle.

If something hangs or errors, check terminal 1/2 logs (`RUST_LOG=debug`
for more), and confirm the `--socket` paths match `archangel.toml`.
