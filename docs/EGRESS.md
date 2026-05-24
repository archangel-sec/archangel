# Archangel — Egress filtering (threat-model layer #17)

> Status: **v0.3.** The fail-closed egress *decision* (`archangel-egress` +
> `[egress]` config) and the *systemd structural enforcer*
> (`archangelctl egress-sync`, kernel-level `IPAddressAllow=` from the
> resolved allowlist) are implemented and tested. A hostname-native egress
> proxy and per-action egress remain future work (§3).

## 1. What #17 is for

Layer #17 exists so that **exfiltration is structurally impossible**: even if
a component is fully compromised, it cannot open a connection to an
attacker-controlled destination. It is the last containment net — if prompt
defenses, the denylist, signing, the sandbox, and rate limits all failed and
something tried to phone home, #17 is what stops the packet leaving.

Two egress surfaces:

- **The daemon (T3) → the LLM.** The daemon must reach *exactly* the
  configured model endpoint and nothing else. This is the primary exfil
  vector (a subverted daemon trying to POST stolen data somewhere).
- **Sandboxed actions.** An action only has network if its bundle's
  `[sandbox] network` opts in. For the default/`inspect` profile, the seccomp
  filter (#11) already makes `socket(AF_INET/AF_INET6)` fatal — so a
  read-only action *cannot create a network socket at all*, regardless of
  egress rules. #17 governs the actions that do opt into egress.

## 2. The decision: `archangel-egress` (implemented)

`EgressPolicy` answers one question, fail-closed: may we connect to
`(host, port)`?

- `default_policy = "deny"` (the secure default) ⇒ only explicit `host` /
  `host:port` allowlist entries are permitted; everything else is denied.
- `default_policy = "allow"` ⇒ permit everything (local dev only; callers
  must warn loudly).
- Host matching is exact and case-insensitive — **no implicit subdomain
  matching** (`anthropic.com` does not imply `api.anthropic.com`). A bare
  `host` allows any port; `host:port` pins the port.
- Malformed entries (bad port, IPv6 literal, illegal characters) are refused
  at config load — a typo narrows nothing open by accident.

`Config::validate` compiles the `[egress]` allowlist, so a bad entry refuses
daemon startup rather than silently widening egress.

## 3. Enforcement

The policy decides; enforcement makes "deny" *unbypassable*. In order of
strength:

1. **Daemon network confinement via systemd — implemented.**
   `archangelctl egress-sync` compiles the `[egress]` allowlist into a
   systemd drop-in for `archangeld`: it resolves each allowlisted host to its
   current IPs and emits `IPAddressDeny=any` + `IPAddressAllow=localhost <ips>`.
   That filter is **kernel-enforced** (eBPF/cgroup) and unbypassable by the
   process — even a fully compromised daemon cannot send a packet to a
   non-allowlisted address.

   ```sh
   archangelctl egress-sync                 # print the drop-in (dry run)
   sudo archangelctl egress-sync --write    # install it
   sudo systemctl daemon-reload && sudo systemctl restart archangeld
   ```

   Two honest limits: it is **IP-granular** (ports are dropped — `IPAddressAllow`
   has no port concept), and **IP-pinned** — a CDN-fronted API (rotating IPs)
   needs `egress-sync` re-run when its addresses change (a timer is reasonable).
   `localhost` is always allowed so a loopback model endpoint and the
   `systemd-resolved` stub keep working.

2. **Egress proxy + network namespace — future.** The hostname-native,
   rotation-proof alternative: the daemon has no direct route and all traffic
   goes through a small-TCB proxy that allowlists by hostname/SNI. Strongest,
   but a larger subsystem; deferred.
3. **Action egress — future.** For bundles that opt into `network = "egress"`,
   the sandbox will apply the same `EgressPolicy` to the action's network
   namespace. Until then, the default/`inspect` seccomp profile already makes
   action `socket(AF_INET)` fatal, so non-network actions cannot egress at all.

## 4. Scope today

Implemented: the fail-closed decision (`archangel-egress`), its config
(validated at startup), and the systemd structural enforcer (`egress-sync`).
The enforcer is **opt-in** (the operator runs it) so it never silently breaks
a working daemon; once applied, it is a real kernel-level containment of the
daemon's egress. The proxy (hostname-native) and per-action egress remain
future work — until the proxy lands, treat the IP-pinned drop-in as "precise
but needs re-sync on rotation," not "set and forget."
