# Archangel — Egress filtering (threat-model layer #17)

> Status: **v0.3, policy core.** The fail-closed egress *decision* —
> `archangel-egress` + the `[egress]` config — is implemented and tested.
> The *structural enforcement* that makes a denied connection impossible
> (not merely "decided against") is the next unit; this document is its
> contract.

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

## 3. The enforcement (next unit)

The policy decides; enforcement must make "deny" *unbypassable*. Planned, in
order of strength:

1. **Daemon network confinement (structural).** Restrict the `archangeld`
   process so the kernel only lets it reach allowlisted endpoints:
   - *systemd `IPAddressAllow=`* generated from the allowlist resolved to IPs
     at setup time. Kernel-enforced (eBPF/cgroup), unbypassable by the
     process — but IP-based, so CDN-fronted APIs (rotating IPs) need
     periodic regeneration. This is why `IPAddressAllow=` cannot take a
     hostname directly.
   - *Egress proxy + network namespace* — the daemon has no direct route; all
     traffic goes through a small-TCB proxy that allowlists by hostname/SNI.
     Strongest and hostname-native, but a larger subsystem.
2. **App-level connector guard (defense in depth).** The LLM client checks
   every destination against `EgressPolicy` before connecting and refuses a
   non-allowlisted host. This catches a *steered* (not yet RCE'd) daemon and
   documents intent, but a raw-syscall RCE bypasses it — hence it complements,
   never replaces, the structural layer.
3. **Action egress.** For bundles that opt into `network = "egress"`, the
   sandbox applies the same `EgressPolicy` to the action's network namespace.

## 4. Honest scope

Implemented now: the fail-closed decision (`archangel-egress`) and its
config, validated at startup. **Not yet enforced on the wire** — a denied
destination is currently only "would be denied," not "cannot be reached."
Until the structural layer lands, the daemon's egress is bounded the way the
operator set it up (e.g. the `IPAddressDeny=any` + `IPAddressAllow=` in the
systemd unit, edited by hand). Do not rely on #17 as a containment guarantee
before the enforcement unit ships.
