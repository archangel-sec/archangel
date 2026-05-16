# `/etc/archangel/exec/`

This directory holds the operator-signed `.exec` bundles available to the daemon.

Each bundle is a TOML manifest + payload + detached signature file
(`name.exec` and `name.exec.sig`). Signatures must verify against a key in
`/etc/archangel/trust/operators.pubkeys`.

A "standard library" of safe `.exec` bundles will be distributed in a separate
signed package once the bundle format (`docs/EXEC_FORMAT.md`) is finalized.

Do **not** drop unsigned files here; the executor will refuse them.
