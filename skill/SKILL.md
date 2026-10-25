---
name: op-gate
description: op-gate runs 1Password `op` commands after the owner approves each one with a passkey on their phone. Use when running `op` where OP_FORWARD_ADDR is set, or when `op` returns an op-gate error (denied, no approval in time, not allowed, no token).
---

# op-gate

`op` here is the op-forward shim. It sends each command to op-gate, which notifies the owner's phone and runs the real `op` only after they approve with a passkey. Approval takes a person: expect each new command to wait up to 4 minutes.

## Running commands

Put the subcommand first, then its arguments and flags: `op item get X --format json`.

op-gate allows only these, and rejects anything else without asking the owner:

| Command | Use |
|---|---|
| `op read "op://Vault/Item/field"` | one field |
| `op item get`, `op item list` | items |
| `op vault get`, `op vault list` | vaults |
| `op document get` | documents |
| `op whoami` | the service account |

Ask for exactly what the task needs, in as few commands as possible. Each distinct command is a separate tap for the owner.

If a bare `op` says "no active session", it reached the real 1Password CLI instead of the shim. Call the shim by its full path (`command -v -a op` lists both).

## Approvals and caching

The owner can tap **Approve** (this request only) or **Approve and cache for 1 hour**. A cached approval lets the same exact command from the same client run again without a tap, until it goes 5 minutes unused or an hour passes. Changing any argument, flag, or its order is a new command and asks again. Reuse the exact command line when you need the same secret twice.

## When op-gate says no

op-gate errors arrive on stderr as `op-gate: ...` with exit code 1:

- `denied` or `no approval within 4m0s`: the owner said no or wasn't available. Stop and tell the owner which secret you needed and why. Retrying sends them another notification.
- `"<cmd>" is not allowed`: rewrite it as an allowed command above, subcommand first.
- `this client has no token`: set up the client token below, then retry once.

## Client token

op-gate identifies each client by the token on the first line of `access.token` in the op-forward token directory (`$OP_FORWARD_TOKEN_DIR`, or `~/.cache/op-forward` when that's unset), in the form `<name>:<secret>`. The name is shown on the owner's approval page. Cached approvals belong to one token, so a machine keeps the same token for life.

Create a token only when `access.token` is missing or holds `placeholder`. Use the machine's short hostname as the name, lowercased, with any character outside `a-z`, `0-9`, `.`, `-` replaced by `-` (1 to 32 characters):

```sh
dir="${OP_FORWARD_TOKEN_DIR:-$HOME/.cache/op-forward}"
name=$(hostname -s | tr 'A-Z' 'a-z' | tr -c 'a-z0-9.\n-' '-' | cut -c1-32)
printf '%s:%s\n2099-01-01T00:00:00Z\n' "$name" "$(openssl rand -hex 32)" > "$dir/access.token"
cp "$dir/access.token" "$dir/refresh.token"
chmod 600 "$dir/access.token" "$dir/refresh.token"
```

When `access.token` holds anything else, it's this machine's identity: keep it, and ask the owner if op-gate rejects it.
