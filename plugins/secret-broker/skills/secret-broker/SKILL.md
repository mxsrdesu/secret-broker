---
name: secret-broker
description: Get and use API keys, tokens and passwords through secret-broker without ever seeing them. Use whenever a command needs a credential (GH_TOKEN, a cloud or registry token, a password), when a command fails for missing auth, and before asking the user for any secret.
---

# secret-broker

secret-broker keeps credentials out of the conversation. The user types a value on a one-time page; you only ever use the secret's name.

## Rules

- Never ask the user to paste a secret into the chat. Never print, echo, cat or log a value, write one to a file, or put one on a command line.
- A value reaches a command only through `secret run`.

## Get and use a secret

1. `secret ls` shows each name, whether it is stored, and the commands it may go with.
2. Stored and allowed: `secret run NAME -- command args`.
3. Not stored: `secret request NAME --why "what it's for, in a few words"`. It prints a one-time link and returns at once.
   - Before anything else, write a message to the user with the link exactly as printed and what the value is for. The user may not see command output, and the link is not a secret.
   - Only then run `secret wait NAME`. Exit 75 means the user hasn't saved it yet: run it again, each call waits up to 100 s. Exit 0: go to step 2. Exit 1: the link expired; ask again only if the user still wants to go on. Exit 78: see below.
   - With the MCP tools instead: `secret_request`, give the user the link it returns, then `secret_wait` until it says stored.
4. Pick the name the program reads from its environment: `GH_TOKEN` for gh, `GITLAB_TOKEN` for glab, `HCLOUD_TOKEN` for hcloud, `CLOUDFLARE_API_TOKEN` for wrangler.

## How the command gets the value

- The broker starts the command itself and sets `NAME` in its environment. `$NAME` on your command line expands in your own shell, where it is empty, so use programs that read the variable themselves.
- HTTP APIs: curl 8.3 or newer reads it itself:
  `secret run API_TOKEN -- curl --variable %API_TOKEN --expand-header 'Authorization: Bearer {{API_TOKEN}}' https://api.example.com/v1/...`
- Shells, interpreters and printers (`sh`, `bash`, `python`, `node`, `env`, `cat`, `echo`, ...) never get a secret, so don't wrap the command in `sh -c`.
- The value shows up as `[REDACTED:NAME]` in the output. The command has no terminal, so interactive prompts fail.
- `secret run` starts the command outside your sandbox, as the user. Run only what the task needs.

## When it refuses

- Exit 77, `no policy entry` or `is not allowed for`: only the owner can change the policy. Show them what to add and stop until they say it's done; don't try other programs to get around it.
  ```toml
  [secrets.NAME]
  allow = [["gh"]]          # the command prefixes this secret may go with
  ```
  then `sudo systemctl reload secret-broker`. On NixOS it goes into `services.secret-broker.settings.secrets.NAME.allow`, then a rebuild.
- Exit 77 for a shell or interpreter, or for git `-c` and friends: by design. Run the program directly.
- Exit 78, `not stored yet`: step 3. Exit 78 with another message: the broker can't be reached or failed, see the lines below.
- `the agent's sandbox blocks the connection`: tell the user the setting the message names (Claude Code: add `"secret *"` to `sandbox.excludedCommands`; Codex: `sandbox_workspace_write.network_access = true`), or ask to run the command outside the sandbox.
- `no access to the secret broker`: the user must be in the `secret-broker` group and log in again.
- `isn't running`: the user checks `systemctl status secret-broker`.
- `secret: command not found`: secret-broker isn't installed on this machine. Tell the user; don't fall back to asking for the value in the chat.
