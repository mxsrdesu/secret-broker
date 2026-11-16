# secret-broker

secrets for coding agents (claude code, codex) without the agent seeing the value.

the agent asks for a secret by name. you get a one-time link and type the value
on a page. later the agent runs a command with that secret: the broker starts
the command itself, puts the value into its environment and strips the value
from its output. in the agent's shell:

```console
$ secret request GH_TOKEN --why "open the release pr"
Owner: open this link and enter GH_TOKEN (expires in 15 min):
http://127.0.0.1:8787/r/q3Vt9xK2mZ8bR1wE5yL0aC7dF4hJ6nP-sT2uW8vX0yA
Then wait for it with: secret wait GH_TOKEN
$ secret wait GH_TOKEN
stored GH_TOKEN
$ secret run GH_TOKEN -- gh pr create --fill
```

## install

requires linux with systemd and python 3.12 or newer (debian 13, ubuntu 24.04
or later). the broker runs as its own system user, so the agent can't read the
store. your user joins the `secret-broker` group to reach it.

### nixos

```nix
# flake.nix
inputs.secret-broker.url = "github:mxsrdesu/secret-broker";

# configuration
imports = [ inputs.secret-broker.nixosModules.default ];
services.secret-broker = {
  enable = true;
  extraPath = [ pkgs.age ];        # pkgs.bws for bitwarden
  settings = {                     # policy.toml, see config
    allowed_uids = [ 1000 ];
    backend = "agefile";
    backends.agefile = { dir = "/var/lib/secret-broker/store"; identity = "/var/lib/secret-broker/age.key"; };
    secrets.GH_TOKEN.allow = [ [ "gh" ] ];
  };
};
users.users.<you>.extraGroups = [ "secret-broker" ];
```

### other linux

on debian or ubuntu, `sudo apt install git python3-venv age` first. then:

```sh
git clone https://github.com/mxsrdesu/secret-broker && cd secret-broker
sudo python3 -m venv /opt/secret-broker
sudo /opt/secret-broker/bin/pip install .
sudo ln -s /opt/secret-broker/bin/secret /opt/secret-broker/bin/secret-brokerd /usr/local/bin/
sudo install -D -m 644 /opt/secret-broker/share/man/man1/secret.1 /usr/local/share/man/man1/secret.1
sudo useradd --system --home-dir /var/lib/secret-broker --shell /usr/sbin/nologin secret-broker
sudo usermod -aG secret-broker "$USER"
sudo install -D -m 644 examples/policy.toml /etc/secret-broker/policy.toml
sudo sed -i "s/^allowed_uids = \[1000\]/allowed_uids = [$(id -u)]/" /etc/secret-broker/policy.toml
sudo cp systemd/secret-broker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now secret-broker
```

log out and back in so the new group applies, then check with
`secret status`.

### the page

the page listens on `127.0.0.1:8787`, so links open on the same machine. to
open them from your phone, publish the page somewhere private, e.g. inside a
tailnet: `sudo tailscale serve --bg --https=443 http://127.0.0.1:8787`, and set
`public_base_url` to that address. don't publish it without https: the value
travels in the form.

## pick a store

**age** (the default): one encrypted file per secret in
`/var/lib/secret-broker/store`; the key is made on first start. nothing else to
set up.

**bitwarden secrets manager**: the values live in your bitwarden organization,
so several machines can share them.

1. in the web vault (`vault.bitwarden.com`, or `vault.bitwarden.eu`), use an
   organization you own or create one. in admin console → billing →
   subscription, subscribe to secrets manager; the free plan is enough.
2. open secrets manager from the product switcher. new → project, e.g. `agents`.
3. new → machine account. in its projects tab add the project with
   **can read, write**: the broker creates the secret when you save a value.
4. in its access tokens tab, create an access token and copy it. it is shown
   once.
5. install `bws`: on nixos `extraPath = [ pkgs.bws ]`; elsewhere unzip
   `bws-x86_64-unknown-linux-gnu-*.zip` (or `aarch64`) from a `bws-v*` release at
   [bitwarden/sdk-sm](https://github.com/bitwarden/sdk-sm/releases) and
   `sudo install -m 755 bws /usr/local/bin/`.
6. in `policy.toml` set `backend = "bws"` and fill `[backends.bws]` (see
   [examples/policy.toml](examples/policy.toml)), then
   `sudo systemctl restart secret-broker`.
7. at that machine's terminal, `sudo secret add BWS_ACCESS_TOKEN` and paste the
   token. or `sudo secret-brokerd bootstrap` prints a link to paste it on.

`secret ls` shows no `note:` line once bitwarden is connected.

## connect your agent

claude code:

```sh
claude plugin marketplace add mxsrdesu/secret-broker
claude plugin install secret-broker@secret-broker
```

codex:

```sh
codex plugin marketplace add mxsrdesu/secret-broker
codex plugin add secret-broker@secret-broker
```

the plugin brings the mcp server (`secret mcp`: `secret_request`,
`secret_wait`, `secret_list`) and a skill that tells the agent when to ask for a
secret, to show you the link, to wait, and what to do when the policy refuses.
claude code 2.1.287 or later opens the link from a dialog; other agents print
it.

other agents: copy [the skill](plugins/secret-broker/skills/secret-broker) into
the agent's skills folder (`~/.agents/skills/` for cursor and gemini cli), add
`secret mcp` as a stdio mcp server, or put a line like this in `AGENTS.md`:

```md
Secrets go through secret-broker: `secret ls`, then `secret request NAME --why "..."`, show the user the link,
`secret wait NAME`, then `secret run NAME -- command`. Never ask for a value in the chat, never print one.
```

a sandboxed shell can't reach the broker by default, and `secret` says so. in
claude code with the sandbox on, add `"secret *"` to `sandbox.excludedCommands`;
in codex's `workspace-write`, set `sandbox_workspace_write.network_access = true`,
which also lets other sandboxed commands reach the network.

## usage

```sh
secret add GH_TOKEN                                 # you, at a terminal: type the value, input hidden
secret request GH_TOKEN --why "push and watch ci"   # agent: prints a one-time link and returns
secret wait GH_TOKEN                                # agent: returns once the value is saved
secret run GH_TOKEN -- gh run watch 123             # runs gh with GH_TOKEN set
secret ls                                           # names and allowed commands, never values
secret status                                       # is the broker reachable?
```

at a terminal `secret request` waits for the value itself. links live for
`request_ttl_minutes` and work once; the page writes the value straight into
the store. `secret --help` and `man secret` list every command and exit code.

## config

`/etc/secret-broker/policy.toml`, starting from
[examples/policy.toml](examples/policy.toml). after editing it,
`sudo systemctl reload secret-broker`: it checks the file first and keeps the
running policy if the file is broken. a new `socket`, `http_bind` or store needs
`sudo systemctl restart secret-broker`, which also stops running commands.

```toml
[secrets.GH_TOKEN]
allow = [["gh"]]
deny = ["--hostname"]                  # optional: arguments this secret never goes with

[secrets.GITLAB_TOKEN]
allow = [["glab"], ["git", "push"], ["git", "fetch"]]
```

`allow` lists command prefixes. the broker looks the program up only in
`trusted_path`, never in the agent's `PATH`. by default that's
`/run/wrappers/bin`, the nixos profiles, `/usr/local/bin`, `/usr/bin` and `/bin`; set `trusted_path = [...]`
to change it, and never add a directory the agent can write to, like
`~/.local/bin`. shells,
interpreters and printers (`sh`, `python`, `env`, `cat`, `echo`, …) never get
a secret. for `git`, `-c`, `--config-env`, `--exec-path`, `--receive-pack`,
`--upload-pack` and `--exec` are refused; for `gh`, `alias` and `extension`.

the command must read the secret from its environment: `$GH_TOKEN` on the
agent's command line expands in the agent's shell, where it's empty. for http
apis, curl 8.3 or newer reads it itself:
`secret run API_TOKEN -- curl --variable %API_TOKEN --expand-header 'Authorization: Bearer {{API_TOKEN}}' https://…`

## what it protects against

the value doesn't reach the chat, transcripts, memory, logs or the model
provider by accident. the agent can't ask the broker for the value directly:
the broker never hands it out, it only starts allowlisted commands.

it doesn't stop an agent that sets out to steal a secret. a running command
belongs to your user, so its environment is readable in `/proc/<pid>/environ`
while it runs. allowlisted tools also run code the agent can write: git hooks
and repo config, ansible playbooks. keep allowlists short and commands
short-lived. commands started by `secret run` run outside the agent's sandbox.

commands started by `secret run` have no terminal, so interactive prompts
fail, and restarting the broker stops commands that are still running. a value
is one line: multi-line keys (pem, json) can't be entered.

`bws` takes a new value as a command-line argument, so on a shared host mount
`/proc` with `hidepid=invisible`; otherwise other users can see the value in
`ps` for about a second while it's saved.

## if it doesn't work

| `secret` says | do |
| --- | --- |
| no access to the secret broker | join the `secret-broker` group, then log out and back in |
| the agent's sandbox blocks the connection | the sandbox settings under connect your agent |
| the secret broker isn't running | `systemctl status secret-broker`, `journalctl -u secret-broker` |
| … has no policy entry / is not allowed for | add or extend `[secrets.NAME]`, then `sudo systemctl reload secret-broker` |
| … is not stored yet | `secret request NAME --why "…"` |
| note: Bitwarden Secrets Manager is not configured | `sudo secret add BWS_ACCESS_TOKEN` |

the service logs one line when `policy.toml` is wrong at start;
`secret-brokerd check` prints the same, and warns about keys it doesn't know.

## checks

```sh
nix develop
pytest
```

`nix flake check` also runs the nixos module in a vm. ci runs both, and the
install above on a fresh ubuntu machine (`scripts/e2e-install.sh`).

[mit license](LICENSE).
