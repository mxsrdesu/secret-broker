#!/usr/bin/env bash
# The README's "other linux" install, run as written on a fresh debian or ubuntu machine, then the
# whole path a user and an agent take: status, request, the page, wait, run, refusals, reload, mcp.
#
# Installs system-wide: run it only on a throwaway machine (CI) or in a container.
#   scripts/e2e-install.sh              with systemd (the CI runner)
#   scripts/e2e-install.sh --no-systemd in a container: the daemon is started the way the unit starts it
set -euo pipefail

mode=systemd
[ "${1:-}" = "--no-systemd" ] && mode=none
src=$(cd "$(dirname "$0")/.." && pwd)
me=$(id -un)
value="e2e-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
out=$(mktemp -d)
step() { printf '\n== %s\n' "$*"; }
fail() {
    echo "FAIL: $*" >&2
    if [ "$mode" = systemd ]; then sudo journalctl -u secret-broker --no-pager -n 30 >&2 || true
    elif [ -f "$out/daemon.log" ]; then tail -20 "$out/daemon.log" >&2; fi
    exit 1
}
# A new login of the same user: sudo -u reads the groups again, so secret-broker applies.
as_user() { sudo -u "$me" -H -- "$@"; }

daemon_pid() {
    if [ "$mode" = systemd ]; then systemctl show -p MainPID --value secret-broker; return; fi
    for d in /proc/[0-9]*; do
        if tr '\0' ' ' < "$d/cmdline" 2>/dev/null | grep -q '^[^ ]*python[0-9.]* /opt/secret-broker/bin/secret-brokerd'; then
            basename "$d"; return
        fi
    done
}

reload_broker() {
    if [ "$mode" = systemd ]; then
        sudo systemctl reload secret-broker || return
        sleep 1  # ExecReload returns once the signal is sent
    else
        # what the unit's ExecReload runs, as the service user
        sudo -u secret-broker env SECRET_BROKER_CONFIG=/etc/secret-broker/policy.toml \
            /opt/secret-broker/bin/secret-brokerd check --reload "$(daemon_pid)" || return
        sleep 1
    fi
}

step "packages from the readme"
apt_line=$(grep -o 'sudo apt install [a-z0-9 .-]*' "$src/README.md" | head -1)
[ -n "$apt_line" ] || fail "no apt line in the readme"
sudo apt-get update -q
${apt_line/apt install/apt-get install -y -q} curl

step "install steps from the readme"
awk '/^### other linux/{f=1} f&&/^```sh/{c=1;next} c&&/^```/{exit} c' "$src/README.md" > "$out/install.sh"
[ -s "$out/install.sh" ] || fail "no install block in the readme"
grep -q '^git clone ' "$out/install.sh" || fail "the install block doesn't start with git clone"
sed -i "s|^git clone .*|cd '$src'|" "$out/install.sh"
[ "$mode" = none ] && sed -i '/systemctl/d' "$out/install.sh"
cat "$out/install.sh"
bash -euxo pipefail "$out/install.sh"

# A program that prints the secret, root-owned in the trusted path, and two policy entries for it.
sudo tee /usr/local/bin/sb-e2e-show > /dev/null <<'EOF'
#!/bin/sh
printf 'user=%s value=%s\n' "$(id -un)" "$E2E_TOKEN$E2E_MISSING"
EOF
sudo chmod 755 /usr/local/bin/sb-e2e-show

if [ "$mode" = none ]; then
    step "start the daemon as the unit does (no systemd in this container)"
    sudo install -d -o secret-broker -g secret-broker -m 0700 /var/lib/secret-broker
    sudo install -d -o secret-broker -g secret-broker -m 0750 /run/secret-broker
    sudo env SECRET_BROKER_CONFIG=/etc/secret-broker/policy.toml setpriv \
        --reuid=secret-broker --regid=secret-broker --init-groups --no-new-privs \
        --inh-caps=-all,+setuid,+setgid,+kill --ambient-caps=-all,+setuid,+setgid,+kill \
        --bounding-set=-all,+setuid,+setgid,+kill \
        sh -c 'umask 0007; exec /opt/secret-broker/bin/secret-brokerd' > "$out/daemon.log" 2>&1 &
fi
# This shell doesn't have the new group yet, and /run/secret-broker is 0750.
for _ in $(seq 50); do sudo test -S /run/secret-broker/sock && break; sleep 0.2; done
sudo test -S /run/secret-broker/sock || fail "the broker didn't open its socket"

step "status"
as_user secret status | tee "$out/status"
grep -q '^broker: ok' "$out/status" || fail "broker not reachable"
as_user secret --help | grep -q 'wait NAME' || fail "help has no wait"
[ -e /usr/local/share/man/man1/secret.1 ] || fail "man page not installed"
if sudo secret-brokerd bootstrap > "$out/bootstrap" 2>&1; then fail "bootstrap with agefile should refuse"; fi
grep -q 'no credential to bootstrap' "$out/bootstrap" || fail "secret-brokerd not on sudo's PATH: $(cat "$out/bootstrap")"

step "a new secret without a policy entry: request says so, run refuses"
as_user secret request E2E_TOKEN --why "e2e" > "$out/req0" 2> "$out/req0.err"
grep -q '\[secrets.E2E_TOKEN\]' "$out/req0.err" || fail "request didn't name the missing policy entry"
if as_user secret run E2E_TOKEN -- sb-e2e-show > /dev/null 2> "$out/run0.err"; then fail "run without policy"; else rc=$?; fi
[ "$rc" = 77 ] && grep -q 'no policy entry' "$out/run0.err" || fail "expected 77 no policy entry, got $rc"

step "add the policy entries, reload without a restart"
pid_before=$(daemon_pid)
[ -n "$pid_before" ] || fail "can't find the broker's pid"
sudo tee -a /etc/secret-broker/policy.toml > /dev/null <<'EOF'

[secrets.E2E_TOKEN]
allow = [["sb-e2e-show"]]

[secrets.E2E_MISSING]
allow = [["sb-e2e-show"]]
EOF
reload_broker
pid_after=$(daemon_pid)
[ "$pid_before" = "$pid_after" ] || fail "reload restarted the service"
as_user secret ls | tee "$out/ls"
grep -q 'E2E_TOKEN .* sb-e2e-show' "$out/ls" || fail "ls doesn't show the allowed command"

step "request without a terminal returns at once; the page saves the value; wait sees it"
start=$(date +%s)
as_user secret request E2E_TOKEN --why "e2e" > "$out/req" 2> "$out/req.err"
[ $(( $(date +%s) - start )) -lt 10 ] || fail "request blocked"
cat "$out/req"
url=$(grep -m1 '^http' "$out/req")
grep -q 'secret wait E2E_TOKEN' "$out/req" || fail "request didn't name the next step"
if as_user secret wait E2E_TOKEN --timeout 1 2> "$out/wait1.err"; then fail "wait before saving"; else rc=$?; fi
[ "$rc" = 75 ] || fail "wait before saving: expected 75, got $rc"
check=$(curl -fsS "$url" | grep -o 'name="check" value="[^"]*"' | cut -d'"' -f4)
[ -n "$check" ] || fail "no form on the page"
curl -fsS -o "$out/saved.html" --data-urlencode "check=$check" --data-urlencode "value=$value" "$url"
grep -q 'saved' "$out/saved.html" || fail "page didn't save"
as_user secret wait E2E_TOKEN | tee "$out/wait"
grep -q '^stored E2E_TOKEN' "$out/wait" || fail "wait didn't see the value"

step "run: the command gets the value as the user, the output is redacted"
as_user secret run E2E_TOKEN -- sb-e2e-show | tee "$out/run"
grep -qx "user=$me value=\[REDACTED:E2E_TOKEN\]" "$out/run" || fail "unexpected run output"
if as_user secret run E2E_TOKEN -- sh -c 'echo $E2E_TOKEN' > "$out/sh" 2>&1; then fail "sh got a secret"; else rc=$?; fi
[ "$rc" = 77 ] || fail "sh: expected 77, got $rc"
if as_user secret run E2E_MISSING -- sb-e2e-show > "$out/missing" 2>&1; then fail "missing value ran"; else rc=$?; fi
[ "$rc" = 78 ] && grep -q 'not stored yet' "$out/missing" || fail "missing: expected 78 not stored yet, got $rc"

step "a broken policy is refused on reload; the running policy stays"
sudo cp /etc/secret-broker/policy.toml "$out/policy.good"
echo 'this is not toml [' | sudo tee -a /etc/secret-broker/policy.toml > /dev/null
if reload_broker > "$out/reload.bad" 2>&1; then fail "a broken policy reloaded"; fi
as_user secret run E2E_TOKEN -- sb-e2e-show | grep -q 'REDACTED:E2E_TOKEN' || fail "policy lost after a bad reload"
sudo cp "$out/policy.good" /etc/secret-broker/policy.toml

step "mcp server over stdio, as the agent starts it"
as_user /opt/secret-broker/bin/python - > "$out/mcp" <<'EOF'
import anyio
from mcp import Client, StdioServerParameters

async def main():
    async with Client(StdioServerParameters(command="secret", args=["mcp"])) as client:
        result = await client.call_tool("secret_list", {})
        print(result.content[0].text)

anyio.run(main)
EOF
cat "$out/mcp"
grep -q 'E2E_TOKEN: stored; allowed: sb-e2e-show' "$out/mcp" || fail "mcp secret_list"

step "the value never showed up in anything the user or the agent saw"
if grep -rlF "$value" "$out" --exclude=daemon.log; then fail "value leaked into the files above"; fi
if [ "$mode" = systemd ]; then
    sudo journalctl -u secret-broker --no-pager > "$out/journal"
    if grep -qF "$value" "$out/journal"; then fail "value in the journal"; fi
    rm "$out/journal"
elif grep -qF "$value" "$out/daemon.log"; then
    fail "value in the daemon log"
fi

if [ "$mode" = systemd ]; then
    step "a reload right after a restart: systemd holds it until the broker is ready"
    sudo systemctl restart secret-broker
    sudo systemctl reload secret-broker
    systemctl is-active --quiet secret-broker || fail "the broker died on an early reload"
    as_user secret status | grep -q '^broker: ok' || fail "broker not reachable after restart and reload"
fi

echo
echo "PASS: install and agent path ($mode)"
