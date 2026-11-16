"""`secret`: secrets for coding agents without the agent seeing the value. Commands: see HELP."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import signal
import socket
import sys
import time

from .policy import socket_path
from .protocol import BrokerError, call, connect, read_reply

EXIT_DENIED = 77
EXIT_BROKER = 78
EXIT_WAITING = 75  # sysexits EX_TEMPFAIL: not yet, try again; 2 stays argparse's usage error


def _sock() -> str:
    return socket_path()


def allowed(item: dict) -> str:
    """What `secret ls` shows for a name: the commands it may go with."""
    if not item["policy"]:
        return "no policy entry: no command gets it"
    return "; ".join(" ".join(prefix) for prefix in item.get("allow", [])) or "nothing"


def cmd_ls(_args) -> int:
    reply = call(_sock(), {"op": "list"})
    if reply.get("note"):
        print(f"note: {reply['note']}", file=sys.stderr)
    if not reply["names"]:
        print("no secrets stored and no policy entries")
        return 0
    width = max(len(n["name"]) for n in reply["names"])
    print(f"{'NAME':<{width}}  {'VALUE':<10}  ALLOWED COMMANDS")
    for item in reply["names"]:
        print(f"{item['name']:<{width}}  {'stored' if item['stored'] else 'not stored':<10}  {allowed(item)}")
    return 0


def cmd_add(args) -> int:
    """Read the value from the terminal, never from arguments or a pipe: an agent has no terminal."""
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        print("secret add needs a terminal; an agent asks with: secret request NAME --why TEXT", file=sys.stderr)
        return 2
    value = getpass.getpass(f"{args.name}: ")
    if not value.strip():
        print("nothing entered; nothing saved", file=sys.stderr)
        return 1
    call(_sock(), {"op": "add", "name": args.name, "value": value})
    print(f"saved {args.name}")
    return 0


def cmd_request(args) -> int:
    """At a terminal the owner is right here: wait. An agent's shell has no terminal: print and return,
    because an agent sees nothing a command prints until the command ends."""
    reply = call(_sock(), {"op": "request", "name": args.name, "why": args.why})
    print(f"Owner: open this link and enter {args.name} (expires in {reply['ttl_minutes']} min):", flush=True)
    print(reply["url"], flush=True)
    if not reply.get("policy", True):
        print(
            f"note: {args.name} has no policy entry yet, so `secret run` will refuse it. The owner adds to "
            f"{reply.get('policy_file') or 'the policy file'}:\n"
            f'  [secrets.{args.name}]\n  allow = [["<program>"]]\n'
            "and runs: sudo systemctl reload secret-broker",
            file=sys.stderr, flush=True,
        )
    if args.no_wait or not sys.stdout.isatty():
        print(f"Then wait for it with: secret wait {args.name}", flush=True)
        return 0
    return _wait(args.name, {"op": "status", "token": reply["token"]}, args.timeout)


def cmd_wait(args) -> int:
    return _wait(args.name, {"op": "status", "name": args.name}, args.timeout)


def _wait(name: str, query: dict, timeout: int) -> int:
    """0 stored, 1 expired or never asked for, 75 still open when the timeout ran out."""
    deadline = time.time() + timeout
    while True:
        state = call(_sock(), query).get("state")
        if state == "stored":
            print(f"stored {name}", flush=True)
            return 0
        if state == "expired":
            print(f"the link for {name} expired before a value was entered; ask again with: secret request {name} --why TEXT", file=sys.stderr)
            return 1
        if state == "unknown":
            print(f"no open request for {name} from you; ask with: secret request {name} --why TEXT", file=sys.stderr)
            return 1
        if time.time() >= deadline:
            print(f"still waiting for {name}; the link stays valid until it expires. Wait again with: secret wait {name}", file=sys.stderr)
            return EXIT_WAITING
        time.sleep(min(2, max(0.1, deadline - time.time())))


def cmd_run(argv: list[str]) -> int:
    """argv = everything after `run`: NAME [NAME...] -- command args...

    The daemon runs the command itself: it gets this process's stdin/stdout/stderr and current
    directory over the socket, writes redacted output to them and replies with the exit code."""
    if "--" not in argv:
        print("usage: secret run NAME [NAME...] -- command args...", file=sys.stderr)
        return 2
    split = argv.index("--")
    names, command = argv[:split], argv[split + 1 :]
    if not names or not command:
        print("usage: secret run NAME [NAME...] -- command args...", file=sys.stderr)
        return 2
    line = json.dumps({"op": "run", "names": names, "argv": command, "env": dict(os.environ)}).encode() + b"\n"
    with connect(_sock()) as sock:
        cwd = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
        try:
            sent = socket.send_fds(sock, [line], [0, 1, 2, cwd])
            sock.sendall(line[sent:])
        except OSError as exc:
            raise BrokerError(f"could not hand the command to the broker: {exc.strerror or exc}") from exc
        finally:
            os.close(cwd)
        sock.settimeout(None)  # the command may run for as long as it likes

        def forward(sig, _frame):
            try:
                sock.sendall(json.dumps({"signal": sig}).encode() + b"\n")
            except OSError:
                pass

        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, forward)
        reply = read_reply(sock)
    return int(reply["exit"])


def cmd_mcp(_args) -> int:
    from .mcp_server import run

    run()
    return 0


def cmd_status(_args) -> int:
    try:
        reply = call(_sock(), {"op": "list"})
    except BrokerError as exc:
        print(f"broker: unreachable ({exc})")
        return 1
    print(f"broker: ok at {_sock()} ({len(reply['names'])} name(s))")
    return 0


HELP = """secrets for coding agents without the agent seeing the value

usage: secret <command> [args]

commands:
  add NAME                        type a value at the terminal and save it (you, not the agent)
  request NAME --why TEXT         print a one-time link where the owner pastes a value (the agent)
  wait NAME                       wait until the value from that link is saved
  run NAME... -- command [args]   run a command with secrets in its environment
  ls                              list names and the commands each may go with, never values
  status                          is the broker reachable?
  mcp                             MCP server on stdio for the agent: secret_request, secret_wait, secret_list

examples:
  secret add GH_TOKEN                          prompts for the value, input hidden
  secret request GH_TOKEN --why "push to ci"   prints a link; open it and paste the value
  secret wait GH_TOKEN                         returns once it's saved (up to 100 s, repeat if needed)
  secret run GH_TOKEN -- gh pr list            gh gets GH_TOKEN in its environment
  secret run A B -- ansible-playbook site.yml  several secrets at once

a secret is only given to the commands listed for it in /etc/secret-broker/policy.toml.
shells, interpreters and printers (sh, python, env, cat, echo, ...) never get one.
after editing the policy: sudo systemctl reload secret-broker

request waits for the value at a terminal; in an agent's shell it prints the link
and returns at once, and the agent waits with secret wait.

exit codes:
  run       the command's own code, 77 when the policy refuses the command,
            78 when the secret isn't stored yet or the broker fails
  wait      0 saved, 75 still waiting (run it again), 1 link expired or never
            asked for, 78 the broker fails
  all       2 wrong usage

secret <command> --help shows a command's options. more: man secret
"""
COMMANDS = ("add", "request", "wait", "run", "ls", "status", "mcp")


def build_parser() -> argparse.ArgumentParser:
    """Options of each command; the overview is HELP."""
    parser = argparse.ArgumentParser(prog="secret", add_help=False)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("add", help="type a value at the terminal and save it (for you, not the agent)")
    p.add_argument("name", help="UPPER_SNAKE_CASE, e.g. GH_TOKEN")
    p.set_defaults(func=cmd_add)
    sub.add_parser("ls", help="list secret names and their allowed commands (never values)").set_defaults(func=cmd_ls)
    p = sub.add_parser("request", help="ask the owner for a value through a one-time link")
    p.add_argument("name")
    p.add_argument("--why", required=True, help="what the value is needed for (shown to the owner)")
    p.add_argument("--no-wait", action="store_true", help="print the link and return, also at a terminal (without a terminal it always returns)")
    p.add_argument("--timeout", type=int, default=900, help="seconds to wait for the owner at a terminal (default 900)")
    p.set_defaults(func=cmd_request)
    p = sub.add_parser("wait", help="wait until the value asked for with `secret request NAME` is saved")
    p.add_argument("name")
    p.add_argument("--timeout", type=int, default=100, help="seconds to wait (default 100, under an agent's 2-minute shell limit)")
    p.set_defaults(func=cmd_wait)
    p = sub.add_parser("run", help="run an allowlisted command with secrets in its environment: secret run NAME [NAME...] -- command args...")
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p.set_defaults(func=lambda a: cmd_run(a.rest))
    sub.add_parser("mcp", help="run the MCP server on stdio").set_defaults(func=cmd_mcp)
    sub.add_parser("status", help="is the broker reachable?").set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if not argv or argv[0] in ("-h", "--help", "help"):
            print(HELP, end="")
            code = 0
        elif argv[0] not in COMMANDS:
            print(f"secret: unknown command {argv[0]!r}\n", file=sys.stderr)
            print(HELP, end="", file=sys.stderr)
            code = 2
        # `run` is parsed by hand: argparse cannot keep NAME... apart from the command after `--`.
        elif argv[0] == "run":
            code = cmd_run(argv[1:])
        else:
            args = build_parser().parse_args(argv)
            code = args.func(args)
    except BrokerError as exc:
        print(f"secret: {exc}", file=sys.stderr)
        code = EXIT_DENIED if exc.code == "denied" else EXIT_BROKER
    except KeyboardInterrupt:
        code = 130
    sys.exit(code)


if __name__ == "__main__":
    main()
