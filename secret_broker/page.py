"""HTML for the page where the owner enters a value. Every argument is escaped here."""

from __future__ import annotations

import html

ERRORS = {
    "empty": "Enter a value",
    "stale": "This form is out of date. Reload the page and try again",
    "store": "The secret store didn't accept {name}. Try again. If it keeps failing, the reason is in the broker's log on {host}: journalctl -u secret-broker",
    "setup": "Bitwarden isn't connected on {host} yet. In a terminal on {host}, run sudo secret add BWS_ACCESS_TOKEN and paste the key of your Bitwarden machine account. Then save here again; what you typed stays in the field",
}


def request_form(name: str, why: str, nonce: str, seconds_left: int, host: str, error: str = "") -> str:
    """`error` is a key of ERRORS. The form posts through fetch so a failed save keeps the typed value;
    without JavaScript it is a plain form post."""
    message = ERRORS[error].format(name=name, host=host) if error else ""
    product = _product(host)
    name, why, nonce = (html.escape(v) for v in (name, why, nonce))
    seconds_left = max(0, int(seconds_left))
    why_line = f'<p class="why">{why}</p>' if why else ""
    body = f"""
{product}
<h1>{_breakable(name)}</h1>
{why_line}
<form method="post" autocomplete="off" id="form">
  <input type="hidden" name="check" value="{nonce}">
  <label for="value">Value</label>
  <div class="field">
    <input id="value" name="value" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" autofocus required aria-describedby="err"{' aria-invalid="true"' if error == "empty" else ''}>
    <button type="button" class="show" id="show" aria-controls="value">Show</button>
  </div>
  <p class="err" id="err" role="alert">{_command(html.escape(message))}</p>
  <button type="submit" class="save" id="save">Save {name}</button>
</form>
<p class="meta"><span id="expiry" data-left="{seconds_left}">Expires in <span class="num">{seconds_left // 60}:{seconds_left % 60:02d}</span></span><br>Goes to the secret store, not the chat</p>
<script>{_SCRIPT}</script>
"""
    return _html(name, body)


def _product(host: str) -> str:
    return f'<p class="product">secret-broker on {html.escape(host)}</p>'


def _command(text: str) -> str:
    for command in ("journalctl -u secret-broker", "sudo secret add BWS_ACCESS_TOKEN"):
        text = text.replace(command, f'<span class="mono">{command}</span>')
    return text


def _breakable(name: str) -> str:
    """Long names wrap after an underscore, not in the middle of a word."""
    return name.replace("_", "_<wbr>")


def expired(host: str, name: str = "") -> str:
    """`name` is empty when the link is unknown (never issued, or forgotten an hour after expiry)."""
    ask = f'Ask the agent for a new <span class="mono">{html.escape(name)}</span> link' if name else "Ask the agent for a new one"
    return _html("This link has expired", f'{_product(host)}<h1 class="title">This link has expired</h1><p class="why">{ask}</p>')


def already_stored(name: str, host: str) -> str:
    name = html.escape(name)
    return _html("This link was already used", f'{_product(host)}<h1 class="title">This link was already used</h1><p class="why"><span class="mono">{name}</span> is saved. You can close this tab</p>')


def stored(name: str, host: str) -> str:
    name = html.escape(name)
    return _html(f"{name} saved", f'{_product(host)}<h1 class="title"><span class="mono">{name}</span> saved</h1><p class="why">The agent can use it now. You can close this tab</p>')


# Show/Hide, the expiry countdown, and a fetch submit that keeps the value when the save fails.
_SCRIPT = """
(() => {
  const form = document.getElementById("form"), value = document.getElementById("value");
  const show = document.getElementById("show"), save = document.getElementById("save");
  const err = document.getElementById("err"), expiry = document.getElementById("expiry");
  const label = save.textContent;
  show.addEventListener("click", () => {
    const hidden = value.type === "password";
    value.type = hidden ? "text" : "password";
    show.textContent = hidden ? "Hide" : "Show";
    value.focus();
  });
  const end = Date.now() + Number(expiry.dataset.left) * 1000;
  const tick = () => {
    const left = Math.max(0, Math.round((end - Date.now()) / 1000));
    if (left === 0) {
      expiry.textContent = "This link has expired";
      save.disabled = true;
      return;
    }
    expiry.querySelector(".num").textContent = Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0");
    setTimeout(tick, 1000);
  };
  tick();
  let busy = false;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || save.disabled) return;
    busy = true;
    save.textContent = "Saving\\u2026";
    save.setAttribute("aria-busy", "true");
    try {
      const reply = await fetch(location.href, { method: "POST", body: new URLSearchParams(new FormData(form)) });
      const doc = new DOMParser().parseFromString(await reply.text(), "text/html");
      const message = doc.getElementById("err");
      if (message && message.textContent) {
        err.textContent = message.textContent;
        value.toggleAttribute("aria-invalid", doc.getElementById("value")?.getAttribute("aria-invalid") === "true");
        value.focus();
      } else {
        document.title = doc.title;
        document.body.replaceChildren(...doc.body.children);
        return;
      }
    } catch {
      err.textContent = "Couldn't reach the broker. Check the connection and try again";
    }
    busy = false;
    save.textContent = label;
    save.removeAttribute("aria-busy");
  });
})();
"""


def _html(title: str, body: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer">
<title>{title} · secret-broker</title>
<style>
/* Gruvbox Dark Hard roles; values from the palette, nothing else. */
:root{{
  --canvas:#1d2021;--panel:#282828;--raised:#3c3836;
  --text:#ebdbb2;--text-2:#d5c4a1;--muted:#bdae93;
  --action:#fabd2f;--action-hover:#d79921;--on-action:#1d2021;--focus:#fabd2f;--error:#fb4934;
  --border:#504945;--border-control:#928374;
  --mono:ui-monospace,"JetBrains Mono",SFMono-Regular,Menlo,monospace;
  color-scheme:dark;
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--canvas);color:var(--text);font:15px/21px system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:400px;margin:18vh auto 48px;padding:0 16px}}
.product{{margin:0 0 24px;font:13px/20px var(--mono);color:var(--muted)}}
h1{{margin:0;font:500 24px/32px var(--mono);overflow-wrap:break-word}}
h1.title{{font:500 20px/28px system-ui,-apple-system,"Segoe UI",sans-serif}}
.mono{{font-family:var(--mono)}}
.why{{margin:4px 0 0;color:var(--text-2);overflow-wrap:anywhere}}
form{{margin-top:24px}}
label{{display:block;margin-bottom:8px;font-size:14px;color:var(--text-2)}}
.field{{position:relative}}
#value{{width:100%;height:40px;padding:0 72px 0 12px;font:15px var(--mono);color:var(--text);background:var(--panel);border:1px solid var(--border-control);border-radius:6px}}
#value:focus{{outline:2px solid var(--focus);outline-offset:1px}}
#value[aria-invalid=true]{{border-color:var(--error)}}
.show{{position:absolute;top:4px;right:4px;height:32px;min-width:56px;padding:0 12px;font:14px system-ui,sans-serif;color:var(--text-2);background:var(--raised);border:1px solid var(--border);border-radius:4px;cursor:pointer}}
.show:hover{{color:var(--text)}}
.show:focus-visible,.save:focus-visible{{outline:2px solid var(--focus);outline-offset:2px}}
.err{{margin:8px 0 0;font-size:14px;line-height:20px;color:var(--error)}}
.err:empty{{display:none}}
.err .mono{{white-space:nowrap}}
.save{{display:block;width:100%;height:40px;margin-top:16px;font:500 15px system-ui,sans-serif;color:var(--on-action);background:var(--action);border:0;border-radius:6px;cursor:pointer;transition:background-color .12s ease-out}}
.save:hover{{background:var(--action-hover)}}
.save[aria-busy=true]{{cursor:progress}}
.save:disabled{{color:var(--muted);background:var(--raised);cursor:not-allowed}}
.meta{{margin:24px 0 0;font-size:13px;line-height:20px;color:var(--muted)}}
.num{{font-family:var(--mono);font-variant-numeric:tabular-nums}}
@media (prefers-reduced-motion:reduce){{.save{{transition:none}}}}
</style></head><body><main>{body}</main></body></html>"""
