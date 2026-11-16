# The NixOS module in a VM: the service starts with its real unit, a user in the group asks for a
# secret, the page saves it, `secret run` gets it, and a policy change reloads instead of restarting.
{ self, pkgs }:
pkgs.testers.runNixOSTest {
  name = "secret-broker";

  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.default ];
    services.secret-broker = {
      enable = true;
      extraPath = [ pkgs.age ];
      settings = {
        http_bind = "127.0.0.1:8787";
        public_base_url = "http://127.0.0.1:8787";
        allowed_uids = [ 1000 ];
        backend = "agefile";
        backends.agefile = {
          dir = "/var/lib/secret-broker/store";
          identity = "/var/lib/secret-broker/age.key";
        };
        secrets.DEMO_TOKEN.allow = [ [ "sb-show" ] ];
      };
    };
    users.users.alice = {
      isNormalUser = true;
      uid = 1000;
      extraGroups = [ "secret-broker" ];
    };
    environment.systemPackages = [
      pkgs.curl
      (pkgs.writeShellScriptBin "sb-show" ''echo "user=$(id -un) value=$DEMO_TOKEN''${NEW_TOKEN:-}"'')
    ];
    specialisation.more-secrets.configuration = {
      services.secret-broker.settings.secrets.NEW_TOKEN.allow = [ [ "sb-show" ] ];
    };
  };

  testScript = ''
    import shlex

    value = "vm-test-value-7f3a9c"

    def alice(cmd, code=0):
        status, out = machine.execute(f"su - alice -c {shlex.quote(cmd)}")
        assert status == code, f"{cmd}: exit {status}, wanted {code}: {out}"
        return out

    machine.wait_for_unit("secret-broker.service")
    assert alice("secret status").startswith("broker: ok")
    assert "DEMO_TOKEN" in alice("secret ls")

    with subtest("request, the page, wait, run"):
        out = alice("secret request DEMO_TOKEN --why vm-test")
        url = next(line for line in out.splitlines() if line.startswith("http"))
        assert "secret wait DEMO_TOKEN" in out
        alice("secret wait DEMO_TOKEN --timeout 1", code=75)
        check = machine.succeed(f"curl -fsS {url} | grep -o 'name=\"check\" value=\"[^\"]*\"' | cut -d'\"' -f4").strip()
        machine.succeed(f"curl -fsS --data-urlencode check={check} --data-urlencode value={value} {url} | grep -q saved")
        assert alice("secret wait DEMO_TOKEN").strip() == "stored DEMO_TOKEN"
        assert alice("secret run DEMO_TOKEN -- sb-show").strip() == "user=alice value=[REDACTED:DEMO_TOKEN]"
        alice("secret run DEMO_TOKEN -- sh -c true", code=77)
        alice("secret run NEW_TOKEN -- sb-show", code=77)

    with subtest("a policy change reloads the running broker"):
        pid = machine.succeed("systemctl show -p MainPID --value secret-broker").strip()
        machine.succeed("/run/current-system/specialisation/more-secrets/bin/switch-to-configuration test")
        assert machine.succeed("systemctl show -p MainPID --value secret-broker").strip() == pid
        assert "NEW_TOKEN" in alice("secret ls")
        machine.succeed("journalctl -u secret-broker | grep -q 'policy reloaded'")

    with subtest("a reload right after a restart waits for the broker instead of killing it"):
        machine.succeed("systemctl restart secret-broker && systemctl reload secret-broker")
        machine.succeed("systemctl is-active secret-broker")
        assert alice("secret status").startswith("broker: ok")

    with subtest("the value is nowhere in the journal"):
        machine.fail(f"journalctl -u secret-broker | grep -qF {value}")
  '';
}
