{ self }:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.secret-broker;
  toml = pkgs.formats.toml { };
  settingsFile = toml.generate "secret-broker-policy.toml" cfg.settings;
in
{
  options.services.secret-broker = {
    enable = lib.mkEnableOption "the secret broker daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.secret-broker;
      description = "secret-broker package (provides secret and secret-brokerd).";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "secret-broker";
      description = "Group that may open the broker socket. Add agent users to it.";
    };

    extraPath = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [ ];
      description = "Backend tools the daemon needs on PATH (bws, age).";
    };

    settings = lib.mkOption {
      inherit (toml) type;
      default = { };
      description = "Contents of /etc/secret-broker/policy.toml (see the README).";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];
    environment.etc."secret-broker/policy.toml".source = settingsFile;

    users.groups.${cfg.group} = { };
    users.users.secret-broker = {
      isSystemUser = true;
      group = cfg.group;
      home = "/var/lib/secret-broker";
      description = "secret-broker daemon";
    };

    systemd.services.secret-broker = {
      description = "Secret broker for coding agents";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      # A policy change reloads (SIGHUP) instead of restarting, so running `secret run` commands go on.
      reloadTriggers = [ settingsFile ];
      path = cfg.extraPath ++ [ pkgs.coreutils ];
      environment.SECRET_BROKER_CONFIG = "/etc/secret-broker/policy.toml";
      serviceConfig = {
        # Started once the socket and the page accept connections; a reload waits until then.
        Type = "notify";
        ExecStart = "${cfg.package}/bin/secret-brokerd";
        ExecReload = "${cfg.package}/bin/secret-brokerd check --reload $MAINPID";
        User = "secret-broker";
        Group = cfg.group;
        StateDirectory = "secret-broker";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "secret-broker";
        RuntimeDirectoryMode = "0750";
        UMask = "0007";
        Restart = "on-failure";
        RestartSec = "5s";
        # `secret run` children are started here as the calling user and must see /home and /tmp like any
        # process of that user, so no ProtectHome/ProtectSystem/PrivateTmp; SETUID/SETGID switch to the
        # user (cleared before exec), KILL forwards signals to a child that no longer runs as this uid.
        AmbientCapabilities = [ "CAP_SETUID" "CAP_SETGID" "CAP_KILL" ];
        CapabilityBoundingSet = [ "CAP_SETUID" "CAP_SETGID" "CAP_KILL" ];
        NoNewPrivileges = true;
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
      };
    };
  };
}
