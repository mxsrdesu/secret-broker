{
  description = "secret-broker: secrets for coding agents without the agent ever seeing a value";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      mkPackage = pkgs: pkgs.python3Packages.buildPythonApplication {
        pname = "secret-broker";
        version = "0.1.0";
        pyproject = true;
        src = pkgs.lib.cleanSource ./.;
        build-system = [ pkgs.python3Packages.setuptools ];
        dependencies = with pkgs.python3Packages; [ mcp starlette uvicorn ];
        nativeCheckInputs = [ pkgs.python3Packages.pytestCheckHook pkgs.age ];
        meta = {
          description = "Secret broker for coding agents";
          mainProgram = "secret";
          license = pkgs.lib.licenses.mit;
        };
      };
    in
    {
      packages = forAll (pkgs: rec {
        secret-broker = mkPackage pkgs;
        default = secret-broker;
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.python3.withPackages (ps: [ ps.mcp ps.starlette ps.uvicorn ps.pytest ]))
            pkgs.age
            pkgs.uv
          ];
          shellHook = ''export PYTHONPATH="$PWD:''${PYTHONPATH:-}"'';
        };
      });

      nixosModules.default = import ./nix/module.nix { inherit self; };

      checks = forAll (pkgs: {
        module = import ./nix/test.nix { inherit self pkgs; };
      });
    };
}
