{
  description = "Application packaged using poetry2nix";

  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs";
  inputs.poetry2nix.url = "github:nix-community/poetry2nix/master";

  outputs = { self, nixpkgs, flake-utils, poetry2nix }:
    let
      ttfrevBase = (poetry2nix: {
        projectDir = ./.;
        overrides = poetry2nix.overrides.withDefaults (self: super: { 
          construct-dataclasses = super.construct-dataclasses.overridePythonAttrs (
            old: {
              buildInputs = (old.buildInputs or [ ]) ++ [ super.setuptools ];
            }
          );
        });
      });
    in
    {
      # Nixpkgs overlay providing the application
      overlay = nixpkgs.lib.composeManyExtensions [
        poetry2nix.overlays.default
        (final: prev: {
          # The application
          ttfrev = prev.poetry2nix.mkPoetryApplication ((ttfrevBase prev.poetry2nix) // {
          });
        })
      ];
    } // (flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ self.overlay ];
        };
        ttfrevShell = pkgs.poetry2nix.mkPoetryEnv ((ttfrevBase pkgs.poetry2nix) // {
          editablePackageSources = {
            ttfrev = ./ttfrev;
          };
        });
      in
      {
        apps = {
          ttfrev = pkgs.ttfrev;
        };

        packages = {
          ttfrev = ttfrevShell;
        };

        devShells = {
          ttfrev = ttfrevShell.env;
        };

        defaultApp = pkgs.ttfrev;

        devShell = ttfrevShell.env;
      }));
}
