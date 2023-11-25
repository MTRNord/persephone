{
  description = "Persephone is an experimental and WIP matrix homeserver written in C++20.";

  # Nixpkgs / NixOS version to use.
  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";
  inputs.flake-compat = {
    url = "github:edolstra/flake-compat";
    flake = false;
  };

  outputs = {
    self,
    nixpkgs,
    flake-compat,
  }: let
    # to work with older version of flakes
    lastModifiedDate = self.lastModifiedDate or self.lastModified or "19700101";

    # Generate a user-friendly version number.
    version = builtins.substring 0 8 lastModifiedDate;

    # System types to support.
    supportedSystems = ["x86_64-linux" "aarch64-linux"];

    # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
    forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

    # Nixpkgs instantiated for supported system types.
    nixpkgsFor = forAllSystems (system:
      import nixpkgs {
        inherit system;
        overlays = [self.overlays.default];
      });
  in {
    formatter.x86_64-linux = nixpkgs.legacyPackages.x86_64-linux.alejandra;

    # A Nixpkgs overlay.
    overlays.default = final: prev: {
      persephone = with final;
        stdenv.mkDerivation rec {
          pname = "persephone";
          inherit version;

          src = ./.;

          postUnpack = let
            # URLs manually extracted from subprojects directory
            cpp-httplib-wrap = fetchurl {
              name = "cpp-httplib-wrap";
              url = "https://github.com/yhirose/cpp-httplib/archive/v0.14.1.tar.gz";
              hash = "sha256-LU+1VE2mQ+XQqCWFVV2LdQK0E36zIaSruwdeIdLwDpY=";
            };
            soci-wrap = fetchurl {
              name = "soci-wrap";
              url = "https://github.com/SOCI/soci/archive/refs/tags/v4.0.3.tar.gz";
              hash = "sha256-Sx/5yFRcXYAvvgbubNKIZjDlwDv3QOJpu2JbRc+TSSg=";
            };
          in ''
            pushd $sourceRoot/subprojects
            mkdir cpp-httplib-0.14.1
            tar xvf ${cpp-httplib-wrap} -C cpp-httplib-0.14.1 --strip-components 1
            mkdir soci-4.0.3
            tar xvf ${soci-wrap} -C soci-4.0.3 --strip-components 1
            popd
          '';

          nativeBuildInputs = [meson ninja pkg-config cmake];
          buildInputs = [yaml-cpp soci libsodium nlohmann_json httplib openssl zlib brotli];

          meta = with pkgs.lib; {
            homepage = "https://git.nordgedanken.dev/mtrnord/persephone";
            license = with licenses; [agpl3Plus];
            maintainers = ["MTRNord"];
            platforms = platforms.linux;
          };

          doCheck = true;
        };
    };

    # Provide some binary packages for selected system types.
    packages = forAllSystems (system: rec {
      inherit (nixpkgsFor.${system}) persephone;
      default = persephone;
    });

    # A NixOS module, if applicable (e.g. if the package provides a system service).
    nixosModules.persephone = {pkgs, ...}: {
      nixpkgs.overlays = [self.overlay];

      environment.systemPackages = [pkgs.persephone];

      systemd.services.persephone = {
        wantedBy = ["multi-user.target"];
        serviceConfig.ExecStart = "${pkgs.persephone}/bin/persephone";
      };
    };

    # Tests run by 'nix flake check' and by Hydra.
    checks =
      forAllSystems
      (
        system:
          with nixpkgsFor.${system};
            {
              inherit (self.packages.${system}) persephone;

              # # Additional tests, if applicable.
              # test = stdenv.mkDerivation {
              #   pname = "persephone-test";
              #   inherit version;

              #   buildInputs = [persephone];

              #   dontUnpack = true;

              #   buildPhase = ''
              #     echo 'running some integration tests'
              #     [[ $(hello) = 'Hello Nixers!' ]]
              #   '';

              #   installPhase = "mkdir -p $out";
              # };
            }
            // lib.optionalAttrs stdenv.isLinux {
              # A VM test of the NixOS module.
              vmTest = with import (nixpkgs + "/nixos/lib/testing-python.nix") {
                inherit system;
              };
                makeTest {
                  nodes = {
                    client = {...}: {
                      imports = [self.nixosModules.persephone];
                    };
                  };

                  testScript = ''
                    start_all()
                    client.wait_for_unit("multi-user.target")
                    client.succeed("persephone")
                  '';
                };
            }
      );
  };
}
