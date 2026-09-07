{
  description = "Myc Nostr remote signer";

  inputs = {
    # Crane 0.23+ currently asks nixpkgs' Cargo vendor helper to fetch
    # semver-build-metadata crate versions through the crates.io API. That
    # endpoint rejects the literal `+`; the immutable v0.22.0 input avoids
    # that upstream fetch defect while preserving the same locked sources.
    crane.url = "github:ipetkov/crane/01bc1d404a51a0a07e9d8759cd50a7903e218c82";
    lib = {
      url = "github:radrootslabs/lib/055096853fca95e15d0f813d33a14aca13be3881";
      inputs.crane.follows = "crane";
    };
    nixpkgs.follows = "lib/nixpkgs";
    rust-overlay.follows = "lib/rust-overlay";
  };

  outputs =
    {
      self,
      crane,
      lib,
      nixpkgs,
      rust-overlay,
      ...
    }:
    let
      systems = lib.lib.supportedSystems;
      forAllSystems = function:
        builtins.listToAttrs (
          map (system: {
            name = system;
            value = function system;
          }) systems
        );
      serviceOutputs =
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          helpers = lib.lib.mkServiceHelpers system;
          toolchain = helpers.mkToolchain {
            rustToolchainFile = ./rust-toolchain.toml;
          };
          nativeInputs = helpers.mkNativeInputs { };
          craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;
          source = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter =
              path: type:
              craneLib.filterCargoSources path type
              || pkgs.lib.hasSuffix ".json" (baseNameOf path)
              || baseNameOf path == "README";
            name = "myc-source";
          };
          commonArgs = {
            src = source;
            cargoLock = ./Cargo.lock;
            strictDeps = true;
            nativeBuildInputs = nativeInputs.nativeBuildInputs;
            buildInputs = nativeInputs.buildInputs;
            env = nativeInputs.environment;
            doCheck = false;
          };
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          package = craneLib.buildPackage (
            commonArgs
            // {
              inherit cargoArtifacts;
              pname = "myc";
              version = "0.1.0";
              CARGO_PROFILE = "release";
              cargoExtraArgs = "--locked --package myc --bin myc";
            }
          );
          mkCargoCheck =
            name: command: extraArgs:
            craneLib.mkCargoDerivation (
              commonArgs
              // extraArgs
              // {
                inherit cargoArtifacts;
                pname = "myc-${name}";
                version = "1";
                buildPhaseCargoCommand = command;
                installPhaseCommand = "mkdir -p $out";
              }
            );
          checks = {
            fmt = craneLib.cargoFmt (
              commonArgs
              // {
                pname = "myc-fmt";
                version = "1";
              }
            );
            check = mkCargoCheck "check" "cargo check --workspace --all-targets --locked" { };
            test = mkCargoCheck "test" "cargo test --workspace --all-targets --locked" { };
            clippy = mkCargoCheck "clippy" "cargo clippy --workspace --all-targets --locked -- -D warnings" { };
            docs = mkCargoCheck "docs" "cargo doc --workspace --no-deps --locked" {
              RUSTDOCFLAGS = "-D warnings";
            };
            config = package;
            integration = package;
            package = package;
            source-lock = package;
            sqlx = package;
          };
          apps = helpers.mkServiceApps {
            serviceName = "myc";
            binaryName = "myc";
            inherit nativeInputs package toolchain;
            releaseAcceptanceCommand = ''
              ${package}/bin/myc \
                --profile repo-local \
                --instance nix-release-acceptance \
                --repo-local-root "$PWD" \
                config schema >/dev/null
            '';
          };
          devShells.default = helpers.mkServiceDevShell {
            serviceName = "myc";
            inherit nativeInputs toolchain;
          };
          oci = helpers.mkServiceOciImage {
            serviceName = "myc";
            binaryName = "myc";
            inherit package;
            buildInfo = {
              serviceVersion = "0.1.0";
              serviceCommit = self.rev or "0000000000000000000000000000000000000000";
              libRevision = "055096853fca95e15d0f813d33a14aca13be3881";
              rustVersion = "1.97.1";
              target = "x86_64-unknown-linux-gnu";
              featureProfile = "service-host";
              contractVersions = {
                config = 1;
                state = 12;
                admin = 1;
                status = 1;
                provider = 1;
              };
            };
          };
        in
        helpers.mkServiceOutputs {
          serviceName = "myc";
          inherit
            apps
            checks
            devShells
            nativeInputs
            package
            ;
          extraPackages = if system == "x86_64-linux" then { inherit oci; } else { };
        };
    in
    {
      packages = forAllSystems (system: (serviceOutputs system).packages);
      apps = forAllSystems (system: (serviceOutputs system).apps);
      checks = forAllSystems (system: (serviceOutputs system).checks);
      devShells = forAllSystems (system: (serviceOutputs system).devShells);

      nixosModules.default =
        let
          helpers = lib.lib.mkServiceHelpers "x86_64-linux";
        in
        helpers.mkServiceNixosModule {
          serviceName = "myc";
          binaryName = "myc";
          packageFor = _pkgs: self.packages.x86_64-linux.default;
          commandForInstance = instance: [
            "--profile"
            "service-host"
            "--instance"
            instance
            "--config"
            "/etc/radroots/services/myc/${instance}/config.toml"
            "run"
          ];
        };
    };
}
