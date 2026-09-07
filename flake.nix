{
  description = "Myc Nostr remote signer";

  inputs.lib.url = "github:radrootslabs/lib/055096853fca95e15d0f813d33a14aca13be3881";

  outputs =
    { self, lib }:
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
          helpers = lib.lib.mkServiceHelpers system;
          toolchain = helpers.mkToolchain {
            rustToolchainFile = ./rust-toolchain.toml;
          };
          nativeInputs = helpers.mkNativeInputs { };
          package = helpers.mkServicePackage {
            inherit nativeInputs toolchain;
            source = ./.;
            cargoLock = ./Cargo.lock;
            servicePackage = "myc";
            binaryName = "myc";
          };
          hooks = {
            config = package;
            integration = package;
            source-lock = package;
            sqlx = package;
          };
          checks = helpers.mkServiceChecks {
            serviceName = "myc";
            inherit
              hooks
              nativeInputs
              package
              toolchain
              ;
            source = ./.;
            cargoLock = ./Cargo.lock;
          };
          apps = helpers.mkServiceApps {
            serviceName = "myc";
            binaryName = "myc";
            inherit nativeInputs package toolchain;
            releaseAcceptanceCommand = "${package}/bin/myc --help >/dev/null";
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
