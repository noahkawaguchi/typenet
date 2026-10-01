{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs, rust-overlay, ... }:
    {
      devShells = nixpkgs.lib.genAttrs [ "aarch64-linux" "x86_64-linux" ] (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };

          default = pkgs.mkShell {
            packages = with pkgs; [
              # Use nightly for formatting only
              rust-bin.nightly.latest.rustfmt
              (rust-bin.stable."1.97.1".minimal.override {
                extensions = [
                  "rust-src"
                  "rust-analyzer"
                  "clippy"
                  "llvm-tools-preview"
                ];
              })

              cargo-llvm-cov
              codebook
              inetutils
              iproute2
              just
              netcat
            ];
          };
        in
        {
          inherit default;

          docker = pkgs.mkShell {
            inputsFrom = [ default ];

            packages = with pkgs; [
              # Only include TShark in the Docker shell because if it's used in the native setup, it
              # should be set up on the host (see README), and including `tshark`/`wireshark-cli` in
              # the devShell would shadow the privileged Dumpcap with an unprivileged one
              tshark

              # The user is root inside the container, so `sudo` calls in the `justfile` only need
              # to run the command as is
              (writeShellScriptBin "sudo" ''exec "$@"'')
            ];

            shellHook = "alias j=just";
          };
        }
      );
    };
}
