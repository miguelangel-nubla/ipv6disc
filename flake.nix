{
  description = "ipv6disc: finds the hosts on the local network and their addresses, over IPv6 and IPv4";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      # Where the command runs, of the systems nixpkgs has.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forEachSystem = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      # A flake knows its commit, not its tag: the version is the commit's.
      version = self.shortRev or self.dirtyShortRev or "dev";
      package = pkgs: pkgs.callPackage ./nix/package.nix { inherit version; };
    in
    {
      packages = forEachSystem (pkgs: rec {
        ipv6disc = package pkgs;
        default = ipv6disc;
      });

      overlays.default = final: _prev: { ipv6disc = package final; };

      # nix flake check: the package builds, which tells a hash of the modules that is behind
      # go.sum, and the command it has says its version.
      checks = forEachSystem (pkgs: {
        package = package pkgs;
        version =
          pkgs.runCommand "ipv6disc-version"
            {
              nativeBuildInputs = [ (package pkgs) ];
            }
            ''
              ipv6disc --version | grep -x "ipv6disc ${version}"
              test -s ${package pkgs}/share/man/man1/ipv6disc.1.gz
              touch $out
            '';
      });

      formatter = forEachSystem (pkgs: pkgs.nixfmt-rfc-style);
    };
}
