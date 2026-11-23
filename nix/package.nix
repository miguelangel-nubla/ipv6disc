# The command, built from this source, with its manual page.
{
  lib,
  buildGoModule,
  installShellFiles,
  version,
}:

buildGoModule {
  pname = "ipv6disc";
  inherit version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../go.sum
      ../pkg/config/schema.json
      ../cmd/ipv6disc/example.config.yaml
      ../docs/ipv6disc.1
      (lib.fileset.fileFilter (file: file.hasExt "go") ../.)
    ];
  };

  # The hash of the modules go.sum names: tools/nix-test.sh --update writes it, after a change
  # of them, and nix flake check fails while it is behind.
  vendorHash = "sha256-x3cbSLy8kdxgR7WvLjgOC5bXfxKWjN83W+UEqGAFWzA=";

  subPackages = [ "cmd/ipv6disc" ];

  env.CGO_ENABLED = 0;

  ldflags = [
    "-s"
    "-w"
    "-X main.version=${version}"
  ];

  # The tests are CI's, which runs them where they have what they need: a network, and root.
  doCheck = false;

  nativeBuildInputs = [ installShellFiles ];

  postInstall = ''
    installManPage docs/ipv6disc.1
    install -Dm644 cmd/ipv6disc/example.config.yaml $out/share/ipv6disc/example.config.yaml
  '';

  meta = {
    description = "Finds the hosts on the local network and their addresses, over IPv6 and IPv4";
    homepage = "https://github.com/miguelangel-nubla/ipv6disc";
    license = lib.licenses.asl20;
    mainProgram = "ipv6disc";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
