{
  lib,
  fetchFromGitHub,
  rustPlatform,
}:

rustPlatform.buildRustPackage (finalAttrs: {
  pname = "secrets-manager";
  version = "0.1.0";

  src = ./.;

  cargoHash = "sha256-C+AmXi30vmXg3HgG4gX5aBfrPsQiCrjSmTOvBDo+tq8=";
})
