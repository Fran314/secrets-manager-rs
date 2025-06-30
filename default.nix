{
  rustPlatform,
}:

rustPlatform.buildRustPackage (finalAttrs: {
  pname = "secrets-manager";
  version = "0.1.0";

  src = ./.;

  cargoHash = "sha256-pHZ0iuFyYmN0tlz5cikE+ONDPQxAowZjHMYFtKk/anU=";
})
