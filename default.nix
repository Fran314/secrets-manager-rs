{
  rustPlatform,
}:

rustPlatform.buildRustPackage (finalAttrs: {
  pname = "secrets-manager";
  version = "0.3.0";

  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };
})
