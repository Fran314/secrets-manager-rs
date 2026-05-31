{
  rustPlatform,
}:

rustPlatform.buildRustPackage (finalAttrs: {
  pname = "secs-man";
  version = "0.3.1";

  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };
})
