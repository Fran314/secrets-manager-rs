{
  rustPlatform,
}:

rustPlatform.buildRustPackage (finalAttrs: {
  pname = "secrets-manager";
  version = "0.2.1";

  src = ./.;

  cargoHash = "sha256-TsctEKjFdAw+QOIl+MhCznk1MwaBpOboVvEWxxfedHw=";
})
