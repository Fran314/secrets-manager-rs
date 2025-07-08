{
  rustPlatform,
}:

rustPlatform.buildRustPackage (finalAttrs: {
  pname = "secrets-manager";
  version = "0.2.0";

  src = ./.;

  cargoHash = "sha256-Exmp1k98cVQbriAD0IdO+6+e8lFfgk3yKE9NM+1Qdk4=";
})
