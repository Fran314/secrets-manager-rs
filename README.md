# secs-man

`secs-man` is a tool for managing backups of secrets with tool-independence in
mind: if you encrypt your secrets with this software, you should be able to
decrypt and restore them without this software. Even if `secs-man` disappears
from the face of the Earth, your data is still accessible.

`secs-man` can be used to manage secrets of local and remote machines, and is
ideal for creating local-only backups for data that is too sensitive to be
backed up somewhere in the cloud.

## Philosophy

### The theory

You should not depend on any specific software for backing-up your extremely
important data.

Any software that forces you to remain in its ecosystem after use (such as: "if
you encrypt it with this software, you can only decrypt it with this software")
makes you dependent on it.

Hence, the encryption, decryption and restore of your important data should be
decoupled, that is if you encrypted it with software X, you should still be able
to decrypt it without software X.

### The practice

In practice, you cannot create a setup where your secrets are 100% safe from
data loss. Even if your software X is compatible with Y, Z and W, you'll still
lose access to your data if X, Y, Z and W all stopped working at the same time.

What you do in practice is make sure to be dependent only on technologies that
are "standards" or close to. I'm ok with being dependent on the existence of
bash interpreters, USB ports and Linux machines.

The true goal of secs-man then becomes being perfectly reproducible only with:

- a terminal
- coreutils such as `cp`, `mv` and `sha256sum`
- [age](https://github.com/FiloSottile/age)
- manual work and a bit of time

> The dependency on `age` is the most delicate, but the dependency on _some_
> cryptographical library is unavoidable, and `age` has both great popularity
> and nice bindings in Rust.

This ensures that even if anything happened to this software that prevented you
from using it again, assuming that `age` still exists and that you're willing to
spend 30 minutes of your life, you could still recover all your secrets.

The section [manual recovery](#manual-recovery) explains how to import the
secrets exported by this software without using this software, that is only with
coreutils, `age` and a terminal.

## Installation

`secs-man` is not published anywhere (it is not a published crate, nor is it on
nixpkgs, the AUR or similar). It can only be installed directly from this
repository, in one of the following ways.

### With `nix run`

If you only need to run `secs-man` occasionally, you can run it directly without
installing it (requires flakes enabled)

```bash
nix run github:Fran314/secrets-manager-rs -- export /path/to/secrets /path/to/export/endpoint
```

### Through your Nix configuration

To make `secs-man` available system-wide, you can import this repository in your
Nix configuration with `fetchGit` and add the resulting package to
`environment.systemPackages` (or `home.packages` with home-manager)

```nix
let
  secs-man = pkgs.callPackage "${builtins.fetchGit {
    url = "https://github.com/Fran314/secrets-manager-rs.git";
    ref = "main";
    # rev = "<commit>"; # pin a specific commit for reproducibility
  }}/default.nix" { };
in
# add `secs-man` to environment.systemPackages or home.packages
```

### With `cargo`

If you are not on NixOS, you can install the `secs-man` binary by pointing
`cargo` at this repository

```bash
cargo install --git https://github.com/Fran314/secrets-manager-rs
```

> note that none of these methods install the
> [secs-man-ssh](./scripts/secs-man-ssh) script needed for
> [remote machines](#usage-with-remote-machines): it is a standalone script that
> has to be copied from this repository separately

## Usage

This tool allows to export and encrypt files from a given source directory, and
to recover them by importing to the same directory. The recommended way to use
this tool is to have all your "secrets" (keys, files, ...) in a centralized
directory.

At the root of the secrets directory there should be a `.secrets-manifest`
plaintext file containing the list of secrets to be managed, in the form of
paths relative to the secrets directory. Filepaths cannot contain whitespaces.
Each entry can also specify an `owner` and a `mode` which will be used to set
the correct permissions during import. See
[`.secrets-manifest.example`](./.secrets-manifest.example) for the syntax.

During an export, the files listed in the manifest get encrypted through `age`
with a passphrase requested through an interactive prompt (`secs-man` never
reads it from a file, an argument or an environment variable). The same
passphrase is requested again on import, to decrypt the files. The integrity of
the files is guaranteed by a companion `*.sha256` file, which gets automatically
generated if missing. The encrypted files get exported to a timestamped snapshot
inside the export target directory.

The files can then be decrypted and imported either by pointing to the export
target directory (to import the latest snapshot) or to a specific snapshot
inside this directory.

The following commands can be run without `sudo`, however they will fail if the
manifest specifies any owner different than the user executing the command (as
the inner chown call will fail).

To export your secrets, run

```bash
sudo secs-man export /path/to/secrets /path/to/export/endpoint
```

To verify the integrity of an existing export (see note below), run

```bash
# to verify the integrity of all the exported snapshots
sudo secs-man verify-export /path/to/export/endpoint

# to verify the integrity of a specific snapshot
sudo secs-man verify-export /path/to/export/endpoint/export-YYYY-MM-DD_HH-MM-SSZ
```

> note that an integrity check is automatically done at every export. This is
> needed only if you want to check the integrity of an old export that could
> have possibly decayed and corrupted

To import your secrets, run

```bash
# to import the latest snapshot
sudo secs-man import /path/to/export/endpoint /path/to/secrets

# to import a specific snapshot
sudo secs-man import /path/to/export/endpoint/export-YYYY-MM-DD_HH-MM-SSZ /path/to/secrets

# to import only specific secrets
sudo secs-man import /path/to/export/endpoint /path/to/secrets --pick ssh/id_ed25519 wg/wg0.key
```

## Usage with remote machines

This tool can be used to deploy and backup secrets on remote machines as well.

The easiest way to export remote secrets is to export them on a temporary
directory on the remote host, and then copy the exported snapshot over a local
backup. Similarly, to import a local backup the easiest approach is to copy the
local snapshot on a temporary directory over the remote host, and then import
them from there. However, this has the issue that the encryption/decryption
passphrase has to pass through the remote host, which might be considered
untrusted.

In order to deploy to / backup from untrusted remote hosts without passing the
passphrase over the remote, you can use the
[secs-man-ssh](./scripts/secs-man-ssh) script. This script does not assume
root-login over SSH (as it might be disabled for security reasons), but it
assumes that the remote user has `sudo` privileges (in order to let `secs-man`
run `chown` and `chmod`).

To export from a remote host, run:

```bash
secs-man-ssh export <user@host> <remote-secrets-dir> <local-backup>

# The flow is the following:
# 1. the script copies the remote secrets to a temporary directory on the remote host
# 2. the temporary directory gets chowned to the remote normal user, so that it can be sudo-less read and copied locally
# 3. the temporary directory is copied on the local host and deleted from the remote host
# 4. the local directory gets exported to the local backup, then deleted
```

To import to a remote host, run:

```bash
# secs-man has to be installed on the remote for the script import to work
secs-man-ssh import <user@host> <local-container> <remote-secrets-dir>

# The flow is the following:
# 1. the latest snapshot gets imported to a temporary local directory with the `--skip-chown-chmod` flag, so that it can be sudo-less read and copied to the remote host
# 2. the local directory gets copied to the remote host in a temporary directory, and deleted from the local host
# 3. the remote temporary directory gets imported to the remote secrets directory with `--from-plaintext`, as the files have already been decrypted
# 4. the remote temporary directory is deleted
```

## Manual Recovery

### Export

Exported files are encrypted using `age` with a passphrase. The name of the
exported file is the original name with the additional extension `.age`.

To obtain the same behaviour, you can use the following:

```bash
age --passphrase --output filename.txt.age --encrypt filename.txt
```

Note that:

- before exporting, the checksum of the source file is checked
- during the export, the existing checksum of the plaintext file is exported
  next to the encrypted file
- after the export, another checksum is created for all the encrypted files to
  enable to check the integrity of the export at a later moment.

### Verify Export

Verifying the integrity of an export consists in checking that every checksum
matches. To do so one can simply run

```bash
find . -name "sha256sums.txt" -execdir sha256sum -c sha256sums.txt \;
```

in the exported snapshot directory

### Import

Imported files are decrypted using `age` with a passphrase. The name of the
imported file is the exported name without the `.age` extension. If `owner`
and/or `mode` are specified in the manifest for a given entry, the imported file
is set to the specified owner and mode. If no mode is specified, it defaults to
`600`.

To obtain the same behaviour, you can use the following:

```bash
age --output filename.txt --decrypt filename.txt.age

# if no mode is specified, it defaults to 600
chmod <mode> filename.txt

# if no owner is specified, skip this step
chown <owner> filename.txt
```

Note that:

- before the import, the checksum of the source file is checked
- after the import, the checksum of the imported files is checked

## Threat model

This tool automatically creates snapshots during export which **do not** get
cleaned up by the tool itself. This means that some care should be used when
exporting secrets with this tool.

When exporting "authenticating" secrets (SSH/WireGuard keys, tokens), which can
easily be rotated, the existence of the snapshot doesn't pose any additional
risk.

When exporting "decrypting" secrets (disk keys, age/PGP identities,
password-manager master key), however, the existence of the snapshots means
that, if the secrets inside the exports were to be leaked and somehow decrypted,
an attacker could have access to current **and past** decryption keys. For this
reason, when rotating "decrypting" secrets, it would be safe to also delete old
exported snapshots (which can be easily done with
`rm -r /path/to/export/endpoint/export-YYYY-MM-DD_HH-MM-SSZ`). Note that the
critical path which exposes old decryption keys also implies the knowledge of
the current secrets, which is probably a bigger concern.
