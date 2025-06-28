# Secrets Manager

Secrets Manager is an interoperable software to manage backups of secrets.

## Philosophy

### The theory

You should not depend on any specific software for backing-up your extremely
important data.

Any software that forces you to remain in its ecosystem after use (such as: "if
you encrypt it with this software, you can only decrypt it with this software")
makes you dependant on it.

Hence, the encryption, decryption and restore of you important data should
decoupled, that is if you encrypted it with software X, you should still be able
to decrypt it without software X.

This is the meaning of "interoperable" in the description: if you encrypt your
secrets with this software, you should be able to decrypt and restore them
without this software. Even if `secrets-manager` disappears from the face of the
Earth, your data is still accessible.

### The practice

In practice, you cannot create a setup where you secrets are 100% safe from data
loss. Even if your software X is interoperable with Y, Z and W, you'll still
lose access to your data if X, Y, Z and W all stopped working at the same time.

What you do in practice is make sure to be dependant only on technologies that
are "standards" or close to. I'm ok with being dependant on the existance of
bash interpreters, usb ports and linux machines.

The true goal of secrets-manager then becomes being perfectly reproducible only
with:

- a terminal
- coreutils such as `cp`, `mv` and `sha256sum`
- [age](https://github.com/FiloSottile/age)
- manual work and a bit of time

> The dependency on `age` is the most delicate, but the dependency on _some_
> cryptographical library is unavoidable, and `age` has both great popularity
> and nice bindings in Rust.

This ensures that even if anything happened to this software that prevented you
from using it again, assuming that `age` still exist and that you're willing to
spend 30 minutes of your life, you could still recover all your secrets.

The section [interoperability](#interoperability) explains how to import the
secrets exported by this software without using this software, that is only with
coreutils, `age` and a terminal.

## Usage

The following commands assume the presence of a `secrets-manager.toml` in the
current directory or in `XDG_CONFIG`.

To export your secrets, run

```bash
sudo secrets-manager export /path/to/export/endpoint
```

To verify the integrity of an existing export (see note below), run

```bash
# if you're using the exported binary
sudo secrets-manager verify-export .

# if you're using the installed binary
# sudo secrets-managet verify-export /path/to/export/source
```

> note that an integrity check is automatically done at every export. This is
> needed only if you want to check the integrity of an old export that could
> have possibly decayed and corrupted

To import your secrets, run

```bash
# if you're using the exported binary
sudo secrets-managet import .

# if you're using the installed binary
# sudo secrets-managet import /path/to/export/source
```

## Interoperability

### Export

Exported files are encrypted using `age` with a passphrase. The name of the
exported file is the original name with the additional extension `.age`.
Ownership and permissions of the files are preserved during the export.

To obtain the same behaviour, you can use the following:

```bash
age --passphrase --output filename.txt.age --encrypt filename.txt
chown --reference=filename.txt filename.txt.age
chmod --reference=filename.txt filename.txt.age
```

Note that:

- before exporting, the checksum of the source file is checked
- during the export, the existing checksum of the plaintext file is encrypted
  and exported
- after the export, another checksum is created for all the encrypted files to
  enable to check the integrity of the export on a later moment.

### Verify Export

Veryfying the integrity of an export consist in checking that every checksum
matches. To do so one can simply run

```bash
find . -name "sha256sums.txt" -execdir sha256sum -c sha256sums.txt \;
```

in the export's root directory

### Import

Imported files are decrypted using `age` with a passphrase. The name of the
imported file is the exported name without the `.age` extension. Ownership and
permissions of the files are preserved during import. Additionally, if specified
by the config, symlinks are generated.

To obtain the same behaviour, you can use the following:

```bash
age --output filename.txt --decrypt filename.txt.age
chown --reference=filename.txt.age filename.txt
chmod --reference=filename.txt.age filename.txt
ln -s /path/to/target/filename.txt /path/to/link/filename.txt
```

Note that:

- before the import, the checksum of the source file is checked
- after the export, the checksum of the imported files is checked
