use std::io::{Read, Write};

use age::{DecryptError, Decryptor, EncryptError, Encryptor, secrecy::SecretString};

pub fn encrypt<C>(plaintext: C, passphrase: &str) -> Result<Vec<u8>, EncryptError>
where
    C: AsRef<[u8]>,
{
    let encryptor = Encryptor::with_user_passphrase(SecretString::from(passphrase));

    let plaintext = plaintext.as_ref();
    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted)?;

    writer.write_all(plaintext)?;
    writer.finish()?;

    Ok(encrypted)
}

pub fn decrypt<C>(ciphertext: C, passphrase: &str) -> Result<Vec<u8>, DecryptError>
where
    C: AsRef<[u8]>,
{
    let ciphertext = ciphertext.as_ref();
    let decryptor = Decryptor::new(ciphertext)?;

    let mut decrypted = vec![];
    let mut reader = decryptor.decrypt(std::iter::once(&age::scrypt::Identity::new(
        SecretString::from(passphrase),
    ) as _))?;
    reader.read_to_end(&mut decrypted)?;

    Ok(decrypted)
}
