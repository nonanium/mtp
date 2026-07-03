use std::path::PathBuf;

use mtp::crypto::Keyring;
use mtp::files::{
    self, BUNDLE_EXTENSION, KEYRING_EXTENSION, load_keyring, load_public_key_bundle, save_keyring,
    save_public_key_bundle,
};

fn main() -> Result<(), files::FileError> {
    let keyring_path = PathBuf::from(format!("keyring.{KEYRING_EXTENSION}"));
    let bundle_path = PathBuf::from(format!("bundle.{BUNDLE_EXTENSION}"));

    let keyring = Keyring::generate();
    save_keyring(&keyring, &keyring_path)?;
    save_public_key_bundle(&keyring.public_key_bundle(), &bundle_path)?;

    /* Read both back to confirm the files round-trip through the on-disk format. */
    let loaded_keyring = load_keyring(&keyring_path)?;
    let loaded_bundle = load_public_key_bundle(&bundle_path)?;
    assert_eq!(keyring.to_bytes(), loaded_keyring.to_bytes());
    assert_eq!(
        keyring.public_key_bundle().as_bytes(),
        loaded_bundle.as_bytes()
    );
    println!("\nPrivateKeyRing (base64):\n{}", keyring.to_base64());

    println!("\nPublicKeyBundle (base64):\n{}", loaded_bundle.to_base64());

    println!("Wrote keyring  -> {}", keyring_path.display());
    println!("Wrote bundle   -> {}", bundle_path.display());
    Ok(())
}
