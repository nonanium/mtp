use mtp::crypto::Keyring;

fn main() {
    let keyring = Keyring::generate();
    let bundle = keyring.public_key_bundle();

    // The `Debug` impl redacts private keys by design, so use the encoding
    // methods to emit the full keyring (public + secret keys) instead.
    println!("Keyring (hex):\n{}\n", keyring.to_hex());
    println!("Keyring (base64):\n{}\n", keyring.to_base64());

    println!("PublicKeyBundle (base64):\n{}", bundle.to_base64());
}
