use sha2::Digest;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.into()
}

pub fn sha256_double(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

pub struct Sha256Hasher(sha2::Sha256);

impl Sha256Hasher {
    pub fn new() -> Self {
        Self(sha2::Sha256::new())
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let result = self.0.finalize();
        result.into()
    }
}
