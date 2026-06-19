use rand::random;

pub fn rand_u32() -> u32 {
    random::<u32>()
}

pub fn rand_u64() -> u64 {
    random::<u64>()
}
