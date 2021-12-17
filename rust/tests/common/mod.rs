pub const SEED: [u8; 16] = [7u8; 16];
pub const ID: &'static [u8] = b"oberon test identity";

pub struct MockRng(rand_xorshift::XorShiftRng);

impl rand_core::SeedableRng for MockRng {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        Self(rand_xorshift::XorShiftRng::from_seed(seed))
    }
}

impl rand_core::CryptoRng for MockRng {}

impl rand_core::RngCore for MockRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl MockRng {
    pub fn new() -> Self {
        use rand_core::SeedableRng;
        Self(rand_xorshift::XorShiftRng::from_seed(SEED))
    }
}
