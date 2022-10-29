use criterion::*;
use oberon::*;
use rand::rngs::OsRng;
use rand_core::{RngCore, SeedableRng, CryptoRng};
use rand_chacha::ChaChaRng;
use rand_xorshift::XorShiftRng;

struct XorShiftRngWrapper(XorShiftRng);

impl SeedableRng for XorShiftRngWrapper {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        Self(XorShiftRng::from_seed(seed))
    }
}

impl RngCore for XorShiftRngWrapper {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, buffer: &mut [u8]) {
        self.0.fill_bytes(buffer)
    }

    fn try_fill_bytes(&mut self, buffer: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(buffer)
    }
}

impl CryptoRng for XorShiftRngWrapper {}

fn setup<R: RngCore>(rng: &mut R) -> ([u8; 16], [u8; 16], Token) {
    let mut sk_seed = [0u8; 16];
    let mut id = [0u8; 16];
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut sk_seed);
    rng.fill_bytes(&mut id);
    rng.fill_bytes(&mut nonce);

    let sk = SecretKey::hash(&sk_seed);
    (id, nonce, sk.sign(&id).unwrap())
}

fn xof_shift_rng(c: &mut Criterion) {
    let mut rng = XorShiftRngWrapper::from_seed([7u8; 16]);
    let (id, nonce, token) = setup(&mut rng);
    c.bench_function("xor shift rng proof generation", |b| {
        b.iter(|| {
            let _ = Proof::new(&token, &[], id, &nonce, &mut rng);
        })
    });
}

fn os_rng(c: &mut Criterion) {
    let mut rng = OsRng;
    let (id, nonce, token) = setup(&mut rng);
    c.bench_function("os rng proof generation", |b| {
        b.iter(|| {
            let _ = Proof::new(&token, &[], id, &nonce, &mut rng);
        })
    });
}

fn chacha_rng(c: &mut Criterion) {
    let mut rng = ChaChaRng::from_seed([5u8; 32]);
    let (id, nonce, token) = setup(&mut rng);
    c.bench_function("chacha rng proof generation", |b| {
        b.iter(|| {
            let _ = Proof::new(&token, &[], id, &nonce, &mut rng);
        })
    });
}

criterion_group!(benches, xof_shift_rng, chacha_rng, os_rng);
criterion_main!(benches);