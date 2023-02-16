use criterion::*;
use oberon::*;
use rand::rngs::OsRng;
use rand::thread_rng;
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
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

fn setup<R: RngCore>(rng: &mut R) -> ([u8; 16], [u8; 16], Token, SecretKey) {
    let mut sk_seed = [0u8; 16];
    let mut id = [0u8; 16];
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut sk_seed);
    rng.fill_bytes(&mut id);
    rng.fill_bytes(&mut nonce);

    let sk = SecretKey::hash(&sk_seed);
    (id, nonce, sk.sign(&id).unwrap(), sk)
}

fn signing(c: &mut Criterion) {
    let mut id = [0u8; 16];
    let mut sk_seed = [0u8; 16];
    thread_rng().fill_bytes(&mut sk_seed);
    thread_rng().fill_bytes(&mut id);
    let sk = SecretKey::hash(&sk_seed);
    c.bench_function("token generation", |b| b.iter(|| sk.sign(&id).unwrap()));
}

fn token_verify(c: &mut Criterion) {
    let mut id = [0u8; 16];
    let mut sk_seed = [0u8; 16];
    thread_rng().fill_bytes(&mut sk_seed);
    thread_rng().fill_bytes(&mut id);
    let sk = SecretKey::hash(&sk_seed);
    let pk = PublicKey::from(&sk);
    let token = sk.sign(&id).unwrap();
    c.bench_function("token verification", |b| b.iter(|| token.verify(pk, id)));
}

fn xof_shift_rng(c: &mut Criterion) {
    let mut rng = XorShiftRngWrapper::from_seed([7u8; 16]);
    let (id, nonce, token, _) = setup(&mut rng);
    c.bench_function("xor shift rng proof generation", |b| {
        b.iter(|| {
            let _ = Proof::new(&token, &[], id, &nonce, &mut rng);
        })
    });
}

fn os_rng(c: &mut Criterion) {
    let mut rng = OsRng;
    let (id, nonce, token, _) = setup(&mut rng);
    c.bench_function("os rng proof generation", |b| {
        b.iter(|| {
            let _ = Proof::new(&token, &[], id, &nonce, &mut rng);
        })
    });
}

fn chacha_rng(c: &mut Criterion) {
    let mut rng = ChaChaRng::from_seed([5u8; 32]);
    let (id, nonce, token, _) = setup(&mut rng);
    c.bench_function("chacha rng proof generation", |b| {
        b.iter(|| {
            let _ = Proof::new(&token, &[], id, &nonce, &mut rng);
        })
    });
}

fn proof_verify(c: &mut Criterion) {
    let (id, nonce, token, sk) = setup(&mut thread_rng());
    let proof = Proof::new(&token, &[], id, &nonce, thread_rng()).unwrap();
    let pk = PublicKey::from(&sk);
    c.bench_function("proof verification", |b| {
        b.iter(|| proof.open(pk, id, nonce))
    });
}

fn blinding_factor(c: &mut Criterion) {
    c.bench_function("Blinding factor length 1", |b| {
        b.iter(|| Blinding::new(&[1u8]))
    });
    c.bench_function("Blinding factor length 2", |b| {
        b.iter(|| Blinding::new(&[2u8; 2]))
    });
    c.bench_function("Blinding factor length 4", |b| {
        b.iter(|| Blinding::new(&[4u8; 4]))
    });
    c.bench_function("Blinding factor length 8", |b| {
        b.iter(|| Blinding::new(&[8u8; 8]))
    });
    c.bench_function("Blinding factor length 16", |b| {
        b.iter(|| Blinding::new(&[16u8; 16]))
    });
}

criterion_group!(
    benches,
    signing,
    token_verify,
    proof_verify,
    xof_shift_rng,
    chacha_rng,
    os_rng,
    blinding_factor
);
criterion_main!(benches);
