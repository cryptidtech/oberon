use kmeans::*;
use oberon::*;
use rand::rngs::OsRng;
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;
use random_tester::*;

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

fn main() {
    const SAMPLE_COUNT: usize = 4000;
    const SAMPLE_DIMENSIONS: usize = 256;
    const K: usize = 2;
    const MAX_ITER: usize = 1000;

    let mut rng = OsRng;
    let mut sk_seed = [0u8; 16];
    let mut id = [0u8; 16];
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut sk_seed);
    rng.fill_bytes(&mut id);
    rng.fill_bytes(&mut nonce);

    let sk = SecretKey::hash(&sk_seed);
    let token = sk.sign(id).unwrap();

    let mut entropy_testers: Vec<(&'static str, &'static str, Box<dyn DynEntropyTester>)> = vec![
        ("Shannon", ">= 7.9", Box::new(ShannonCalculation::default())),
        ("Mean", "= 127.0", Box::new(MeanCalculation::default())),
        (
            "MonteCarlo",
            "3.1 <=> 3.2",
            Box::new(MonteCarloCalculation::default()),
        ),
        (
            "Serial",
            "-0.004 <=> 0.004",
            Box::new(SerialCorrelationCoefficientCalculation::default()),
        ),
        (
            "ChiSquare",
            "0.001 <=> 0.99",
            Box::new(ChiSquareCalculation::default()),
        ),
    ];

    // Create proof samples using the same nonce
    // Not done in practice but used to isolate the effects
    // of the RNG
    let mut rngs = get_rngs();
    for (label, rng) in rngs.iter_mut() {
        println!("Sampling with {}", *label);
        let mut samples = vec![0f32; SAMPLE_DIMENSIONS * SAMPLE_COUNT];
        for i in 0..SAMPLE_COUNT {
            let proof = Proof::new(&token, &[], &id, &nonce, &mut *rng).unwrap();
            let proof_bytes = proof
                .to_bytes()
                .iter()
                .map(|b| *b as f32)
                .collect::<Vec<f32>>();
            for tester in entropy_testers.iter_mut() {
                tester.2.update(&proof.to_bytes());
            }
            samples[i * SAMPLE_DIMENSIONS..(i + 1) * SAMPLE_DIMENSIONS]
                .copy_from_slice(&proof_bytes);
        }
        println!("Computing clustering");
        let kmean = KMeans::new(samples, SAMPLE_COUNT, SAMPLE_DIMENSIONS);
        let result = kmean.kmeans_lloyd(
            K,
            MAX_ITER,
            KMeans::init_kmeanplusplus,
            &KMeansConfig::default(),
        );

        // println!("Centroids: {:?}", result.centroids);
        // println!("Cluster-assignments: {:?}", result.assignments);
        println!("Error: {}", result.distsum);
        for tester in entropy_testers.iter_mut() {
            println!("{}: {} - {}", tester.0, tester.1, tester.2.finalize());
        }
    }
}

enum Rngs {
    Os(OsRng),
    Xor(XorShiftRngWrapper),
    Cha(ChaChaRng),
}

impl RngCore for Rngs {
    fn next_u32(&mut self) -> u32 {
        match self {
            Self::Xor(x) => x.next_u32(),
            Self::Cha(c) => c.next_u32(),
            Self::Os(o) => o.next_u32(),
        }
    }

    fn next_u64(&mut self) -> u64 {
        match self {
            Self::Xor(x) => x.next_u64(),
            Self::Cha(c) => c.next_u64(),
            Self::Os(o) => o.next_u64(),
        }
    }

    fn fill_bytes(&mut self, buffer: &mut [u8]) {
        match self {
            Self::Xor(x) => x.fill_bytes(buffer),
            Self::Cha(c) => c.fill_bytes(buffer),
            Self::Os(o) => o.fill_bytes(buffer),
        }
    }

    fn try_fill_bytes(&mut self, buffer: &mut [u8]) -> Result<(), rand_core::Error> {
        match self {
            Self::Xor(x) => x.try_fill_bytes(buffer),
            Self::Cha(c) => c.try_fill_bytes(buffer),
            Self::Os(o) => o.try_fill_bytes(buffer),
        }
    }
}

impl CryptoRng for Rngs {}

fn get_rngs() -> [(&'static str, Rngs); 3] {
    let mut rng = OsRng;
    let xs_rng = XorShiftRngWrapper::from_rng(&mut rng).unwrap();
    let cc_rng = ChaChaRng::from_rng(&mut rng).unwrap();
    let os_rng = OsRng;
    [
        ("XorShiftRng", Rngs::Xor(xs_rng)),
        ("ChaChaRng", Rngs::Cha(cc_rng)),
        ("OsRng", Rngs::Os(os_rng)),
    ]
}
