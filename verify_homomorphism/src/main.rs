use std::io;
use std::io::Write;
use ring::rand::{SystemRandom, SecureRandom};
use num_primes::Generator;
use rug::Integer;

fn generate_keypair() -> ((Integer, Integer), (Integer, Integer)) {
    let rand = SystemRandom::new();
    let p = Integer::from_str_radix(&Generator::safe_prime(512).to_string(), 10).unwrap();
    let q = Integer::from_str_radix(&Generator::safe_prime(512).to_string(), 10).unwrap();
    let n = p.clone() * q.clone();
    let nsq = n.clone() * n.clone();
    let lambda = Integer::lcm(p - Integer::from(1), &(q - Integer::from(1)));
    let mut g;
    loop {
        g = random_integer(&rand, nsq.clone());
        if g.clone().gcd(&nsq) == 1 {
            break;
        };
    };
    let mu = Integer::invert((Integer::secure_pow_mod(g.clone(), &lambda, &nsq)- Integer::from(1)) / n.clone(), &n).unwrap();
    ((n, g), (lambda, mu))
}

fn random_integer(rng: &SystemRandom, range: Integer) -> Integer {
    loop {
        let mut bytes = vec![0; ((range.significant_bits() + 7) / 8) as usize];
        rng.fill(&mut bytes).unwrap();
        let num = Integer::from_digits(&bytes, rug::integer::Order::Lsf);
        if num < range {
            return num;
        }
    }
}

fn encrypt_plaintext(plaintext: &Integer, pk: (Integer, Integer)) -> Integer {
    let rand = SystemRandom::new();
    let (n, g) = pk;
    let nsq = n.clone() * n.clone();
    if *plaintext >= 0 && *plaintext < n {
        let mut r;
        loop {
            r = random_integer(&rand, n.clone());
            if r.clone().gcd(&n) == 1 {
                break;
            };
        };
        (g.secure_pow_mod(plaintext, &nsq) * r.secure_pow_mod(&n, &nsq)) % nsq
    } else {
        Integer::from(0)
    }
}

fn decrypt_ciphertext(ciphertext: Integer, sk: (Integer, Integer), n: Integer) -> Integer {
    let (lambda, mu) = sk;
    let nsq = n.clone() * n.clone();
    let first_exp = ((ciphertext.secure_pow_mod(&lambda, &nsq) - Integer::from(1)) / n.clone()) % n.clone();
    let second_exp = mu % n.clone();
    (first_exp * second_exp) % n
}

fn verify_homomorphism(m1: &Integer, m2: &Integer, pk: (Integer, Integer), sk: (Integer, Integer)) {
    let (n, g) = pk.clone();
    let nsq = n.clone() * n.clone();
    let sum = (m1.clone() + m2.clone()) % n.clone();
    let product = (m1.clone() * m2.clone()) % n.clone();
    let c1 = encrypt_plaintext(m1, pk.clone());
    let c2 = encrypt_plaintext(m2, pk);
    assert_eq!(decrypt_ciphertext(c1.clone(), sk.clone(), n.clone()), *m1, "Correctness not verified");
    assert_eq!(decrypt_ciphertext(c2.clone(), sk.clone(), n.clone()), *m2, "Correctness not verified");
    assert_eq!(decrypt_ciphertext(c1.clone() * c2.clone() % nsq.clone(), sk.clone(), n.clone()), sum, "Not additively homomorphic");
    assert_eq!(decrypt_ciphertext(((c1.clone() % nsq.clone()) * (g.secure_pow_mod(m2, &nsq))) % nsq.clone(), sk.clone(), n.clone()), sum, "Not additively homomorphic");
    assert_eq!(decrypt_ciphertext(c1.secure_pow_mod(m2, &nsq), sk.clone(), n.clone()), product, "Not additively homomorphic");
    assert_eq!(decrypt_ciphertext(c2.secure_pow_mod(m1, &nsq), sk, n), product, "Not additively homomorphic");
    println!("Verified additive homomorphism and correctness.");
}

fn main() {
    println!("Enter two strings to verify additive homomorphism and correctness.");
    let mut input = String::new();
    print!("Enter m1: ");
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = input.trim();
    let m1 = Integer::from_str_radix(&hex::encode(input), 16).unwrap();
    let mut input = String::new();
    print!("Enter m2: ");
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = input.trim();
    let m2 = Integer::from_str_radix(&hex::encode(input), 16).unwrap();
    let (pk, sk) = generate_keypair();
    verify_homomorphism(&m1, &m2, pk, sk);
}
