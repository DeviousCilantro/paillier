use std::io;
use std::io::Write;
use num_primes::Generator;
use rug::{Integer, rand};

fn generate_keypair() -> ((Integer, Integer), (Integer, Integer)) {
    let p = Integer::from_str_radix(&Generator::safe_prime(512).to_string(), 10).unwrap();
    let q = Integer::from_str_radix(&Generator::safe_prime(512).to_string(), 10).unwrap();
    let n = p.clone() * q.clone();
    let nsq = n.clone() * n.clone();
    let lambda = Integer::lcm(p - Integer::from(1), &(q - Integer::from(1)));
    let mut g;
    loop {
        let mut rand = rand::RandState::new();
        g = nsq.clone().random_below(&mut rand);
        if g.clone().gcd(&nsq) == 1 {
            break;
        };
    };
    let mu = Integer::invert((Integer::secure_pow_mod(g.clone(), &lambda, &nsq)- Integer::from(1)) / n.clone(), &n).unwrap();
    ((n, g), (lambda, mu))
}

fn encrypt_plaintext(plaintext: &Integer, pk: (Integer, Integer)) -> Integer {
    let (n, g) = pk;
    let nsq = n.clone() * n.clone();
    if *plaintext >= 0 && *plaintext < n {
        let mut r;
        loop {
            let mut rand = rand::RandState::new();
            r = n.clone().random_below(&mut rand);
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
    assert_eq!(decrypt_ciphertext(c1.clone() * c2.clone() % nsq.clone(), sk.clone(), n.clone()), sum, "Not additively homomorphic");
    assert_eq!(decrypt_ciphertext(((c1.clone() % nsq.clone()) * (g.secure_pow_mod(m2, &nsq))) % nsq.clone(), sk.clone(), n.clone()), sum, "Not additively homomorphic");
    assert_eq!(decrypt_ciphertext(c1.secure_pow_mod(m2, &nsq), sk.clone(), n.clone()), product, "Not additively homomorphic");
    assert_eq!(decrypt_ciphertext(c2.secure_pow_mod(m1, &nsq), sk, n), product, "Not additively homomorphic");
    println!("Verified additive homomorphism.");
}

fn main() {
    print!("Enter a string: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = input.trim();
    let (pk, sk) = generate_keypair();
    let input_plaintext = Integer::from_str_radix(&hex::encode(input), 16).unwrap();
    let ciphertext = encrypt_plaintext(&input_plaintext, pk.clone());
    println!("Encrypted ciphertext: {}", &ciphertext);
    let output_plaintext = decrypt_ciphertext(ciphertext, sk.clone(), pk.clone().0);
    assert_eq!(input_plaintext, output_plaintext, "Correctness not proved");
    let output_plaintext = format!("{:X}", &output_plaintext);
    println!("Decrypted plaintext: {}", String::from_utf8(hex::decode(output_plaintext).unwrap()).unwrap());
    println!("Correctness proved.");
    println!("Now enter two more strings to verify additive homomorphism.");
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
    verify_homomorphism(&m1, &m2, pk, sk);
}
