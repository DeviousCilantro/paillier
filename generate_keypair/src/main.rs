use num_primes::Generator;
use ring::rand::{SystemRandom, SecureRandom};
use rug::Integer;

fn generate_keypair() -> ((String, String), (String, String)) {
    let rand = SystemRandom::new();
    println!("\nGenerating keypair...");
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
    ((base64::encode(n.to_string()), base64::encode(g.to_string())), 
     (base64::encode(lambda.to_string()), base64::encode(mu.to_string())))
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

fn main() {
    let ((n, g), (lambda, mu)) = generate_keypair();
    println!("\nPublic key: (n, g)");
    println!("n: {n}");
    println!("g: {g}");
    println!("\nSecret key: (lambda, mu)");
    println!("lambda: {lambda}");
    println!("mu: {mu}");
}
