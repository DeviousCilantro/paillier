use num_primes::Generator;
use rug::{Integer, rand};

fn generate_keypair() -> ((String, String), (String, String)) {
    println!("Generating keypair...");
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
    ((base64::encode(n.to_string()), base64::encode(g.to_string())), 
     (base64::encode(lambda.to_string()), base64::encode(mu.to_string())))
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
