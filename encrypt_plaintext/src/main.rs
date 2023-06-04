use std::io;
use std::io::Write;
use rug::{Integer, rand};
use base64;

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

fn main() {
    print!("Enter the plaintext: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = input.trim();
    let input_plaintext = Integer::from_str_radix(&hex::encode(input), 16).unwrap();
    println!("\nEnter the public key (n, g): ");
    print!("Enter n: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let n = Integer::from_str_radix(input, 10).unwrap();
    print!("Enter g: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let g = Integer::from_str_radix(input, 10).unwrap();
    let pk = (n, g);
    let ciphertext = encrypt_plaintext(&input_plaintext, pk.clone());
    println!("\nEncrypted ciphertext: {}", base64::encode(ciphertext.to_string()));
}
