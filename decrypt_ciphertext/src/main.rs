use std::io;
use std::io::Write;
use rug::Integer;

fn decrypt_ciphertext(ciphertext: Integer, sk: (Integer, Integer), n: Integer) -> Integer {
    let (lambda, mu) = sk;
    let nsq = n.clone() * n.clone();
    let first_exp = ((ciphertext.secure_pow_mod(&lambda, &nsq) - Integer::from(1)) / n.clone()) % n.clone();
    let second_exp = mu % n.clone();
    (first_exp * second_exp) % n
}

fn main() {
    print!("Enter the ciphertext: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let ciphertext = Integer::from_str_radix(input, 10).unwrap();
    println!("\nEnter the secret key (lambda, mu):");
    print!("Enter lambda: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let lambda = Integer::from_str_radix(input, 10).unwrap();
    print!("Enter mu: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let mu = Integer::from_str_radix(input, 10).unwrap();
    print!("\nEnter n: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let n = Integer::from_str_radix(input, 10).unwrap();
    let sk = (lambda, mu);
    let output_plaintext = decrypt_ciphertext(ciphertext, sk.clone(), n);
    let output_plaintext = format!("{:X}", &output_plaintext);
    println!("\nDecrypted plaintext: {}", String::from_utf8(hex::decode(output_plaintext).unwrap()).unwrap());
}
