extern crate openssl;

use openssl::rsa::Rsa;
use openssl::symm::Cipher;

use std::fs::File;
use std::io;
use io::Write;


fn main() -> io::Result<()> {

    // Get the key pair name from the user
    println!("Enter a name for the key pair:");
    let mut key_pair_name = String::new();
    io::stdin().read_line(&mut key_pair_name).unwrap();

    // Get the passphrase for the key from the user
    println!("Enter a passphrase for the key or leave blank for no protection:");
    let mut key_passphrase = String::new();
    io::stdin().read_line(&mut key_passphrase).unwrap();

    // Get the number of bits for the rsa key
    println!("Enter the number of bits for your key or leave blank (1024 bits):");
    let mut bits = String::new();
    io::stdin().read_line(&mut bits).unwrap(); 
    if bits.trim().is_empty() {
        bits = String::from("1024");
    }

    // Generate the keys
    let rsa = Rsa::generate(bits.parse::<u32>().unwrap()).unwrap();
    let private_key: Vec<u8> = rsa.private_key_to_pem_passphrase(
        Cipher::aes_128_cbc(), 
        &key_passphrase.trim().bytes().collect::<Vec<u8>>(),
    ).unwrap();
    let public_key: Vec<u8> = rsa.public_key_to_pem().unwrap();

    // Output the keys to files
    let private_key_file = File::create(format!("{}-private.pem", &key_pair_name.trim())); 
    write!(private_key_file?, "{}", String::from_utf8(private_key).expect("Invalid UTF-8 in private key")).unwrap();

    let public_key_file = File::create(format!("{}-public.pem", &key_pair_name.trim())); 
    write!(public_key_file?, "{}", String::from_utf8(public_key).expect("Invalid UTF-8 in public key")).unwrap();

    Ok(())
}
