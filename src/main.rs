extern crate openssl;

use openssl::rsa::Rsa;
use openssl::symm::Cipher;

use std::fs::File;
use std::io;
use io::Write;


struct UserInput {
    key_pair_name: String,
    passphrase: Vec<u8>,
    bits: u32,
}

fn main() -> io::Result<()> {
    // Gets all the input from the user
    let user_input = get_user_input();

    // Generate the keys
    let rsa = Rsa::generate(user_input.bits).unwrap();
    let private_key: Vec<u8> = rsa.private_key_to_pem_passphrase(
        Cipher::aes_128_cbc(), 
        &user_input.passphrase,
    ).unwrap();
    let public_key: Vec<u8> = rsa.public_key_to_pem().unwrap();

    // Output the keys to files
    let private_key_file = File::create(format!("{}-private.pem", &user_input.key_pair_name)); 
    write!(private_key_file?, "{}", String::from_utf8(private_key).expect("Invalid UTF-8 in private key")).unwrap();

    let public_key_file = File::create(format!("{}-public.pem", &user_input.key_pair_name)); 
    write!(public_key_file?, "{}", String::from_utf8(public_key).expect("Invalid UTF-8 in public key")).unwrap();

    Ok(())
}

fn get_user_input() -> UserInput {
    // Get the key pair name from the user
    println!("Enter a name for the key pair:");
    let mut key_pair_name = String::new();
    io::stdin().read_line(&mut key_pair_name).unwrap();

    // Get the passphrase for the key from the user
    println!("Enter a passphrase for the key or leave blank for no protection:");
    let mut passphrase = String::new();
    io::stdin().read_line(&mut passphrase).unwrap();

    // Get the number of bits for the rsa key
    println!("Enter the number of bits for your key or leave blank (1024 bits):");
    let mut bits = String::new();
    io::stdin().read_line(&mut bits).unwrap(); 
    if bits.trim().is_empty() {
        bits = String::from("1024");
    }

    UserInput { 
        key_pair_name: key_pair_name.trim().to_owned(), 
        passphrase: passphrase.trim().bytes().collect::<Vec<u8>>(), 
        bits: bits.parse::<u32>().unwrap() 
    }
}
