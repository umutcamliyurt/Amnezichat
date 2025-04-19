mod gui;
mod key_operations;
mod network_operations;
mod key_exchange;
mod authentication;
mod encryption;
use gui::create_rocket;
use gui::MessagingApp;
use key_operations::key_operations_dilithium;
use key_operations::key_operations_eddsa;
use network_operations::create_client_with_proxy;
use network_operations::fetch_kyber_pubkey;
use network_operations::fetch_dilithium_pubkeys;
use network_operations::fetch_eddsa_pubkeys;
use network_operations::fetch_ciphertext;
use network_operations::send_kyber_pubkey;
use network_operations::send_dilithium_pubkey;
use network_operations::send_eddsa_pubkey;
use network_operations::send_ciphertext;
use network_operations::send_encrypted_message;
use network_operations::receive_and_fetch_messages;
use key_exchange::kyber_key_exchange;
use key_exchange::perform_ecdh_key_exchange;
use authentication::sign_data_with_dilithium;
use authentication::sign_data_with_eddsa;
use authentication::verify_signature_with_dilithium;
use authentication::verify_signature_with_eddsa;
use encryption::derive_salt_from_password;
use encryption::derive_key;
use encryption::combine_shared_secrets;
use encryption::encrypt_data;
use encryption::decrypt_data;

use oqs::*;
use oqs::sig::{Sig, PublicKey, SecretKey, Algorithm as SigAlgorithm};
use rand::Rng;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;
use std::process::Command;
use hex;
use std::io::{self, Write};
use rpassword::read_password;
use std::result::Result;
use std::{
    collections::HashSet,
    error::Error,
};
use serde::{Deserialize, Serialize};
use chacha20poly1305::aead::OsRng;
use rand::RngCore;
use sha3::{Sha3_512, Digest};
use ed25519_dalek::VerifyingKey as Ed25519PublicKey;

fn get_raw_bytes_public_key(pk: &PublicKey) -> &[u8] {
    pk.as_ref() 
}

fn get_raw_bytes_secret_key(sk: &SecretKey) -> &[u8] {
    sk.as_ref() 
}

#[derive(Serialize, Deserialize, Debug)] 
struct MessageData {
    message: String,
    room_id: String,
}

fn fingerprint_dilithium_public_key(public_key: &PublicKey) -> String {

    let raw_bytes = public_key.as_ref(); 
    let hashed = Sha3_512::digest(raw_bytes);
    hex::encode(hashed)
}

fn fingerprint_eddsa_public_key(public_key: &Ed25519PublicKey) -> String {

    let hashed = Sha3_512::digest(public_key);
    hex::encode(hashed)
}

fn request_user_confirmation(
    fingerprint: &str,
    own_fingerprint: &str,
    password: &str,
) -> Result<bool, io::Error> {
    if fingerprint == own_fingerprint {
        return Ok(true);
    }

    let path = "contact_fingerprints.enc";

    let trusted_fingerprints = load_trusted_fingerprints(path, password)?;

    if trusted_fingerprints.contains(fingerprint) {
        println!("Auto-trusting stored fingerprint: {}", fingerprint);
        return Ok(true);
    }

    println!("The fingerprint of the received public key is: {}", fingerprint);
    print!("Do you confirm this fingerprint? (yes/no): ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let response = input.trim().to_lowercase();

    match response.as_str() {
        "yes" => {
            print!("Would you like to remember this fingerprint for future sessions? (yes/no): ");
            io::stdout().flush()?;

            input.clear();
            io::stdin().read_line(&mut input)?;
            let remember_response = input.trim().to_lowercase();

            if remember_response == "yes" {
                save_fingerprint(path, fingerprint, password)?;
            }

            Ok(true)
        }
        "no" => Ok(false),
        _ => {
            println!("Invalid input. Please enter 'yes' or 'no'.");
            request_user_confirmation(fingerprint, own_fingerprint, password)
        }
    }
}

fn load_trusted_fingerprints<P: AsRef<Path>>(
    path: P,
    password: &str
) -> Result<HashSet<String>, io::Error> {
    let mut set = HashSet::new();

    if let Ok(file) = File::open(&path) {
        for line in BufReader::new(file).lines() {
            if let Ok(encrypted_line) = line {
                match decrypt_data(&encrypted_line, password) {
                    Ok(fingerprint) => {
                        set.insert(fingerprint);
                    }
                    Err(err) => {
                        eprintln!("Warning: Could not decrypt a line in fingerprint file: {}", err);
                    }
                }
            }
        }
    }

    Ok(set)
}

fn save_fingerprint<P: AsRef<Path>>(
    path: P,
    fingerprint: &str,
    password: &str
) -> Result<(), io::Error> {
    match encrypt_data(fingerprint, password) {
        Ok(encrypted) => {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            writeln!(file, "{}", encrypted)?;
            Ok(())
        }
        Err(e) => {
            eprintln!("Encryption error: {}", e);
            Err(io::Error::new(io::ErrorKind::Other, "Failed to encrypt fingerprint"))
        }
    }
}

fn generate_random_room_id() -> String {
    const ID_LENGTH: usize = 16;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    let mut rng = OsRng;
    let mut room_id = String::with_capacity(ID_LENGTH);

    for _ in 0..ID_LENGTH {
        let idx = (rng.next_u32() as usize) % CHARSET.len();
        room_id.push(CHARSET[idx] as char);
    }

    room_id
}

fn pad_message(message: &str, max_length: usize) -> String {
    let current_length = message.len();

    if current_length < max_length {
        let padding_len = max_length - current_length;

        let mut rng = OsRng;  
        let padding: String = (0..padding_len)
            .map(|_| rng.gen_range(33..127) as u8 as char) 
            .collect();

        return format!("{}<padding>{}</padding>", message, padding);
    }

    message.to_string()  
}

fn main() -> Result<(), Box<dyn Error>> {
    use std::sync::{Arc, Mutex};
    use std::{io::{self, Write}, thread, time::Duration};

    let sigalg = sig::Sig::new(sig::Algorithm::Dilithium5)?;

    println!("Would you like to create a new room or join an existing one?");
    println!("Type 'create' to create a new room or 'join' to join an existing one.");
    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();

    let room_id = match choice {
        "create" => {
            let new_room_id = generate_random_room_id();
            println!("Generated new room ID: {}", new_room_id);
            new_room_id
        }
        "join" => {
            println!("Enter the room ID to join:");
            let mut room_input = String::new();
            io::stdin().read_line(&mut room_input)?;
            room_input.trim().to_string()
        }
        _ => {
            println!("Invalid choice. Please restart the program and choose 'create' or 'join'.");
            return Ok(());
        }
    };

    let mut input = String::new();
    print!("Enter the server URL: ");
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    let url = input.trim().to_string();
    input.clear();

    print!("Enter your username: ");
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    let username = input.trim().to_string();
    input.clear();

    print!("Enter private key encryption password: ");
    io::stdout().flush()?;
    let private_password = read_password()?.to_string();

    println!("Is this a group chat? (yes/no): ");
    let mut is_group_chat = String::new();
    io::stdin().read_line(&mut is_group_chat)?;
    let is_group_chat = is_group_chat.trim().to_lowercase() == "yes";

    let room_password = if is_group_chat {

        loop {
            print!("Enter room password (must be longer than 8 characters): ");
            io::stdout().flush()?; 
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let password_input = input.trim();
            if password_input.len() > 8 {
                break password_input.to_string(); 
            } else {
                println!("Error: Password must be longer than 8 characters. Please try again.");
            }
        }
    } else {

        String::new()
    };

    let room_password = if is_group_chat {
        let salt = derive_salt_from_password(&room_password);
        let key = derive_key(&room_password, &salt);
        hex::encode(key)
    } else {
        String::new() 
    };

    if is_group_chat {
        println!("Skipping key exchange. Using room password as shared secret.");
        let hybrid_shared_secret = room_password.clone();  
        println!("Shared secret established.");
        println!("You can now start messaging!");

        let shared_hybrid_secret = Arc::new(hybrid_shared_secret.clone());
        let shared_room_id = Arc::new(Mutex::new(room_id.clone()));
        let shared_url = Arc::new(Mutex::new(url.clone()));

        let random_data_thread = {
            let shared_room_id = Arc::clone(&shared_room_id);
            let shared_url = Arc::clone(&shared_url);
            let shared_hybrid_secret = Arc::clone(&shared_hybrid_secret);

            thread::spawn(move || loop {
                let mut random_data = vec![0u8; OsRng.next_u32() as usize % 2048 + 1];
                OsRng.fill_bytes(&mut random_data);

                let dummy_message = format!("[DUMMY_DATA]: {:?}", random_data);
                let encrypted_dummy_message = match encrypt_data(&dummy_message, &shared_hybrid_secret) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("Error encrypting dummy message: {}", e);
                        continue;
                    }
                };

                let room_id_locked = shared_room_id.lock().unwrap();
                let url_locked = shared_url.lock().unwrap();
                let padded_message = pad_message(&encrypted_dummy_message, 2048);

                if let Err(e) = send_encrypted_message(&padded_message, &room_id_locked, &url_locked) {
                    eprintln!("Error sending dummy message: {}", e);
                }

                thread::sleep(Duration::from_secs(OsRng.next_u32() as u64 % 120 + 1));
            })
        };

        let fetch_thread = thread::spawn({
            let shared_hybrid_secret = Arc::clone(&shared_hybrid_secret);
            let shared_room_id = Arc::clone(&shared_room_id);
            let shared_url = Arc::clone(&shared_url);

            move || loop {
                let room_id_locked = shared_room_id.lock().unwrap().clone();
                let url_locked = shared_url.lock().unwrap().clone();

                match receive_and_fetch_messages(
                    &room_id_locked,
                    &shared_hybrid_secret,
                    &url_locked,
                    true, 
                ) {
                    Ok(_) => {}
                    Err(e) => eprintln!("Error fetching messages: {}", e),
                }

                thread::sleep(Duration::from_secs(10));
            }
        });

        let rt = rocket::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let app = MessagingApp::new(
                username,
                shared_hybrid_secret,
                Arc::clone(&shared_room_id),
                Arc::clone(&shared_url),
            );

            if let Err(e) = create_rocket(app).launch().await {
                eprintln!("Rocket server failed: {}", e);
            }
        });

        if let Err(e) = random_data_thread.join() {
            eprintln!("Random data thread terminated with error: {:?}", e);
        }

        if let Err(e) = fetch_thread.join() {
            eprintln!("Fetch thread terminated with error: {:?}", e);
        }

        return Ok(());
    }

    let dilithium_keys = key_operations_dilithium(&sigalg, &username, &private_password);
    let Ok((dilithium_pk, dilithium_sk)) = dilithium_keys else { todo!() };

    let eddsa_keys = key_operations_eddsa(&username, &private_password);
    let Ok((eddsa_sk, eddsa_pk)) = eddsa_keys else { todo!() };

    let encoded_dilithium_pk = hex::encode(&dilithium_pk);
    send_dilithium_pubkey(&room_id, &encoded_dilithium_pk, &url);

    let encoded_eddsa_pk = hex::encode(&eddsa_pk);
    send_eddsa_pubkey(&room_id, &encoded_eddsa_pk, &url);

    let fingerprint_dilithium = fingerprint_dilithium_public_key(&dilithium_pk);

    println!("Own Dilithium5 fingerprint: {}", fingerprint_dilithium);

    let fingerprint_eddsa = match Ed25519PublicKey::from_bytes(&eddsa_pk) {
        Ok(public_key) => fingerprint_eddsa_public_key(&public_key),
        Err(e) => {
            eprintln!("Failed to convert EdDSA public key: {}", e);
            return Err(Box::new(e));
        }
    };

    println!("Own EdDSA fingerprint: {}", fingerprint_eddsa);

    let mut processed_fingerprints: HashSet<String> = HashSet::new();
    processed_fingerprints.insert(fingerprint_dilithium.clone());
    processed_fingerprints.insert(fingerprint_eddsa.clone());

    let mut all_other_dilithium_keys: Vec<oqs::sig::PublicKey> = Vec::new();

    while all_other_dilithium_keys.len() < 1 {
        println!("Waiting for Dilithium public key...");
        thread::sleep(Duration::from_secs(5));

        let encoded_other_dilithium_pks = fetch_dilithium_pubkeys(&room_id, &url);

        for encoded_pk in encoded_other_dilithium_pks {
            if let Ok(decoded_pk) = hex::decode(&encoded_pk) {

                let algorithm = SigAlgorithm::Dilithium5;

                let sig = Sig::new(algorithm).map_err(|_| "Failed to initialize signature scheme")?;

                if let Some(public_key_ref) = sig.public_key_from_bytes(&decoded_pk) {

                    let public_key = public_key_ref.to_owned();

                    let fetched_fingerprint = fingerprint_dilithium_public_key(&public_key);

                    if fetched_fingerprint == fingerprint_dilithium {
                        continue;
                    }

                    if processed_fingerprints.contains(&fetched_fingerprint) {
                        continue;
                    }

                    if request_user_confirmation(&fetched_fingerprint, &fingerprint_dilithium, &private_password)? {

                        all_other_dilithium_keys.push(public_key);
                        processed_fingerprints.insert(fetched_fingerprint);
                    } else {
                        eprintln!("User did not confirm the public key fingerprint.");
                    }
                } else {
                    eprintln!("Failed to decode valid public key.");
                }
            } else {
                eprintln!("Failed to convert decoded key to PublicKey.");
            }
        }
    }

    println!("Received Dilithium5 public key from the server.");

    let mut eddsa_key: Option<Ed25519PublicKey> = None;

    while eddsa_key.is_none() {
        println!("Waiting for EdDSA public key...");
        thread::sleep(Duration::from_secs(5));

        let encoded_other_eddsa_pks = fetch_eddsa_pubkeys(&room_id, &url);

        for encoded_pk in encoded_other_eddsa_pks {
            if let Ok(decoded_pk) = hex::decode(&encoded_pk) {
                if let Ok(public_key) = Ed25519PublicKey::from_bytes(
                    decoded_pk.as_slice().try_into().expect("Decoded public key must be 32 bytes long"),
                ) {
                    let fetched_fingerprint = fingerprint_eddsa_public_key(&public_key);

                    if fetched_fingerprint == fingerprint_eddsa {
                        continue;
                    }

                    if processed_fingerprints.contains(&fetched_fingerprint) {
                        continue;
                    }

                    if request_user_confirmation(&fetched_fingerprint, &fingerprint_eddsa, &private_password)? {
                        eddsa_key = Some(public_key);
                        processed_fingerprints.insert(fetched_fingerprint);
                        break;
                    } else {
                        eprintln!("User did not confirm the public key fingerprint.");
                    }
                } else {
                    eprintln!("Failed to decode valid public key.");
                }
            } else {
                eprintln!("Failed to convert decoded key to PublicKey.");
            }
        }
    }

    println!("Received EdDSA public key from the server.");

    let mut all_dilithium_pks = vec![dilithium_pk];
    all_dilithium_pks.extend(all_other_dilithium_keys);

    let kyber_shared_secret = kyber_key_exchange(&room_id, &all_dilithium_pks, &dilithium_sk, &url)?;
    let ecdh_shared_secret = if let Some(ref eddsa_key) = eddsa_key {
        perform_ecdh_key_exchange(&room_id, &eddsa_sk.to_bytes(), eddsa_key, &url)?
    } else {
        return Err("EdDSA public key is missing".into());
    };

    let hybrid_shared_secret = combine_shared_secrets(&kyber_shared_secret, &ecdh_shared_secret)?;

    println!("Hybrid shared secret established.");
    println!("You can now start messaging!");

let shared_hybrid_secret = Arc::new(hybrid_shared_secret.clone());
let shared_room_id = Arc::new(Mutex::new(room_id.clone()));
let shared_url = Arc::new(Mutex::new(url.clone()));

let random_data_thread = {
    let shared_room_id = Arc::clone(&shared_room_id);
    let shared_url = Arc::clone(&shared_url);
    let shared_hybrid_secret = Arc::clone(&shared_hybrid_secret);

    thread::spawn(move || loop {
        let mut random_data = vec![0u8; OsRng.next_u32() as usize % 2048 + 1];
        OsRng.fill_bytes(&mut random_data);

        let dummy_message = format!("[DUMMY_DATA]: {:?}", random_data);
        let padded_message = pad_message(&dummy_message, 2048);
        let encrypted_dummy_message = match encrypt_data(&padded_message, &shared_hybrid_secret) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Error encrypting dummy message: {}", e);
                continue;
            }
        };

        let room_id_locked = shared_room_id.lock().unwrap();
        let url_locked = shared_url.lock().unwrap();

        if let Err(e) = send_encrypted_message(&encrypted_dummy_message, &room_id_locked, &url_locked) {
            eprintln!("Error sending dummy message: {}", e);
        }

        thread::sleep(Duration::from_secs(OsRng.next_u32() as u64 % 120 + 1));
    })
};

let fetch_thread = thread::spawn({
    let shared_hybrid_secret = Arc::clone(&shared_hybrid_secret);
    let shared_room_id = Arc::clone(&shared_room_id);
    let shared_url = Arc::clone(&shared_url);

    move || loop {
        let room_id_locked = shared_room_id.lock().unwrap().clone();
        let url_locked = shared_url.lock().unwrap().clone();

        match receive_and_fetch_messages(
            &room_id_locked,
            &shared_hybrid_secret,
            &url_locked,
            true, 
        ) {
            Ok(_) => {}
            Err(e) => eprintln!("Error fetching messages: {}", e),
        }

        thread::sleep(Duration::from_secs(10));
    }
});

let rt = rocket::tokio::runtime::Runtime::new().unwrap();
rt.block_on(async {
    let app = MessagingApp::new(
        username,
        shared_hybrid_secret,
        Arc::clone(&shared_room_id),
        Arc::clone(&shared_url),
    );

    if let Err(e) = create_rocket(app).launch().await {
        eprintln!("Rocket server failed: {}", e);
    }
});

if let Err(e) = random_data_thread.join() {
    eprintln!("Random data thread terminated with error: {:?}", e);
}

if let Err(e) = fetch_thread.join() {
    eprintln!("Fetch thread terminated with error: {:?}", e);
}

    Ok(())
}    

fn clear_screen() {
    if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(&["/C", "cls"])
            .output()
            .expect("Failed to clear screen on Windows");
    } else {
        Command::new("clear")
            .status()
            .expect("Failed to clear screen on Unix");
    }
}
