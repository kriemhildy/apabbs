use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};

// PHC salt string used in password hashing

pub fn generate_phc_salt_string() -> SaltString {
    SaltString::generate(&mut OsRng)
}

// Convert Base64 salt string to PHC SaltString

pub fn convert_b64_salt(b64_salt: &str) -> SaltString {
    SaltString::from_b64(b64_salt).expect("convert Base64 str to PHC SaltString")
}

pub fn hash_password(password: &str, phc_salt_string: &SaltString) -> String {
    // resources used:
    // modern rust hashing guide: https://www.lpalmieri.com/posts/password-authentication-in-rust/
    // argon2 docs: https://docs.rs/argon2/latest/argon2/
    let password = password.as_bytes();

    // Argon2 with OWASP params
    let params = Params::new(15000, 2, 1, None).expect("build Argon2 params");
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = hasher
        .hash_password(password, phc_salt_string)
        .expect("hash password");
    password_hash.to_string()
}
