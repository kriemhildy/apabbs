use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Algorithm, Argon2, Params, PasswordVerifier, Version,
};

// PHC salt string used in password hashing

pub fn generate_phc_salt_string() -> SaltString {
    SaltString::generate(&mut OsRng)
}

pub fn argon2_hasher() -> Argon2<'static> {
    // Argon2 with OWASP params
    let params = Params::new(15000, 2, 1, None).expect("build Argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_password(password: &str, phc_salt_string: &SaltString) -> String {
    // resources used:
    // modern rust hashing guide: https://www.lpalmieri.com/posts/password-authentication-in-rust/
    // argon2 docs: https://docs.rs/argon2/latest/argon2/
    let password = password.as_bytes();
    let hasher = argon2_hasher();
    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = hasher
        .hash_password(password, phc_salt_string)
        .expect("hash password");
    password_hash.to_string()
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let password_bytes = password.as_bytes();
    let parsed_hash = argon2::PasswordHash::new(hash).expect("parse password hash");
    let hasher = argon2_hasher();
    // Verify password against hash
    hasher
        .verify_password(password_bytes, &parsed_hash)
        .is_ok()
}
