// PHC salt string used in password hashing
use argon2::password_hash::SaltString;

pub fn generate_phc_salt_string() -> SaltString {
    use argon2::password_hash::rand_core::OsRng;
    SaltString::generate(&mut OsRng)
}

pub fn convert_b64_salt(b64_salt: &str) -> SaltString {
    SaltString::from_b64(b64_salt).expect("convert B64 str to PHC SaltString")
}

pub fn hash_password(password: &str, phc_salt_string: &SaltString) -> String {
    // resources used:
    // modern rust hashing guide: https://www.lpalmieri.com/posts/password-authentication-in-rust/
    // argon2 docs: https://docs.rs/argon2/latest/argon2/
    use argon2::{password_hash::PasswordHasher, Algorithm, Argon2, Params, Version};
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
