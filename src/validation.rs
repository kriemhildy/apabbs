#[derive(Debug)]
pub struct ValidationError {
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

macro_rules! val {
    ($vec:expr, $msg:expr) => {
        $vec.push(ValidationError {
            message: String::from($msg),
        })
    };
}

pub(crate) use val;
