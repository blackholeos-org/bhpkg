#[derive(Debug)]
pub enum AppError {
    Io(std::io::Error),
    Db(rusqlite::Error),
    Net(String),
    Solver(String),
    Crypto(String),
    Security(String),
    General(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Io(e) => write!(f, "I/O error: {}", e),
            AppError::Db(e) => write!(f, "Database error: {}", e),
            AppError::Net(e) => write!(f, "Network error: {}", e),
            AppError::Solver(e) => write!(f, "Solver error: {}", e),
            AppError::Crypto(e) => write!(f, "Crypto error: {}", e),
            AppError::Security(e) => write!(f, "Security violation: {}", e),
            AppError::General(e) => write!(f, "Application error: {}", e),
        }
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::Io(err)
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(err: rusqlite::Error) -> Self {
        AppError::Db(err)
    }
}

impl From<nix::errno::Errno> for AppError {
    fn from(err: nix::errno::Errno) -> Self {
        AppError::Io(std::io::Error::from_raw_os_error(err as i32))
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
