use ed25519_dalek::pkcs8::Error as PKCS8Error;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UpdaterError {
    // ==================== input errors (sign) ====================
    #[error("Package file '{0}' does not exist or is not accessible")]
    PackageNotFound(PathBuf),

    #[error("Private key file '{0}' does not exist or is not accessible")]
    PrivateKeyNotFound(PathBuf),

    #[error("Package file '{0}' is not a ZIP file")]
    InvalidPackageFormat(PathBuf),

    #[error("Failed to parse private key from '{content}': {source}")]
    PrivateKeyParseFailed { content: String, source: PKCS8Error },

    #[error("URL '{0}' must start with 'https://'. HTTP is not supported for security reasons")]
    UrlInvalid(String),

    #[error(
        "Invalid SemVer version '{version}': {source}. Expected format: X.Y.Z (e.g., 1.2.3, 2.0.0-beta.1)"
    )]
    VersionInvalid {
        version: String,
        source: semver::Error,
    },

    // ==================== output errors (common) ====================
    #[error("Operation '{action}' failed for path '{path}': {source}")]
    Io {
        action: IoAction,
        path: PathBuf,
        source: std::io::Error,
    },

    // ==================== output errors (generate keys) ====================
    #[error(
        "Key files already exist in '{path}'. Use -f or --force to overwrite.\n  Private key: {private}\n  Public key: {public}"
    )]
    KeyAlreadyExists {
        path: PathBuf,
        private: PathBuf,
        public: PathBuf,
    },

    #[error("Output path {0} is a file, but a directory is required.")]
    OutputIsFile(String),

    #[error("Operation 'write file' failed for path '{path}': {source}")]
    KeyWriteFailed { path: PathBuf, source: PKCS8Error },

    // ==================== output errors (sign) ====================
    #[error("Output manifest file '{0}' already exists. Use -f or --force to overwrite")]
    ManifestAlreadyExists(PathBuf),

    #[error("Failed to serialize manifest to JSON: {0}")]
    SerializationFailed(serde_json::Error),
}

impl UpdaterError {
    pub fn to_exit_code(&self) -> ExitCode {
        use UpdaterError::*;
        match self {
            KeyAlreadyExists { .. } | ManifestAlreadyExists { .. } => ExitCode::AccessError,

            PackageNotFound(_) | PrivateKeyNotFound(_) | OutputIsFile(_) | UrlInvalid(_) => {
                ExitCode::InvalidInput
            }

            InvalidPackageFormat(_) | PrivateKeyParseFailed { .. } | VersionInvalid { .. } => {
                ExitCode::DataError
            }

            Io { .. } | KeyWriteFailed { .. } => ExitCode::IoError,

            SerializationFailed(_) => ExitCode::InternalError,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum IoAction {
    CreateDir,
    OpenFile,
    ReadFile,
    WriteFile,
    RemoveFile,
}

impl std::fmt::Display for IoAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use IoAction::*;
        let s = match self {
            CreateDir => "create directory",
            OpenFile => "open file",
            ReadFile => "read file",
            WriteFile => "write file",
            RemoveFile => "remove file",
        };
        write!(f, "{}", s)
    }
}

#[repr(i32)]
pub enum ExitCode {
    Success = 0,
    Unknown = 1,
    InvalidInput = 10,
    IoError = 11,
    AccessError = 12,
    DataError = 13,
    InternalError = 14,
}

impl ExitCode {
    pub fn exit(self) -> ! {
        std::process::exit(self as i32);
    }
}
