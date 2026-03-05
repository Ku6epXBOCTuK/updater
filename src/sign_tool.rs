use base64::{Engine, prelude::BASE64_STANDARD as BASE64};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{
    Signer, SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use rand::rngs::OsRng;
use semver::Version;
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use updater::{
    UpdateManifest,
    error::{IoAction, UpdaterError},
    format_canonical,
};

#[derive(Parser, Debug)]
#[command(name = "sign-tool", version = env!("CARGO_PKG_VERSION"), 
about = "Tool for updater. Can generate keys and update manifest JSON file")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    GenerateKeys(GenerateKeysArgs),
    Sign(SignArgs),
}

#[derive(Args, Debug)]
struct GenerateKeysArgs {
    /// Path to output keys directory
    #[arg(long, short, default_value = "./keys")]
    out_dir: PathBuf,
    /// Overwrite existing files
    #[arg(short, long)]
    force: bool,
}

fn generate_keys(out_dir: PathBuf, force: bool) -> Result<(), UpdaterError> {
    let priv_path = out_dir.join("private_key.pem");
    let pub_path = out_dir.join("public_key.hex");

    if out_dir.exists() && out_dir.is_file() {
        return Err(UpdaterError::OutputIsFile(out_dir.display().to_string()));
    }

    if !force && (priv_path.exists() || pub_path.exists()) {
        return Err(UpdaterError::KeyAlreadyExists {
            path: out_dir,
            private: priv_path,
            public: pub_path,
        });
    }

    println!("Creating directory: {}", out_dir.display());
    fs::create_dir_all(&out_dir).map_err(|e| UpdaterError::Io {
        action: IoAction::CreateDir,
        path: out_dir,
        source: e,
    })?;

    println!("Generating Ed25519 key pair...");
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    println!("Writing private key to: {}", priv_path.display());
    signing_key
        .write_pkcs8_pem_file(&priv_path, Default::default())
        .map_err(|e| UpdaterError::KeyWriteFailed {
            path: priv_path,
            source: e,
        })?;

    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());

    println!("Writing public key to: {}", pub_path.display());
    fs::write(&pub_path, &public_key_hex).map_err(|e| UpdaterError::Io {
        action: IoAction::WriteFile,
        path: pub_path,
        source: e,
    })?;

    println!("Keys generated successfully!");
    println!("Public key (HEX): {}", public_key_hex);

    Ok(())
}

#[derive(Args, Debug)]
struct SignArgs {
    /// Path to package file
    #[arg(long, short)]
    package: PathBuf,
    /// Url to package file
    #[arg(long, short)]
    url: String,
    /// Package file version
    #[arg(long, short)]
    version: String,
    /// Path to private key
    #[arg(long, short = 'k', default_value = "./private_key.pem")]
    private_key: PathBuf,
    /// Path to output signed manifest JSON file
    #[arg(long, short, default_value = "./update_manifest.json")]
    output: PathBuf,
    /// Overwrite existing file
    #[arg(short, long)]
    force: bool,
}

fn sign(
    package: PathBuf,
    url: String,
    version: String,
    private_key: PathBuf,
    output: PathBuf,
    force: bool,
) -> Result<(), UpdaterError> {
    println!("Validating input parameters...");

    validate_package(&package)?;
    validate_url(&url)?;
    validate_version(&version)?;

    if !private_key.exists() {
        return Err(UpdaterError::PrivateKeyNotFound(private_key));
    }

    if !force && output.exists() {
        return Err(UpdaterError::ManifestAlreadyExists(output));
    }

    let output_parent = output.parent().unwrap_or_else(|| Path::new("."));
    if !output_parent.exists() {
        println!("Creating directory: {}", output_parent.display());
        fs::create_dir_all(output_parent).map_err(|e| UpdaterError::Io {
            action: IoAction::CreateDir,
            path: output_parent.to_path_buf(),
            source: e,
        })?;
    }

    println!("Loading private key from: {}", private_key.display());
    let private_key_content = fs::read_to_string(&private_key).map_err(|e| UpdaterError::Io {
        action: IoAction::ReadFile,
        path: private_key,
        source: e,
    })?;

    let signing_key = SigningKey::from_pkcs8_pem(&private_key_content).map_err(|e| {
        UpdaterError::PrivateKeyParseFailed {
            content: private_key_content,
            source: e,
        }
    })?;

    println!("Calculating SHA256 hash for package: {}", package.display());
    let mut file = fs::File::open(&package).map_err(|e| UpdaterError::Io {
        action: IoAction::OpenFile,
        path: package.clone(),
        source: e,
    })?;

    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).map_err(|e| UpdaterError::Io {
        action: IoAction::ReadFile,
        path: package,
        source: e,
    })?;

    let hash_bytes = hasher.finalize();
    let hash_hex = hex::encode(hash_bytes);

    println!("Package hash (SHA256): {}", hash_hex);

    println!("Creating signature...");
    let canonical = format_canonical(&version, &url, &hash_hex);
    let signature = signing_key.sign(canonical.as_bytes());
    let signature = BASE64.encode(signature.to_bytes());

    let manifest: UpdateManifest = UpdateManifest {
        url: url.clone(),
        version,
        sha256: hash_hex,
        signature,
    };

    println!("Creating manifest...");
    let manifest_json =
        serde_json::to_string_pretty(&manifest).map_err(UpdaterError::SerializationFailed)?;

    println!("Writing manifest to: {}", output.display());
    fs::write(&output, manifest_json).map_err(|e| UpdaterError::Io {
        action: IoAction::WriteFile,
        path: output.clone(),
        source: e,
    })?;

    println!("Manifest created successfully at: {}", output.display());
    println!("  Version: {}", manifest.version);
    println!("  URL: {}", manifest.url);
    println!("  SHA256: {}", manifest.sha256);

    Ok(())
}

fn validate_package(package: &Path) -> Result<(), UpdaterError> {
    if !package.exists() {
        return Err(UpdaterError::PackageNotFound(package.to_path_buf()));
    }

    if !package
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
    {
        return Err(UpdaterError::InvalidPackageFormat(package.to_path_buf()));
    }
    Ok(())
}

fn validate_url(url: &str) -> Result<(), UpdaterError> {
    if !url.starts_with("https://") {
        return Err(UpdaterError::UrlInvalid(url.to_string()));
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<(), UpdaterError> {
    Version::parse(version).map_err(|e| UpdaterError::VersionInvalid {
        version: version.to_string(),
        source: e,
    })?;
    Ok(())
}

fn run(cli: Cli) -> Result<(), UpdaterError> {
    match cli.command {
        Commands::GenerateKeys(args) => {
            generate_keys(args.out_dir, args.force)?;
        }
        Commands::Sign(args) => {
            sign(
                args.package,
                args.url,
                args.version,
                args.private_key,
                args.output,
                args.force,
            )?;
        }
    };

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    if let Err(err) = run(cli) {
        eprintln!("Error: {}", err);
        std::process::exit(err.to_exit_code() as i32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_url_valid_https() {
        let url = "https://example.com/update.zip";
        assert!(validate_url(url).is_ok());
    }

    #[test]
    fn test_validate_url_invalid_http() {
        let url = "http://example.com/update.zip";
        assert!(validate_url(url).is_err());
    }

    #[test]
    fn test_validate_url_no_protocol() {
        let url = "example.com/update.zip";
        assert!(validate_url(url).is_err());
    }

    #[test]
    fn test_validate_version_valid() {
        let version = "1.2.3";
        assert!(validate_version(version).is_ok());
    }

    #[test]
    fn test_validate_version_with_prerelease() {
        let version = "1.2.3-beta.1";
        assert!(validate_version(version).is_ok());
    }

    #[test]
    fn test_validate_version_with_build_metadata() {
        let version = "1.2.3+build.123";
        assert!(validate_version(version).is_ok());
    }

    #[test]
    fn test_validate_version_invalid_format() {
        let version = "1.2";
        assert!(validate_version(version).is_err());
    }

    #[test]
    fn test_validate_version_invalid_characters() {
        let version = "1.2.3.x";
        assert!(validate_version(version).is_err());
    }
}
