use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{
    Signer, SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use rand::rngs::OsRng;
use semver::Version;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};
use updater::UpdateManifest;

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

fn generate_keys(out_dir: PathBuf, force: bool) -> Result<(), Box<dyn Error>> {
    let priv_path = out_dir.join("private_key.pem");
    let pub_path = out_dir.join("public_key.hex");

    if out_dir.exists() && out_dir.is_file() {
        return Err(format!(
            "Output path '{}' is a file, but a directory is required.",
            out_dir.display()
        )
        .into());
    }

    if !force && (priv_path.exists() || pub_path.exists()) {
        return Err(format!(
            "Key files already exist in '{}'. Use -f or --force to overwrite.\n  Private key: {}\n  Public key: {}",
            out_dir.display(),
            priv_path.display(),
            pub_path.display()
        ).into());
    }

    println!("Creating directory: {}", out_dir.display());
    fs::create_dir_all(&out_dir)
        .map_err(|e| format!("Failed to create directory '{}': {}", out_dir.display(), e))?;

    println!("Generating Ed25519 key pair...");
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    println!("Writing private key to: {}", priv_path.display());
    signing_key
        .write_pkcs8_pem_file(&priv_path, Default::default())
        .map_err(|e| {
            format!(
                "Failed to write private key to '{}': {}",
                priv_path.display(),
                e
            )
        })?;

    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());

    println!("Writing public key to: {}", pub_path.display());
    fs::write(&pub_path, &public_key_hex).map_err(|e| {
        format!(
            "Failed to write public key to '{}': {}",
            pub_path.display(),
            e
        )
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
) -> Result<(), Box<dyn Error>> {
    println!("Validating input parameters...");

    if !package.exists() {
        return Err(format!(
            "package file '{}' does not exist or is not accessible",
            package.display()
        )
        .into());
    }

    if !package
        .extension()
        .map_or(false, |ext| ext.eq_ignore_ascii_case("zip"))
    {
        return Err(format!(
            "package file '{}' is not a ZIP file. Expected .zip extension",
            package.display()
        )
        .into());
    }

    validate_url(&url)?;
    validate_version(&version)?;

    if !private_key.exists() {
        return Err(format!(
            "Private key file '{}' does not exist or is not accessible",
            private_key.display()
        )
        .into());
    }

    if !force && output.exists() {
        return Err(format!(
            "Output file '{}' already exists. Use -f or --force to overwrite",
            output.display()
        )
        .into());
    }

    let output_parent = output.parent().unwrap_or_else(|| Path::new("."));
    if !output_parent.exists() {
        println!("Creating directory: {}", output_parent.display());
        fs::create_dir_all(output_parent).map_err(|e| {
            format!(
                "Failed to create directory '{}': {}",
                output_parent.display(),
                e
            )
        })?;
    }

    println!("Loading private key from: {}", private_key.display());
    let private_key_content = fs::read_to_string(&private_key).map_err(|e| {
        format!(
            "Failed to read private key file '{}': {}",
            private_key.display(),
            e
        )
    })?;
    let signing_key = SigningKey::from_pkcs8_pem(&private_key_content).map_err(|e| {
        format!(
            "Failed to parse private key from '{}': {}",
            private_key.display(),
            e
        )
    })?;

    println!("Calculating SHA256 hash for package: {}", package.display());
    let mut file = fs::File::open(&package)
        .map_err(|e| format!("Failed to open package file '{}': {}", package.display(), e))?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)
        .map_err(|e| format!("Failed to read package file '{}': {}", package.display(), e))?;
    let hash_bytes = hasher.finalize();
    let hash_hex = hex::encode(hash_bytes);

    println!("Package hash (SHA256): {}", hash_hex);

    println!("Creating signature...");
    let canonical = format_canonical(&version, &url, &hash_hex);
    let signature = signing_key.sign(canonical.as_bytes());

    let manifest: UpdateManifest = UpdateManifest {
        url: url.clone(),
        version: version,
        sha256: hash_hex,
        signature: signature.to_string(),
    };

    println!("Creating manifest...");
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| format!("Failed to serialize manifest to JSON: {}", e))?;

    println!("Writing manifest to: {}", output.display());
    fs::write(&output, manifest_json).map_err(|e| {
        format!(
            "Failed to write manifest file '{}': {}",
            output.display(),
            e
        )
    })?;

    println!("Manifest created successfully at: {}", output.display());
    println!("  Version: {}", manifest.version);
    println!("  URL: {}", manifest.url);
    println!("  SHA256: {}", manifest.sha256);

    Ok(())
}

fn format_canonical(version: &str, url: &str, sha256: &str) -> String {
    format!("{}|{}|{}", version, url, sha256)
}

fn validate_url(url: &str) -> Result<(), Box<dyn Error>> {
    if !url.starts_with("https://") {
        return Err(format!(
            "URL '{}' must start with 'https://'. HTTP is not supported for security reasons",
            url
        )
        .into());
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<(), Box<dyn Error>> {
    Version::parse(version).map_err(|e| {
        format!(
            "Invalid SemVer version '{}': {}. Expected format: X.Y.Z (e.g., 1.2.3, 2.0.0-beta.1)",
            version, e
        )
    })?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

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
    }

    Ok(())
}
