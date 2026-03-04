# Launcher-Core

Universal self-update system for portable Windows applications.

## Description

Launcher-Core is a set of tools for creating portable Windows applications with transparent self-update mechanism. The system is fully abstracted from specific software and allows building branded launchers from a single source code.

### System Components

- **Launcher Source**: Rust repository containing the launcher template and `sign-tool` utility for working with manifests and keys
- **Sign-Tool**: CLI utility for generating Ed25519 keys and creating signed manifests for ZIP update archives

### Features

- **Automatic Updates**: Transparent application updates without user intervention
- **Security**: Ed25519 algorithm for manifest signing and SHA256 for integrity verification
- **Atomic Updates**: Guarantee that updates are either fully applied or do not affect the running version
- **Offline Mode**: Application continues to work when network is unavailable if local version is intact
- **Logging**: Detailed logging of all update stages with log rotation

## Installation

```bash
cargo build --release
```

After building, executable files will be in the `target/release/` directory.

## Usage

### Generating Keys

```bash
# Create keys in ./keys directory
updater-tool generate-keys --out-dir ./keys

# Force overwrite existing keys
updater-tool generate-keys --out-dir ./keys --force
```

### Signing Archive

```bash
sign-tool sign \
  --package ./release/Package.zip \
  --url "https://example.com/Package.zip" \
  --version "1.2.3" \
  --private-key ./keys/private_key.pem \
  --output ./release/update_manifest.json
```

## Architecture

The system consists of two main components:

1. **Launcher** - application entry point that checks for updates and downloads them
2. **Updater-Tool** - utility for creating signed update manifests

### Manifest Format

Manifest (`update_manifest.json`) is a JSON object:

```json
{
  "version": "1.2.3",
  "url": "https://example.com/download/Package.zip",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "signature": "ed25519_base64_signature"
}
```

Signature is created by signing the canonical string `<version>|<url>|<sha256>` with the private key.

### Build-time Parameterization

The following environment variables are injected into the launcher code at compile time:

- `APP_NAME` - application name (for file names)
- `MANIFEST_URL` - permanent link to `update_manifest.json` (HTTPS)
- `PUBLIC_KEY` - Ed25519 public key in hex format

## Security

- **Ed25519** - guarantee of manifest authenticity
- **SHA256** - integrity control of downloaded archive and local core
- **HTTPS** - mandatory for all URLs to prevent MITM attacks
- **Atomic Renames** - exclude application corruption on failures
- **Process Locking via Mutex** - prevents file replacement while core is running

## Documentation

Detailed architecture and usage documentation is available in the [docs/](docs/) directory:

- [System Architecture](docs/adr-main.md)
- [Updater-Tool](docs/adr-sign-tool.md)

## License

This project is dual-licensed under MIT/Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.
