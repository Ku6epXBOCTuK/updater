use assert_cmd::{Command, cargo};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use tempfile::tempdir;
use updater::{error::ExitCode, format_canonical};
use zip::write::FileOptions;

static BIN_PATH: LazyLock<PathBuf> = LazyLock::new(|| cargo::cargo_bin!("sign-tool").into());

fn create_dummy_zip(path: &Path) {
    let file = fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("test.txt", FileOptions::<()>::default())
        .unwrap();
    zip.write_all(b"Hello, world!").unwrap();
    zip.finish().unwrap();
}

// ==================== generate-keys tests ====================

#[test]
fn test_generate_keys_creates_files() {
    let temp_dir = tempdir().unwrap();
    let out_dir = temp_dir.path().join("keys");

    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&["generate-keys", "--out-dir", out_dir.to_str().unwrap()]);
    cmd.assert().success();

    assert!(out_dir.join("private_key.pem").exists());
    assert!(out_dir.join("public_key.hex").exists());

    let pub_key_hex = fs::read_to_string(out_dir.join("public_key.hex")).unwrap();
    assert_eq!(pub_key_hex.len(), 64);
    assert!(pub_key_hex.chars().all(|c| c.is_ascii_hexdigit()));

    let priv_key_pem = fs::read_to_string(out_dir.join("private_key.pem")).unwrap();
    assert!(priv_key_pem.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn test_generate_keys_existing_without_force_fails() {
    let temp_dir = tempdir().unwrap();
    let out_dir = temp_dir.path().join("keys");
    fs::create_dir(&out_dir).unwrap();
    fs::write(out_dir.join("private_key.pem"), "dummy").unwrap();

    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&["generate-keys", "--out-dir", out_dir.to_str().unwrap()]);
    cmd.assert().code(ExitCode::AccessError as i32);
}

#[test]
fn test_generate_keys_existing_with_force_overwrites() {
    let temp_dir = tempdir().unwrap();
    let out_dir = temp_dir.path().join("keys");
    fs::create_dir(&out_dir).unwrap();
    fs::write(out_dir.join("private_key.pem"), "dummy").unwrap();

    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&[
        "generate-keys",
        "--out-dir",
        out_dir.to_str().unwrap(),
        "--force",
    ]);
    cmd.assert().success();

    let priv_key_pem = fs::read_to_string(out_dir.join("private_key.pem")).unwrap();
    assert!(priv_key_pem.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn test_generate_keys_out_dir_is_file_error() {
    let temp_dir = tempdir().unwrap();
    let out_file = temp_dir.path().join("file.txt");
    fs::write(&out_file, "I am a file").unwrap();

    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&["generate-keys", "--out-dir", out_file.to_str().unwrap()]);
    cmd.assert().code(ExitCode::InvalidInput as i32);
}

// ==================== sign tests ====================

#[test]
fn test_sign_with_valid_inputs() {
    let temp_dir = tempdir().unwrap();

    let keys_dir = temp_dir.path().join("keys");
    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&["generate-keys", "--out-dir", keys_dir.to_str().unwrap()]);
    cmd.assert().success();

    let zip_path = temp_dir.path().join("package.zip");
    create_dummy_zip(&zip_path);

    let url = "https://example.com/package.zip";
    let version = "1.2.3";
    let output = temp_dir.path().join("update_manifest.json");

    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&[
        "sign",
        "--package",
        zip_path.to_str().unwrap(),
        "--url",
        url,
        "--version",
        version,
        "--private-key",
        keys_dir.join("private_key.pem").to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    cmd.assert().success();

    assert!(output.exists());

    let manifest_content = fs::read_to_string(&output).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&manifest_content).unwrap();

    assert_eq!(manifest["version"], version);
    assert_eq!(manifest["url"], url);

    let mut file = fs::File::open(&zip_path).unwrap();
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).unwrap();
    let expected_sha256 = hex::encode(hasher.finalize());
    assert_eq!(manifest["sha256"].as_str().unwrap(), expected_sha256);

    let signature_b64 = manifest["signature"].as_str().unwrap();
    let public_key_hex = fs::read_to_string(keys_dir.join("public_key.hex")).unwrap();
    let public_key_bytes = hex::decode(public_key_hex).unwrap();
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes.try_into().unwrap()).unwrap();
    let signature_bytes = BASE64.decode(signature_b64).unwrap();
    assert_eq!(signature_bytes.len(), 64);
    let signature = Signature::from_bytes(&signature_bytes.try_into().unwrap());

    let canonical = format_canonical(version, url, &expected_sha256);
    verifying_key
        .verify_strict(canonical.as_bytes(), &signature)
        .unwrap();
}

#[test]
fn test_sign_invalid_url() {
    let temp_dir = tempdir().unwrap();
    let zip_path = temp_dir.path().join("package.zip");
    create_dummy_zip(&zip_path);

    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&[
        "sign",
        "--package",
        zip_path.to_str().unwrap(),
        "--url",
        "http://insecure.com/package.zip",
        "--version",
        "1.0.0",
        "--private-key",
        "dummy",
    ]);
    cmd.assert().code(ExitCode::InvalidInput as i32);
}

#[test]
fn test_sign_invalid_version() {
    let temp_dir = tempdir().unwrap();
    let zip_path = temp_dir.path().join("package.zip");
    create_dummy_zip(&zip_path);

    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&[
        "sign",
        "--package",
        zip_path.to_str().unwrap(),
        "--url",
        "https://example.com/package.zip",
        "--version",
        "not-semver",
        "--private-key",
        "dummy",
    ]);
    cmd.assert().code(ExitCode::DataError as i32);
}

#[test]
fn test_sign_package_not_found() {
    let temp_dir = tempdir().unwrap();
    let zip_path = temp_dir.path().join("nonexistent.zip");

    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&[
        "sign",
        "--package",
        zip_path.to_str().unwrap(),
        "--url",
        "https://example.com/package.zip",
        "--version",
        "1.0.0",
        "--private-key",
        "dummy",
    ]);
    cmd.assert().code(ExitCode::InvalidInput as i32);
}

#[test]
fn test_sign_private_key_not_found() {
    let temp_dir = tempdir().unwrap();
    let zip_path = temp_dir.path().join("package.zip");
    create_dummy_zip(&zip_path);
    let private_key_path = temp_dir.path().join("missing.pem");

    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&[
        "sign",
        "--package",
        zip_path.to_str().unwrap(),
        "--url",
        "https://example.com/package.zip",
        "--version",
        "1.0.0",
        "--private-key",
        private_key_path.to_str().unwrap(),
    ]);
    cmd.assert().code(ExitCode::InvalidInput as i32);
}

#[test]
fn test_sign_output_exists_without_force_fails() {
    let temp_dir = tempdir().unwrap();

    let keys_dir = temp_dir.path().join("keys");
    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&["generate-keys", "--out-dir", keys_dir.to_str().unwrap()]);
    cmd.assert().success();

    let zip_path = temp_dir.path().join("package.zip");
    create_dummy_zip(&zip_path);
    let output = temp_dir.path().join("update_manifest.json");
    fs::write(&output, "dummy").unwrap();

    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&[
        "sign",
        "--package",
        zip_path.to_str().unwrap(),
        "--url",
        "https://example.com/package.zip",
        "--version",
        "1.0.0",
        "--private-key",
        keys_dir.join("private_key.pem").to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    cmd.assert().code(ExitCode::AccessError as i32);
}

#[test]
fn test_sign_output_exists_with_force_overwrites() {
    let temp_dir = tempdir().unwrap();

    let keys_dir = temp_dir.path().join("keys");
    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&["generate-keys", "--out-dir", keys_dir.to_str().unwrap()]);
    cmd.assert().success();

    let zip_path = temp_dir.path().join("package.zip");
    create_dummy_zip(&zip_path);
    let output = temp_dir.path().join("update_manifest.json");
    fs::write(&output, "dummy").unwrap();

    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&[
        "sign",
        "--package",
        zip_path.to_str().unwrap(),
        "--url",
        "https://example.com/package.zip",
        "--version",
        "1.0.0",
        "--private-key",
        keys_dir.join("private_key.pem").to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--force",
    ]);
    cmd.assert().success();

    let content = fs::read_to_string(&output).unwrap();
    assert!(content.starts_with('{'));
}

#[test]
fn test_sign_creates_output_directory() {
    let temp_dir = tempdir().unwrap();

    let keys_dir = temp_dir.path().join("keys");
    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&["generate-keys", "--out-dir", keys_dir.to_str().unwrap()]);
    cmd.assert().success();

    let zip_path = temp_dir.path().join("package.zip");
    create_dummy_zip(&zip_path);
    let output = temp_dir.path().join("subdir").join("manifest.json");

    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&[
        "sign",
        "--package",
        zip_path.to_str().unwrap(),
        "--url",
        "https://example.com/package.zip",
        "--version",
        "1.0.0",
        "--private-key",
        keys_dir.join("private_key.pem").to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    cmd.assert().success();

    assert!(output.exists());
}

#[test]
fn test_sign_deterministic() {
    let temp_dir = tempdir().unwrap();

    let keys_dir = temp_dir.path().join("keys");
    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&["generate-keys", "--out-dir", keys_dir.to_str().unwrap()]);
    cmd.assert().success();

    let zip_path = temp_dir.path().join("package.zip");
    create_dummy_zip(&zip_path);
    let url = "https://example.com/package.zip";
    let version = "1.2.3";

    let output1 = temp_dir.path().join("manifest1.json");
    let output2 = temp_dir.path().join("manifest2.json");

    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&[
        "sign",
        "--package",
        zip_path.to_str().unwrap(),
        "--url",
        url,
        "--version",
        version,
        "--private-key",
        keys_dir.join("private_key.pem").to_str().unwrap(),
        "--output",
        output1.to_str().unwrap(),
    ]);
    cmd.assert().success();

    let mut cmd = Command::new(&*BIN_PATH);
    cmd.args(&[
        "sign",
        "--package",
        zip_path.to_str().unwrap(),
        "--url",
        url,
        "--version",
        version,
        "--private-key",
        keys_dir.join("private_key.pem").to_str().unwrap(),
        "--output",
        output2.to_str().unwrap(),
    ]);
    cmd.assert().success();

    let manifest1: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(output1).unwrap()).unwrap();
    let manifest2: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(output2).unwrap()).unwrap();

    assert_eq!(manifest1["signature"], manifest2["signature"]);
}
