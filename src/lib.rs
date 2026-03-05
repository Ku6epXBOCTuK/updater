use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub signature: String,
}

pub struct LocalManifest {
    pub version: String,
    pub sha256: String,
}

pub fn format_canonical(version: &str, url: &str, sha256: &str) -> String {
    format!("{}|{}|{}", version, url, sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_canonical() {
        let version = "1.0.0";
        let url = "https://example.com/update";
        let sha256 = "abc123def456";
        let result = format_canonical(version, url, sha256);
        assert_eq!(result, "1.0.0|https://example.com/update|abc123def456");
    }

    #[test]
    fn test_format_canonical_empty_strings() {
        let result = format_canonical("", "", "");
        assert_eq!(result, "||");
    }
}
