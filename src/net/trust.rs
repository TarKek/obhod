//! Release trust: SHA-256 integrity and Ed25519 manifest signatures.
//!
//! The updater must never install an older or tampered binary. Two independent
//! checks are implemented here:
//!
//! 1. **SHA-256** — the downloaded asset hash is compared with the hash from
//!    the signed manifest, or (when no manifest is published) with the
//!    `digest` field of the GitHub API asset.
//! 2. **Ed25519** — a detached signature (`obhod-manifest.json.sig`, base64)
//!    over the raw manifest bytes, verified with a public key compiled into
//!    the binary.
//!
//! If no public key is configured, verification returns [`TrustLevel::Unverified`]
//! and the update may proceed on the hash check alone — but nothing claims a
//! cryptographic signature was verified. When a key *is* configured, a
//! missing or invalid signature is fatal for the update.
//!
//! ## Publishing signed releases (GitHub Actions)
//!
//! No private key is ever stored in this repository. The maintainer generates
//! a keypair once, keeps the private half in the repository secret
//! `ED25519_PRIVATE_KEY` (base64 of the 32-byte seed) and puts the public half
//! into [`RELEASE_PUBKEY_B64`] below (base64 of the 32 raw bytes):
//!
//! ```text
//! # once, locally
//! openssl genpkey -algorithm ED25519 -out release-key.pem
//! openssl pkey -in release-key.pem -pubout -outform DER | tail -c 32 | base64 -w0
//! base64 -w0 release-key.pem   # -> repository secret, never committed
//! ```
//!
//! ```yaml
//! # .github/workflows/release.yml (excerpt)
//! - name: Sign manifest
//!   shell: bash
//!   run: |
//!     echo "$ED25519_PRIVATE_KEY" | base64 -d > release-key.pem
//!     printf '%s' obhod-manifest.json > manifest.bin
//!     openssl pkeyutl -sign -inkey release-key.pem -rawin \
//!       -in manifest.bin -out sig.bin
//!     base64 -w0 sig.bin > obhod-manifest.json.sig
//!   env:
//!     ED25519_PRIVATE_KEY: ${{ secrets.ED25519_PRIVATE_KEY }}
//! ```
//!
//! Then upload `obhod.exe`, `obhod-manifest.json` and
//! `obhod-manifest.json.sig` as release assets. `obhod-manifest.json`:
//!
//! ```json
//! { "version": "0.2.0", "asset": "obhod.exe",
//!   "sha256": "<hash of obhod.exe>", "published_at": "2026-11-13T10:00:00Z",
//!   "min_version": "0.1.4" }
//! ```

use serde::{Deserialize, Serialize};

use crate::net::{b64_decode, b64_encode, sha256_hex};

/// Asset name of the signed manifest in a GitHub release.
pub const MANIFEST_ASSET: &str = "obhod-manifest.json";
/// Detached Ed25519 signature over the raw manifest bytes (base64).
pub const SIGNATURE_ASSET: &str = "obhod-manifest.json.sig";

/// Trusted release public key (base64 of 32 raw Ed25519 bytes).
///
/// `None` = no key pinned yet. The updater then reports [`TrustLevel::Unverified`]
/// and relies on the SHA-256 check only. Replace with the real public key
/// **before** publishing signed releases; never put a private key here.
pub const RELEASE_PUBKEY_B64: Option<&str> = None;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub version: String,
    pub asset: String,
    pub sha256: String,
    #[serde(default)]
    pub published_at: String,
    /// Oldest installed version this update can be applied from.
    #[serde(default)]
    pub min_version: Option<String>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustLevel {
    /// Signature checked against a pinned key.
    Verified,
    /// Hash/version checked, but no trusted key was configured: no claim of
    /// cryptographic authenticity.
    Unverified,
    /// Something did not match: do not install.
    Invalid,
}

impl TrustLevel {
    pub fn ru(self) -> &'static str {
        match self {
            TrustLevel::Verified => "подпись проверена",
            TrustLevel::Unverified => "подпись не проверена (ключ не настроен)",
            TrustLevel::Invalid => "проверка не пройдена",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ManifestCheck {
    /// Safe to install: hash and version checks passed (signature may be absent
    /// only when no key is pinned).
    pub accepted: bool,
    pub trust: TrustLevel,
    pub manifest: Option<Manifest>,
    pub reason: String,
}

impl ManifestCheck {
    fn reject(reason: impl Into<String>, manifest: Option<Manifest>) -> Self {
        Self {
            accepted: false,
            trust: TrustLevel::Invalid,
            manifest,
            reason: reason.into(),
        }
    }
}

/// Parses manifest bytes into the structured form.
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, String> {
    serde_json::from_slice::<Manifest>(bytes).map_err(|e| format!("манифест не читается: {e}"))
}

/// Verifies the detached Ed25519 signature of `manifest_bytes`.
///
/// `pubkey_b64` and `signature_b64` are base64 of 32 / 64 raw bytes.
pub fn verify_signature(
    manifest_bytes: &[u8],
    signature_b64: &str,
    pubkey_b64: &str,
) -> Result<(), String> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let key_raw =
        b64_decode(pubkey_b64.trim()).ok_or_else(|| "публичный ключ не base64".to_string())?;
    let key_arr: [u8; 32] = key_raw.as_slice().try_into().map_err(|_| {
        format!(
            "публичный ключ должен быть 32 байта, а не {}",
            key_raw.len()
        )
    })?;
    let key = VerifyingKey::from_bytes(&key_arr)
        .map_err(|e| format!("публичный ключ не Ed25519: {e}"))?;

    let sig_raw =
        b64_decode(signature_b64.trim()).ok_or_else(|| "подпись не base64".to_string())?;
    let sig_arr: [u8; 64] = sig_raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("подпись должна быть 64 байта, а не {}", sig_raw.len()))?;
    let signature = Signature::from_bytes(&sig_arr);

    key.verify_strict(manifest_bytes, &signature)
        .map_err(|_| "подпись не совпадает с манифестом".to_string())
}

/// Full admission check for a downloaded release.
///
/// * `signature_b64` — asset content of [`SIGNATURE_ASSET`], `None` if missing.
/// * `pubkey_b64` — override for tests; production uses [`RELEASE_PUBKEY_B64`].
/// * `actual_sha256` — hash of the downloaded binary (lowercase hex).
pub fn verify_manifest_bytes(
    manifest_bytes: &[u8],
    signature_b64: Option<&str>,
    pubkey_b64: Option<&str>,
    current_version: &str,
    asset_name: &str,
    actual_sha256: &str,
) -> ManifestCheck {
    let manifest = match parse_manifest(manifest_bytes) {
        Ok(m) => m,
        Err(e) => return ManifestCheck::reject(e, None),
    };

    // --- integrity ------------------------------------------------------
    let expected = match normalize_sha256(&manifest.sha256) {
        Some(h) => h,
        None => return ManifestCheck::reject("в манифесте нет корректного sha256", Some(manifest)),
    };
    let actual = normalize_sha256(actual_sha256).unwrap_or_default();
    if expected != actual {
        return ManifestCheck::reject(
            format!("sha256 не совпадает: ожидалось {expected}, получено {actual}"),
            Some(manifest),
        );
    }
    if !manifest.asset.eq_ignore_ascii_case(asset_name) {
        return ManifestCheck::reject(
            format!(
                "манифест описывает «{}», а не «{asset_name}»",
                manifest.asset
            ),
            Some(manifest),
        );
    }

    // --- version / rollback protection ---------------------------------
    let latest = match parse_version(&manifest.version) {
        Some(v) => v,
        None => {
            return ManifestCheck::reject(
                format!("версия «{}» не разбирается", manifest.version),
                Some(manifest),
            )
        }
    };
    let current = parse_version(current_version).unwrap_or((0, 0, 0));
    if latest <= current {
        return ManifestCheck::reject(
            format!(
                "отказ от отката: в манифесте {} — не новее установленной {}",
                manifest.version, current_version
            ),
            Some(manifest),
        );
    }
    if let Some(min) = manifest.min_version.as_deref() {
        if let Some(min_v) = parse_version(min) {
            if current < min_v {
                return ManifestCheck::reject(
                    format!("обновление требует версию {min} или новее (сейчас {current_version})"),
                    Some(manifest),
                );
            }
        }
    }

    // --- authenticity ---------------------------------------------------
    let key = pubkey_b64
        .or(RELEASE_PUBKEY_B64)
        .map(str::trim)
        .filter(|k| !k.is_empty());
    let Some(key) = key else {
        return ManifestCheck {
            accepted: true,
            trust: TrustLevel::Unverified,
            reason: "доверенный ключ не настроен: sha256 и версия проверены, подпись — нет".into(),
            manifest: Some(manifest),
        };
    };
    let Some(sig) = signature_b64.map(str::trim).filter(|s| !s.is_empty()) else {
        return ManifestCheck::reject("нет файла подписи манифеста", Some(manifest));
    };
    match verify_signature(manifest_bytes, sig, key) {
        Ok(()) => ManifestCheck {
            accepted: true,
            trust: TrustLevel::Verified,
            reason: "подпись Ed25519 проверена".into(),
            manifest: Some(manifest),
        },
        Err(e) => ManifestCheck::reject(format!("подпись недействительна: {e}"), Some(manifest)),
    }
}

/// Normalizes `sha256:<hex>`, `<HEX>` and `sha256=<hex>` to lowercase hex.
pub fn normalize_sha256(raw: &str) -> Option<String> {
    let s = raw.trim();
    let s = s
        .strip_prefix("sha256:")
        .or_else(|| s.strip_prefix("SHA256:"))
        .or_else(|| s.strip_prefix("sha256="))
        .unwrap_or(s);
    let s = s.trim().to_ascii_lowercase();
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(s)
    } else {
        None
    }
}

/// Compares a GitHub API `digest` field (`sha256:<hex>`) with the actual hash.
///
/// `None` when the API gave no usable digest, `Some(false)` on mismatch.
pub fn digest_matches(api_digest: Option<&str>, actual_sha256: &str) -> Option<bool> {
    let raw = api_digest?;
    let expected = normalize_sha256(raw)?;
    let actual = normalize_sha256(actual_sha256)?;
    Some(expected == actual)
}

pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim().trim_start_matches(['v', 'V']);
    let core = core.split(['-', '+']).next().unwrap_or(core);
    let mut it = core.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next().unwrap_or("0").parse().ok()?;
    let c = it.next().unwrap_or("0").parse().ok()?;
    Some((a, b, c))
}

pub fn version_is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

/// Short hash of a manifest bytes blob, for logs.
pub fn manifest_fingerprint(bytes: &[u8]) -> String {
    let mut h = sha256_hex(bytes);
    h.truncate(16);
    h
}

/// Helper for the release pipeline and tests: base64 of raw bytes.
pub fn encode_signature(sig: &[u8]) -> String {
    b64_encode(sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const SHA_GOOD: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn keypair() -> (SigningKey, String) {
        // Deterministic test-only seed. It is never used for real releases.
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = b64_encode(sk.verifying_key().as_bytes());
        (sk, pk)
    }

    fn manifest_json(version: &str, sha: &str) -> Vec<u8> {
        format!(
            r#"{{"version":"{version}","asset":"obhod.exe","sha256":"{sha}","published_at":"2026-11-13T10:00:00Z","min_version":"0.1.0"}}"#
        )
        .into_bytes()
    }

    fn sign(sk: &SigningKey, bytes: &[u8]) -> String {
        b64_encode(&sk.sign(bytes).to_bytes())
    }

    fn check(
        bytes: &[u8],
        sig: Option<&str>,
        key: Option<&str>,
        current: &str,
        actual: &str,
    ) -> ManifestCheck {
        verify_manifest_bytes(bytes, sig, key, current, "obhod.exe", actual)
    }

    #[test]
    fn valid_signature_is_verified() {
        let (sk, pk) = keypair();
        let m = manifest_json("0.2.0", SHA_GOOD);
        let r = check(&m, Some(&sign(&sk, &m)), Some(&pk), "0.1.4", SHA_GOOD);
        assert!(r.accepted, "{}", r.reason);
        assert_eq!(r.trust, TrustLevel::Verified);
        assert_eq!(r.manifest.unwrap().version, "0.2.0");
    }

    #[test]
    fn tampered_manifest_fails_signature() {
        let (sk, pk) = keypair();
        let m = manifest_json("0.2.0", SHA_GOOD);
        let sig = sign(&sk, &m);
        let tampered = manifest_json("0.9.9", SHA_GOOD);
        let r = check(&tampered, Some(&sig), Some(&pk), "0.1.4", SHA_GOOD);
        assert!(!r.accepted);
        assert_eq!(r.trust, TrustLevel::Invalid);
        assert!(r.reason.contains("подпись"));
    }

    #[test]
    fn garbage_signature_is_rejected() {
        let m = manifest_json("0.2.0", SHA_GOOD);
        let (_, pk) = keypair();
        let r = check(&m, Some("not-base64!!"), Some(&pk), "0.1.4", SHA_GOOD);
        assert!(!r.accepted);
        let r2 = check(&m, Some("AAAA"), Some(&pk), "0.1.4", SHA_GOOD);
        assert!(!r2.accepted);
    }

    #[test]
    fn wrong_download_hash_is_rejected_even_without_a_key() {
        let m = manifest_json("0.2.0", SHA_GOOD);
        let other = "0".repeat(64);
        let r = check(&m, None, None, "0.1.4", &other);
        assert!(!r.accepted);
        assert!(r.reason.contains("sha256"));
        assert_eq!(r.trust, TrustLevel::Invalid);
    }

    #[test]
    fn downgrade_and_same_version_are_rejected() {
        let (sk, pk) = keypair();
        for v in ["0.1.3", "0.1.4", "v0.1.0"] {
            let m = manifest_json(v, SHA_GOOD);
            let r = check(&m, Some(&sign(&sk, &m)), Some(&pk), "0.1.4", SHA_GOOD);
            assert!(!r.accepted, "version {v} must be rejected");
            assert!(r.reason.contains("отката") || r.reason.contains("не новее"));
        }
    }

    #[test]
    fn min_version_gate_is_honored() {
        let (sk, pk) = keypair();
        let m = format!(
            r#"{{"version":"0.3.0","asset":"obhod.exe","sha256":"{SHA_GOOD}","min_version":"0.2.0"}}"#
        )
        .into_bytes();
        let r = check(&m, Some(&sign(&sk, &m)), Some(&pk), "0.1.4", SHA_GOOD);
        assert!(!r.accepted);
        assert!(r.reason.contains("0.2.0"));
    }

    #[test]
    fn missing_key_is_unverified_not_verified() {
        let m = manifest_json("0.2.0", SHA_GOOD);
        let r = check(&m, None, None, "0.1.4", SHA_GOOD);
        assert!(r.accepted);
        assert_eq!(r.trust, TrustLevel::Unverified);
        assert!(r.reason.contains("ключ не настроен"));
    }

    #[test]
    fn key_pinned_but_signature_missing_is_fatal() {
        let (_, pk) = keypair();
        let m = manifest_json("0.2.0", SHA_GOOD);
        let r = check(&m, None, Some(&pk), "0.1.4", SHA_GOOD);
        assert!(!r.accepted);
        assert!(r.reason.contains("подпис"));
    }

    #[test]
    fn broken_manifest_json_is_rejected() {
        let r = check(b"{not json", None, None, "0.1.4", SHA_GOOD);
        assert!(!r.accepted);
        assert!(r.manifest.is_none());
    }

    #[test]
    fn sha_normalization_and_digest() {
        let hex = SHA_GOOD;
        assert_eq!(normalize_sha256(hex), Some(hex.to_string()));
        assert_eq!(
            normalize_sha256(&format!("sha256:{}", hex.to_uppercase())),
            Some(hex.to_string())
        );
        assert_eq!(normalize_sha256("sha256=abc"), None);
        assert_eq!(
            digest_matches(Some(&format!("sha256:{hex}")), hex),
            Some(true)
        );
        assert_eq!(
            digest_matches(Some(&format!("sha256:{}", "a".repeat(64))), hex),
            Some(false)
        );
        assert_eq!(digest_matches(None, hex), None);
        assert_eq!(digest_matches(Some("garbage"), hex), None);
    }

    #[test]
    fn version_helpers() {
        assert!(version_is_newer("v0.2.0", "0.1.4"));
        assert!(!version_is_newer("0.1.4", "0.1.4"));
        assert_eq!(parse_version("1.2"), Some((1, 2, 0)));
        assert_eq!(parse_version("мусор"), None);
    }
}
