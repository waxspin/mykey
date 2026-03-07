use std::fs;
use std::path::{Path, PathBuf};

use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{MikeyError, Result};

const PUBLIC_KEY_FILENAME: &str = "mykey.pub";
const SECRET_KEY_FILENAME: &str = "mykey.key";

/// A persistent X25519 identity keypair for opt-in MITM protection.
///
/// **This is not the default mode.** By default, [`DhInitiator`](crate::message::DhInitiator)
/// and [`DhResponder`](crate::message::DhResponder) use ephemeral keys that provide
/// forward secrecy without identity verification — suitable for trusted/isolated networks.
///
/// Use `Identity` when you need to:
/// - Pin peer public keys to prevent man-in-the-middle attacks
/// - Maintain a stable identity across sessions (like SSH host keys)
/// - Distribute public keys out-of-band (rsync, scp, config management)
///
/// ## File layout
///
/// - `mykey.key` — hex-encoded secret key (mode 0600 on unix)
/// - `mykey.pub` — hex-encoded public key (safe to distribute)
///
/// Default location: `~/.config/mykey/` (unix) or `%APPDATA%\mykey\` (windows)
///
/// ## Example
///
/// ```no_run
/// use std::path::Path;
/// use mykey::identity::{Identity, PinnedPeer};
///
/// // Generate or load persistent identity
/// let my_id = Identity::load_or_generate(Path::new("/etc/mykey")).unwrap();
///
/// // Load a peer's public key (distributed out-of-band)
/// let peer = PinnedPeer::from_file("studio-b", Path::new("/etc/mykey/peers/studio-b.pub")).unwrap();
///
/// // After DH exchange, verify the peer before deriving keys
/// let received_pub = &[0u8; 32]; // from MIKEY message
/// peer.verify(received_pub).unwrap(); // fails if key doesn't match
/// ```
pub struct Identity {
    secret: StaticSecret,
    /// The X25519 public key derived from this identity's secret key.
    pub public: PublicKey,
}

impl Identity {
    /// Generate a new random identity
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Load an identity from a directory, or generate and save a new one
    /// if none exists.
    pub fn load_or_generate(dir: &Path) -> Result<Self> {
        let secret_path = dir.join(SECRET_KEY_FILENAME);
        if secret_path.exists() {
            Self::load(dir)
        } else {
            let identity = Self::generate();
            identity.save(dir)?;
            Ok(identity)
        }
    }

    /// Save the keypair to the given directory.
    ///
    /// Creates the directory if it doesn't exist.
    /// Writes `mykey.key` (hex secret) and `mykey.pub` (hex public).
    pub fn save(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir).map_err(|e| MikeyError::Crypto(format!("create dir: {e}")))?;

        let secret_path = dir.join(SECRET_KEY_FILENAME);
        let public_path = dir.join(PUBLIC_KEY_FILENAME);

        let secret_bytes = self.secret.to_bytes();
        let secret_hex = hex::encode(secret_bytes);
        let public_hex = hex::encode(self.public.as_bytes());

        fs::write(&secret_path, format!("{secret_hex}\n"))
            .map_err(|e| MikeyError::Crypto(format!("write secret: {e}")))?;
        fs::write(&public_path, format!("{public_hex}\n"))
            .map_err(|e| MikeyError::Crypto(format!("write public: {e}")))?;

        // Best-effort: restrict secret key permissions on unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600));
        }

        Ok(())
    }

    /// Load a keypair from the given directory.
    pub fn load(dir: &Path) -> Result<Self> {
        let secret_path = dir.join(SECRET_KEY_FILENAME);
        let secret_hex = fs::read_to_string(&secret_path)
            .map_err(|e| MikeyError::Crypto(format!("read secret: {e}")))?;
        let secret_bytes = hex::decode(secret_hex.trim())
            .map_err(|e| MikeyError::Crypto(format!("decode secret: {e}")))?;

        if secret_bytes.len() != 32 {
            return Err(MikeyError::Crypto(format!(
                "secret key wrong length: {} (expected 32)",
                secret_bytes.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&secret_bytes);
        let secret = StaticSecret::from(key);
        let public = PublicKey::from(&secret);

        Ok(Self { secret, public })
    }

    /// Return the public key as a hex string (for display, config, etc.)
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public.as_bytes())
    }

    /// Return the raw public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Perform DH key exchange with a peer, consuming the static secret
    /// to produce a shared secret.
    ///
    /// Note: unlike `EphemeralSecret`, `StaticSecret` can be reused.
    /// This method takes `&self` so the identity persists across sessions.
    pub fn diffie_hellman(&self, peer_public: &[u8; 32]) -> Vec<u8> {
        let peer = PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        shared.as_bytes().to_vec()
    }

    /// Default config directory: `~/.config/mykey/`
    pub fn default_dir() -> Result<PathBuf> {
        dirs_path().ok_or(MikeyError::Crypto("cannot determine home directory".into()))
    }
}

fn dirs_path() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".config").join("mykey"))
    }
    #[cfg(windows)]
    {
        std::env::var("APPDATA")
            .ok()
            .map(|h| PathBuf::from(h).join("mykey"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// A pinned peer public key, loaded from a file or provided directly.
///
/// Used with [`Identity`] to verify that a DH exchange is happening with
/// the expected peer, preventing man-in-the-middle attacks. Similar in
/// concept to SSH's `known_hosts`.
///
/// Peer public keys (`mykey.pub` files) should be distributed out-of-band
/// via secure channels (rsync over SSH, config management, USB, etc.).
pub struct PinnedPeer {
    /// Human-readable name identifying this peer (used in error messages).
    pub name: String,
    /// The expected X25519 public key for this peer.
    pub public_key: [u8; 32],
}

impl PinnedPeer {
    /// Create from raw bytes
    pub fn new(name: impl Into<String>, public_key: [u8; 32]) -> Self {
        Self {
            name: name.into(),
            public_key,
        }
    }

    /// Load a peer's public key from a `mykey.pub` file
    pub fn from_file(name: impl Into<String>, path: &Path) -> Result<Self> {
        let hex_str = fs::read_to_string(path)
            .map_err(|e| MikeyError::Crypto(format!("read peer key: {e}")))?;
        Self::from_hex(name, hex_str.trim())
    }

    /// Parse from a hex string
    pub fn from_hex(name: impl Into<String>, hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| MikeyError::Crypto(format!("decode peer key: {e}")))?;
        if bytes.len() != 32 {
            return Err(MikeyError::Crypto(format!(
                "peer key wrong length: {} (expected 32)",
                bytes.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self {
            name: name.into(),
            public_key: key,
        })
    }

    /// Verify that a received DH public key matches this pinned peer.
    pub fn verify(&self, received: &[u8]) -> Result<()> {
        if received.len() != 32 {
            return Err(MikeyError::InvalidDhValue);
        }
        if received != self.public_key {
            return Err(MikeyError::PeerKeyMismatch {
                peer: self.name.clone(),
                expected: hex::encode(self.public_key),
                received: hex::encode(received),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_generate_save_load_roundtrip() {
        let dir = std::env::temp_dir().join("mykey_test_identity");
        let _ = fs::remove_dir_all(&dir);

        let original = Identity::generate();
        original.save(&dir).unwrap();

        // Check files exist
        assert!(dir.join("mykey.pub").exists());
        assert!(dir.join("mykey.key").exists());

        // Public key file should be readable hex
        let pub_contents = fs::read_to_string(dir.join("mykey.pub")).unwrap();
        assert_eq!(pub_contents.trim().len(), 64); // 32 bytes = 64 hex chars

        // Load and verify
        let loaded = Identity::load(&dir).unwrap();
        assert_eq!(original.public_key_bytes(), loaded.public_key_bytes());

        // DH should produce same shared secret
        let peer = Identity::generate();
        let shared_a = original.diffie_hellman(&peer.public_key_bytes());
        let shared_b = loaded.diffie_hellman(&peer.public_key_bytes());
        assert_eq!(shared_a, shared_b);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_or_generate() {
        let dir = std::env::temp_dir().join("mykey_test_load_or_gen");
        let _ = fs::remove_dir_all(&dir);

        // First call generates
        let id1 = Identity::load_or_generate(&dir).unwrap();
        // Second call loads the same key
        let id2 = Identity::load_or_generate(&dir).unwrap();
        assert_eq!(id1.public_key_bytes(), id2.public_key_bytes());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_pinned_peer_verify() {
        let peer = Identity::generate();
        let pinned = PinnedPeer::new("test-peer", peer.public_key_bytes());

        // Correct key passes
        pinned.verify(peer.public.as_bytes()).unwrap();

        // Wrong key fails
        let imposter = Identity::generate();
        assert!(pinned.verify(imposter.public.as_bytes()).is_err());
    }

    #[test]
    fn test_pinned_peer_from_hex() {
        let peer = Identity::generate();
        let hex = peer.public_key_hex();

        let pinned = PinnedPeer::from_hex("test", &hex).unwrap();
        assert_eq!(pinned.public_key, peer.public_key_bytes());
    }

    #[test]
    fn test_pinned_peer_from_file() {
        let dir = std::env::temp_dir().join("mykey_test_pinned");
        let _ = fs::remove_dir_all(&dir);

        let peer = Identity::generate();
        peer.save(&dir).unwrap();

        let pinned = PinnedPeer::from_file("test", &dir.join("mykey.pub")).unwrap();
        pinned.verify(peer.public.as_bytes()).unwrap();

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dh_with_identity() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let shared_a = alice.diffie_hellman(&bob.public_key_bytes());
        let shared_b = bob.diffie_hellman(&alice.public_key_bytes());
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn test_peer_key_mismatch_error_fields() {
        use crate::error::MikeyError;

        let expected_peer = Identity::generate();
        let imposter = Identity::generate();

        let pinned = PinnedPeer::new("studio-rack-01", expected_peer.public_key_bytes());
        let err = pinned.verify(imposter.public.as_bytes()).unwrap_err();

        match err {
            MikeyError::PeerKeyMismatch { peer, expected, received } => {
                assert_eq!(peer, "studio-rack-01");
                assert_eq!(expected, expected_peer.public_key_hex());
                assert_eq!(received, imposter.public_key_hex());
            }
            other => panic!("expected PeerKeyMismatch, got {other:?}"),
        }
    }
}
