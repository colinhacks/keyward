//! The Secure Enclave key Keyward holds itself.
//!
//! The private scalar never leaves the enclave; what lives on disk is a
//! SEP-wrapped handle that is useless on any other machine. Because
//! Keyward performs the signature, it also writes the authentication prompt —
//! which is the entire point. Secretive can only ever say "a request from
//! launchd", since by the time it sees the request the caller's identity has
//! been laundered through the proxy.

use crate::wire::Writer;
use std::ffi::CString;
use std::path::PathBuf;

extern "C" {
    fn kwse_available() -> i32;
    fn kwse_forget(scope: *const i8);
    fn kwse_forget_all();
    fn kwse_screen_locked() -> i32;
    fn kwse_generate(policy: i32, buf: *mut u8, cap: usize) -> isize;
    fn kwse_kind(blob: *const u8, blob_len: usize) -> i32;
    fn kwse_check(blob: *const u8, blob_len: usize, reason: *const i8) -> i32;
    fn kwse_public(blob: *const u8, blob_len: usize, buf: *mut u8, cap: usize) -> isize;
    fn kwse_keychain_load(buf: *mut u8, cap: usize) -> isize;
    fn kwse_keychain_store(blob: *const u8, len: usize, force: i32) -> i32;
    fn kwse_sign(
        blob: *const u8,
        blob_len: usize,
        msg: *const u8,
        msg_len: usize,
        reason: *const i8,
        hold: i32,
        unlock_reuse_seconds: f64,
        scope: *const i8,
        approve: i32,
        riding: i32,
        buf: *mut u8,
        cap: usize,
    ) -> isize;
}

pub const KEY_TYPE: &str = "ecdsa-sha2-nistp256";
pub const CURVE: &str = "nistp256";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// No authentication — anything that can read the blob can sign.
    None,
    /// Touch ID or password, and survives a change to enrolled fingerprints.
    UserPresence,
    /// Touch ID only; the key self-destructs if the fingerprint set changes.
    BiometryCurrentSet,
    /// Touch ID once per sign-in, enforced by the enclave: the key signs for a secret
    /// that only a Touch ID releases, and the daemon holds that for as long as the
    /// sign-in lasts. A presence key cannot be held open past about ten minutes.
    SignIn,
}

impl Policy {
    pub fn parse(s: &str) -> Option<Policy> {
        match s {
            "none" => Some(Policy::None),
            "presence" => Some(Policy::UserPresence),
            "biometry" => Some(Policy::BiometryCurrentSet),
            "sign-in" => Some(Policy::SignIn),
            _ => None,
        }
    }
    fn code(self) -> i32 {
        match self {
            Policy::None => 0,
            Policy::UserPresence => 1,
            Policy::BiometryCurrentSet => 2,
            Policy::SignIn => 3,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Policy::None => "none",
            Policy::UserPresence => "presence",
            Policy::BiometryCurrentSet => "biometry",
            Policy::SignIn => "sign-in",
        }
    }
}

pub fn available() -> bool {
    unsafe { kwse_available() == 1 }
}

/// What the console says about this user's screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Unlocked,
    Locked,
    /// Another user is at the console, or nobody is.
    Away,
    /// The record could not be read.
    Unreadable,
}

impl Screen {
    /// Why a sign-in key signs nothing with the screen like this, as the log puts it.
    /// Only an unlocked screen has no reason: a sign-in must not outlive a lock
    /// nobody could see.
    pub fn refusal(self) -> Option<&'static str> {
        match self {
            Screen::Unlocked => None,
            Screen::Locked => Some("screen locked"),
            Screen::Away => Some("not at the console"),
            Screen::Unreadable => Some("screen state unreadable"),
        }
    }
}

pub fn screen() -> Screen {
    match unsafe { kwse_screen_locked() } {
        0 => Screen::Unlocked,
        1 => Screen::Locked,
        2 => Screen::Away,
        _ => Screen::Unreadable,
    }
}

/// Where the SEP-wrapped handle lives. `enclave_key: "keychain"` in the config keeps it
/// in the login keychain, readable without a prompt only by keywardd's own code signature;
/// a path keeps it in a file any process running as the user can read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStore {
    File(PathBuf),
    Keychain,
}

impl KeyStore {
    pub fn from_config(v: Option<&str>) -> KeyStore {
        match v {
            Some("keychain") => KeyStore::Keychain,
            Some(p) => KeyStore::File(PathBuf::from(p)),
            None => KeyStore::File(default_key_path()),
        }
    }
    pub fn describe(&self) -> String {
        match self {
            KeyStore::File(p) => p.display().to_string(),
            KeyStore::Keychain => "login keychain (dev.danielsol.keyward / enclave-key)".into(),
        }
    }
    fn read(&self) -> Option<Vec<u8>> {
        match self {
            KeyStore::File(p) => std::fs::read(p).ok(),
            KeyStore::Keychain => {
                let mut buf = vec![0u8; 4096];
                let n = unsafe { kwse_keychain_load(buf.as_mut_ptr(), buf.len()) };
                if n <= 0 {
                    return None;
                }
                buf.truncate(n as usize);
                Some(buf)
            }
        }
    }
    fn exists(&self) -> bool {
        match self {
            KeyStore::File(p) => p.exists(),
            KeyStore::Keychain => self.read().is_some(),
        }
    }
}

pub fn default_key_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join("Library/Application Support/Keyward/enclave-key.blob")
}

pub struct Enclave {
    blob: Vec<u8>,
    /// The 65-byte uncompressed EC point.
    point: Vec<u8>,
    pub comment: String,
    /// A sign-in key: its sign-in ends when the screen locks, and nothing is signed
    /// while it is locked. The older kinds keep whatever their own policy gives them.
    pub ends_at_lock: bool,
}

impl Enclave {
    pub fn load(store: &KeyStore, comment: String) -> Option<Enclave> {
        let blob = store.read()?;
        if blob.is_empty() {
            return None;
        }
        let mut point = vec![0u8; 256];
        let n = unsafe { kwse_public(blob.as_ptr(), blob.len(), point.as_mut_ptr(), point.len()) };
        if n <= 0 {
            eprintln!("keywardd: enclave key present but unreadable (code {n})");
            return None;
        }
        point.truncate(n as usize);
        let ends_at_lock = unsafe { kwse_kind(blob.as_ptr(), blob.len()) == 1 };
        Some(Enclave {
            blob,
            point,
            comment,
            ends_at_lock,
        })
    }

    /// SSH wire format: string(type), string(curve), string(point).
    pub fn ssh_public_blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(KEY_TYPE.as_bytes());
        w.string(CURVE.as_bytes());
        w.string(&self.point);
        w.buf
    }

    pub fn authorized_key_line(&self) -> String {
        use base64::Engine;
        format!(
            "{} {} {}",
            KEY_TYPE,
            base64::engine::general_purpose::STANDARD.encode(self.ssh_public_blob()),
            self.comment
        )
    }

    /// Sign `data`, showing `reason` in the authentication prompt.
    ///
    /// CryptoKit hashes with SHA-256 internally, which is what
    /// `ecdsa-sha2-nistp256` requires, and returns a raw r||s pair.
    /// Forget the held authentication for `scope`, so its next `sign` prompts. Other
    /// scopes keep theirs. Nothing here expires by itself: the daemon keeps the
    /// clock and calls this when an approval has run out.
    pub fn forget(&self, scope: &str) {
        let c_scope = CString::new(scope).unwrap_or_default();
        unsafe { kwse_forget(c_scope.as_ptr()) }
    }

    /// Forget every held authentication at once.
    pub fn forget_all(&self) {
        unsafe { kwse_forget_all() }
    }

    /// `scope` keys the held authentication: each scope holds its own, so an
    /// approval in one place neither covers nor evicts an approval in another.
    /// `hold` keeps the context this signature authenticates for the signatures
    /// that follow, until `forget`. `unlock_reuse_secs` lets a Touch ID unlock of
    /// the Mac that recent stand in for the prompt; 0 always asks.
    /// `approve` false skips the daemon's own Touch ID check; a key created with a
    /// presence policy still makes the enclave ask on its own.
    /// `riding` says a live approval covers this request. A sign-in key then signs
    /// with what is held or not at all: a sign-in that ended under the request must
    /// not turn it into a sheet that names one action and opens a sign-in.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        &self,
        data: &[u8],
        reason: &str,
        scope: &str,
        hold: bool,
        unlock_reuse_secs: f64,
        approve: bool,
        riding: bool,
    ) -> Result<Vec<u8>, String> {
        let c_reason = CString::new(reason).unwrap_or_else(|_| CString::new("").unwrap());
        let c_scope = CString::new(scope).unwrap_or_default();
        let mut sig = vec![0u8; 256];
        let n = unsafe {
            kwse_sign(
                self.blob.as_ptr(),
                self.blob.len(),
                data.as_ptr(),
                data.len(),
                c_reason.as_ptr(),
                hold as i32,
                unlock_reuse_secs,
                c_scope.as_ptr(),
                approve as i32,
                riding as i32,
                sig.as_mut_ptr(),
                sig.len(),
            )
        };
        match n {
            -3 => return Err("declined or authentication failed".into()),
            -4 => return Err("signed out while signing".into()),
            n if n <= 0 => return Err(format!("enclave signing failed (code {n})")),
            _ => {}
        }
        sig.truncate(n as usize);
        if sig.len() != 64 {
            return Err(format!("unexpected signature length {}", sig.len()));
        }
        Ok(ssh_ecdsa_signature(&sig[..32], &sig[32..]))
    }
}

/// SSH encodes ECDSA signatures as string(type) + string(mpint r || mpint s).
fn ssh_ecdsa_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut inner = Writer::new();
    inner.string(&mpint(r));
    inner.string(&mpint(s));

    let mut out = Writer::new();
    out.string(KEY_TYPE.as_bytes());
    out.string(&inner.buf);
    out.buf
}

/// Two's-complement big integer: strip leading zeros, then re-add one if the
/// top bit is set so the value is never read as negative.
fn mpint(v: &[u8]) -> Vec<u8> {
    let first = v.iter().position(|b| *b != 0).unwrap_or(v.len());
    let trimmed = &v[first..];
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        out.push(0);
    }
    out.extend_from_slice(trimmed);
    out
}

/// Create a key. Refuses to clobber an existing one: an enclave key cannot be
/// exported or backed up, so overwriting it destroys it beyond recovery.
pub fn generate(store: &KeyStore, policy: Policy, force: bool) -> Result<(), String> {
    if !available() {
        return Err("no Secure Enclave on this machine".into());
    }
    if store.exists() && !force {
        return Err(format!(
            "{} already holds a key. Overwriting destroys the existing key permanently \
             — it cannot be exported or restored. Pass --force only if you have \
             already rotated away from it.",
            store.describe()
        ));
    }
    let mut blob = vec![0u8; 4096];
    let n = unsafe { kwse_generate(policy.code(), blob.as_mut_ptr(), blob.len()) };
    if n <= 0 {
        return Err(format!("enclave key generation failed (code {n})"));
    }
    blob.truncate(n as usize);
    if policy == Policy::SignIn {
        // The key is about to be authorised on servers and can never be remade, so it
        // signs in once, here, before it is kept.
        eprintln!("keywardd: one Touch ID, to try the new key before it is kept");
        let reason = CString::new("try the new sign-in key").unwrap_or_default();
        match unsafe { kwse_check(blob.as_ptr(), blob.len(), reason.as_ptr()) } {
            0 => {}
            -2 => return Err("the new key does not open for its own Touch ID; nothing was kept".into()),
            _ => return Err("the Touch ID was declined or failed; nothing was kept".into()),
        }
    }
    match store {
        KeyStore::File(path) => {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            }
            std::fs::write(path, &blob).map_err(|e| e.to_string())?;
            std::fs::set_permissions(
                path,
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
            )
            .map_err(|e| e.to_string())?;
        }
        KeyStore::Keychain => {
            let rc = unsafe { kwse_keychain_store(blob.as_ptr(), blob.len(), if force { 1 } else { 0 }) };
            if rc != 0 {
                return Err(format!("keychain store failed (code {rc})"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::kwse_kind;

    fn kind(blob: &[u8]) -> i32 {
        unsafe { kwse_kind(blob.as_ptr(), blob.len()) }
    }

    fn container(fields: &[&[u8]]) -> Vec<u8> {
        let mut out = b"keyward sign-in key 1\n".to_vec();
        for f in fields {
            out.extend_from_slice(&(f.len() as u32).to_be_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    /// A sign-in key is told from a plain enclave handle by its container alone, and
    /// that decides whether the screen is watched at all. Anything short of a whole
    /// container is not one.
    #[test]
    fn a_sign_in_key_is_known_by_its_container() {
        let whole = container(&[b"signing", b"unlock", b"peer", b"public"]);
        assert_eq!(kind(&whole), 1);
        assert_eq!(kind(&whole[..whole.len() - 1]), 0, "cut short");
        assert_eq!(kind(&container(&[b"signing", b"unlock", b"peer"])), 0, "a field missing");
        assert_eq!(kind(&container(&[b"a", b"b", b"c", b"d", b"e"])), 0, "a field too many");
        let mut trailing = whole.clone();
        trailing.push(0);
        assert_eq!(kind(&trailing), 0, "something after the last field");
        assert_eq!(kind(&[0x30; 324]), 0, "a plain enclave handle");
        assert_eq!(kind(b""), 0);
    }

    /// Making a sign-in key asks nobody for anything, and the refusals it tries on
    /// the new key before handing it back all raise no prompt. The enclave makes
    /// nothing while the screen is locked, so this only runs unlocked.
    #[test]
    fn a_new_sign_in_key_is_made_and_tried() {
        if !super::available() || super::screen() != super::Screen::Unlocked {
            eprintln!("skipped: needs a Secure Enclave and an unlocked screen");
            return;
        }
        let mut blob = vec![0u8; 4096];
        let n = unsafe { super::kwse_generate(super::Policy::SignIn.code(), blob.as_mut_ptr(), blob.len()) };
        assert!(n > 0, "generation failed (code {n})");
        blob.truncate(n as usize);
        assert_eq!(kind(&blob), 1);

        // Its public half is read without the secret, or the Touch ID that releases it.
        let mut point = vec![0u8; 256];
        let n = unsafe { super::kwse_public(blob.as_ptr(), blob.len(), point.as_mut_ptr(), point.len()) };
        assert_eq!((n, point[0]), (65, 4), "an uncompressed P-256 point");
    }
}
