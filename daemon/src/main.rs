mod agent;
mod attrib;
mod context;
mod enclave;
mod event;
mod purpose;
mod ui;
mod upstream;
mod wire;

use agent::Ctx;
use event::Log;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use upstream::Upstream;

#[derive(Debug, Serialize, Deserialize)]
struct UpstreamCfg {
    name: String,
    path: String,
}

/// Every field is optional: one the file leaves out takes its default, so a config
/// can be as short as `{"sign_in_secs": 0}`. A missing `listen` used to fail the
/// whole file, and the daemon then ran on defaults with the one setting ignored.
#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
struct Config {
    listen: String,
    log: String,
    upstreams: Vec<UpstreamCfg>,
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
    #[serde(default = "default_max_log")]
    max_log_bytes: u64,
    /// Where the SEP-wrapped handle for our own key lives.
    #[serde(default)]
    log_list_identities: bool,
    /// How long one sign-in lasts: a single Touch ID that covers every signature from
    /// every repository and host. 0 = no sign-in, and `touch_id_reuse_secs` decides.
    #[serde(default = "default_sign_in")]
    sign_in_secs: f64,
    /// Without a sign-in: how long one approval covers the place it was given in.
    /// 0 = authenticate every signature.
    #[serde(default)]
    touch_id_reuse_secs: f64,
    /// false = sign with our own key without asking. Pair it with a key generated with
    /// `--policy none`, which is also the kind that keeps signing while the screen is locked.
    #[serde(default = "default_true")]
    require_approval: bool,
    #[serde(default)]
    sheet_reason: String,
    #[serde(default)]
    enclave_key: Option<String>,
    #[serde(default = "default_enclave_comment")]
    enclave_comment: String,
}

fn default_enclave_comment() -> String {
    let host = std::process::Command::new("scutil")
        .arg("--get")
        .arg("LocalHostName")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "mac".into());
    format!("{host}@keyward")
}

fn default_timeout() -> u64 {
    10
}
fn default_true() -> bool {
    true
}
/// Six hours.
fn default_sign_in() -> f64 {
    21600.0
}
fn default_max_log() -> u64 {
    32 * 1024 * 1024
}

fn home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/tmp".into())
}

impl Default for Config {
    fn default() -> Self {
        let h = home();
        Config {
            listen: format!("{h}/.ssh/keyward.sock"),
            log: format!("{h}/Library/Application Support/Keyward/events.jsonl"),
            upstreams: vec![
                UpstreamCfg {
                    name: "Secretive".into(),
                    path: format!(
                        "{h}/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh"
                    ),
                },
                UpstreamCfg {
                    name: "gpg-agent".into(),
                    path: format!("{h}/.gnupg/S.gpg-agent.ssh"),
                },
            ],
            timeout_secs: default_timeout(),
            max_log_bytes: default_max_log(),
            log_list_identities: false,
            sign_in_secs: default_sign_in(),
            touch_id_reuse_secs: 0.0,
            require_approval: true,
            sheet_reason: String::new(),
            enclave_key: None,
            enclave_comment: default_enclave_comment(),
        }
    }
}

/// Expand a leading `~/` the way a shell would. The README writes every path with `~`, and launchd
/// starts the daemon with cwd `/`, so an unexpanded `~` bound a socket under a literal directory
/// named `~` when run from a shell and failed with ENOENT under launchd.
fn expand_home(p: &str) -> String {
    match p.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", home()),
        None if p == "~" => home(),
        None => p.to_string(),
    }
}

fn load_config(path: Option<&str>) -> Config {
    let p = path
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("{}/.config/keyward/config.json", home())));
    let mut cfg = match std::fs::read_to_string(&p) {
        Ok(s) => match serde_json::from_str::<Config>(&s) {
            Ok(c) => c,
            // A file that cannot be read may have been asking for something stricter
            // than the defaults, so it does not get the sign-in: every
            // signature asks until it is fixed.
            Err(e) => {
                eprintln!(
                    "keywardd: bad config {}: {e} — using defaults, without a sign-in",
                    p.display()
                );
                Config {
                    sign_in_secs: 0.0,
                    ..Config::default()
                }
            }
        },
        Err(_) => Config::default(),
    };
    cfg.listen = expand_home(&cfg.listen);
    cfg.log = expand_home(&cfg.log);
    for u in &mut cfg.upstreams {
        u.path = expand_home(&u.path);
    }
    if let Some(k) = cfg.enclave_key.as_mut() {
        *k = expand_home(k);
    }
    cfg
}

/// Bind the listen socket, clearing a stale one but never stealing a live one.
///
/// ssh-agent-mux crash-looped forever on "Address already in use" because it
/// treated any existing socket file as fatal. A socket file that nothing is
/// listening on is just debris; one with a live listener means we should stand
/// down.
fn bind(path: &str) -> std::io::Result<UnixListener> {
    if std::path::Path::new(path).exists() {
        match UnixStream::connect(path) {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "another keywardd is already listening here",
                ));
            }
            Err(_) => {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let l = UnixListener::bind(path)?;
    let _ = std::fs::set_permissions(
        path,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    );
    Ok(l)
}

/// Ask a socket for its identity list and return how many keys it offered. It catches
/// the failure launchd cannot see — a process that is alive and accepting connections
/// but no longer answering them.
fn probe(path: &str, timeout: Duration) -> Result<u32, String> {
    let mut s = UnixStream::connect(path).map_err(|e| format!("cannot connect to {path}: {e}"))?;
    if s.set_read_timeout(Some(timeout)).is_err() || s.set_write_timeout(Some(timeout)).is_err() {
        return Err("cannot set a timeout on the socket".into());
    }
    if s.write_all(&wire::frame(&[agent::REQUEST_IDENTITIES])).is_err() {
        return Err("write failed".into());
    }
    let mut len = [0u8; 4];
    s.read_exact(&mut len)
        .map_err(|e| format!("no answer within {timeout:?}: {e}"))?;
    let n = u32::from_be_bytes(len);
    let mut body = vec![0u8; n as usize];
    if s.read_exact(&mut body).is_err() {
        return Err("truncated answer".into());
    }
    let mut r = wire::Reader::new(&body);
    match (r.u8(), r.u32()) {
        (Some(agent::IDENTITIES_ANSWER), Some(count)) => Ok(count),
        _ => Err("unexpected reply".into()),
    }
}

/// `--health`: probe the socket and say what came back, non-zero if nothing did.
fn health(path: &str, timeout: Duration) -> i32 {
    match probe(path, timeout) {
        Ok(count) => {
            println!("healthy: {count} keys");
            0
        }
        Err(e) => {
            eprintln!("unhealthy: {e}");
            1
        }
    }
}

const SELF_CHECK_EVERY: Duration = Duration::from_secs(120);

/// The watchdog, in-process. The daemon asks its own socket what `--health` asks, and
/// exits when nothing comes back, so launchd's KeepAlive starts a fresh one. This was a
/// second LaunchAgent running `--health` on a timer; a thread costs no extra login item.
fn watch_self(path: String, timeout: Duration) {
    std::thread::spawn(move || loop {
        std::thread::sleep(SELF_CHECK_EVERY);
        if let Err(e) = probe(&path, timeout) {
            eprintln!("keywardd: not answering its own socket ({e}) — exiting so launchd restarts it");
            std::process::exit(1);
        }
    });
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg_path: Option<String> = None;
    let mut want_health = false;
    let mut want_generate = false;
    let mut want_pubkey = false;
    let mut force = false;
    let mut policy = enclave::Policy::UserPresence;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                cfg_path = args.get(i + 1).cloned();
                i += 1;
            }
            "--health" => want_health = true,
            "--generate-key" => want_generate = true,
            "--pubkey" => want_pubkey = true,
            "--force" => force = true,
            "--policy" => {
                let v = args.get(i + 1).cloned().unwrap_or_default();
                match enclave::Policy::parse(&v) {
                    Some(p) => policy = p,
                    None => {
                        eprintln!("keywardd: --policy must be none, presence, biometry or sign-in");
                        std::process::exit(2);
                    }
                }
                i += 1;
            }
            "--help" | "-h" => {
                println!(
                    "keywardd [--config PATH]\n                       --health                    probe the socket, non-zero if unanswered\n                       --generate-key              create a Secure Enclave key (once)\n                       --policy none|presence|biometry|sign-in   what a signature costs\n                       --pubkey                    print the authorized_keys line\n                       --force                     allow overwriting an existing key"
                );
                return;
            }
            other => eprintln!("keywardd: ignoring unknown argument {other}"),
        }
        i += 1;
    }

    let cfg = load_config(cfg_path.as_deref());
    let timeout = Duration::from_secs(cfg.timeout_secs);

    let key_store = enclave::KeyStore::from_config(cfg.enclave_key.as_deref());

    if want_generate {
        match enclave::generate(&key_store, policy, force) {
            Ok(()) => {
                println!("created a Secure Enclave key ({} policy)", policy.label());
                println!("  handle: {}", key_store.describe());
                println!("\nIt cannot be exported or backed up. Authorise it before you rely on it:");
                if let Some(e) = enclave::Enclave::load(&key_store, cfg.enclave_comment.clone()) {
                    println!("\n{}\n", e.authorized_key_line());
                }
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("keywardd: {e}");
                std::process::exit(1);
            }
        }
    }

    let enclave = enclave::Enclave::load(&key_store, cfg.enclave_comment.clone());

    if want_pubkey {
        match &enclave {
            Some(e) => println!("{}", e.authorized_key_line()),
            None => {
                eprintln!("keywardd: no enclave key yet — run keywardd --generate-key");
                std::process::exit(1);
            }
        }
        std::process::exit(0);
    }

    if want_health {
        std::process::exit(health(&cfg.listen, timeout));
    }

    let listener = match bind(&cfg.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("keywardd: cannot listen on {}: {e}", cfg.listen);
            std::process::exit(1);
        }
    };

    let ctx = Arc::new(Ctx {
        enclave,
        upstreams: cfg
            .upstreams
            .iter()
            .map(|u| Upstream {
                name: u.name.clone(),
                path: u.path.clone(),
            })
            .collect(),
        routes: RwLock::new(HashMap::new()),
        comments: RwLock::new(HashMap::new()),
        log: Log::new(PathBuf::from(&cfg.log), cfg.max_log_bytes),
        timeout,
        conns: AtomicUsize::new(0),
        log_lists: cfg.log_list_identities,
        sign_in_secs: cfg.sign_in_secs,
        touch_id_reuse_secs: cfg.touch_id_reuse_secs,
        require_approval: cfg.require_approval,
        sheet_reason: cfg.sheet_reason.clone(),
        approved: Mutex::new(HashMap::new()),
        sign_outs: AtomicU64::new(0),
        looked: Mutex::new(agent::Look::first()),
        sign_gate: Mutex::new(()),
    });

    eprintln!(
        "keywardd: listening on {} with {} upstream(s){}",
        cfg.listen,
        ctx.upstreams.len(),
        if ctx.enclave.is_some() {
            " + its own Secure Enclave key"
        } else {
            ""
        }
    );

    watch_self(cfg.listen.clone(), timeout);
    if ctx.enclave.as_ref().is_some_and(|e| e.ends_at_lock) {
        agent::watch_screen(Arc::clone(&ctx));
    }

    for stream in listener.incoming() {
        match stream {
            Ok(s) => agent::spawn(s, Arc::clone(&ctx)),
            Err(e) => eprintln!("keywardd: accept failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    /// Turning the sign-in off is one line, and that line has to be allowed to be
    /// the whole file: when a missing `listen` failed the parse, the daemon fell
    /// back to its defaults and the sign-in the file had just declined.
    #[test]
    fn a_config_may_set_one_thing_and_leave_the_rest() {
        let cfg: Config = serde_json::from_str(r#"{"sign_in_secs": 0}"#).unwrap();
        assert_eq!(cfg.sign_in_secs, 0.0);
        assert!(cfg.listen.ends_with("/.ssh/keyward.sock"));
        assert!(cfg.require_approval);

        let cfg: Config = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.sign_in_secs, 21600.0, "six hours, unless the file says otherwise");
    }
}
