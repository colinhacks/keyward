//! The proxy itself.

use crate::attrib::{self, Attribution};
use crate::enclave::Enclave;
use crate::purpose::Kind as PurposeKind;
use crate::event::{Event, Kind, Log};
use crate::upstream::Upstream;
use crate::wire::{self, Reader, Writer};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

pub const FAILURE: u8 = 5;
pub const REQUEST_IDENTITIES: u8 = 11;
pub const IDENTITIES_ANSWER: u8 = 12;
pub const SIGN_REQUEST: u8 = 13;
pub const SIGN_RESPONSE: u8 = 14;
pub const EXTENSION: u8 = 27;

const MAX_MSG: u32 = 1 << 20;
const MAX_CONNS: usize = 512;

pub struct Ctx {
    /// The key Keyward holds in the Secure Enclave itself, if one exists.
    pub enclave: Option<Enclave>,
    pub upstreams: Vec<Upstream>,
    /// key blob -> index into `upstreams`
    pub routes: RwLock<HashMap<Vec<u8>, usize>>,
    pub comments: RwLock<HashMap<Vec<u8>, String>>,
    pub log: Log,
    pub timeout: Duration,
    pub conns: AtomicUsize,
    /// Identity listings carry no signature and happen several times per ssh
    /// connection, so they are noise by default. Signatures are the record.
    pub log_lists: bool,
    /// Seconds during which one Touch ID authentication covers further
    /// signatures. 0 asks every time.
    pub touch_id_reuse_secs: f64,
    /// Overrides the system sheet's text. Empty means "describe the action";
    /// a single space means "say as little as macOS allows".
    pub sheet_reason: String,
    /// Where the last approval was granted, and when. The reuse window only
    /// covers further requests from the same place.
    pub last_approved: Mutex<Option<(Scope, Instant)>>,
    /// Every connection runs on its own thread, and two Touch ID prompts at once
    /// cancel each other ("Canceled by another authentication"), so signatures
    /// take turns: the second request waits for the first prompt to finish, and
    /// if the first approval covers its scope it then signs without a prompt.
    pub sign_gate: Mutex<()>,
}

/// The blast radius of one Touch ID approval.
///
/// An unscoped reuse window means approving a push also silently covers an
/// unrelated repository, or a login to another host, for the rest of the
/// window — the one authorisation a human gave is not the one they are asked
/// about. Scoping keeps the convenience it exists for (a fetch right after a
/// push in the same checkout rides the same approval, which is why the purpose
/// kind is deliberately *not* part of the scope) and drops the rest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    /// The repository the work is in, else the caller's working directory.
    pub directory: Option<String>,
    /// SSH destination.
    pub host: Option<String>,
    /// The remote being pushed to or fetched from.
    pub repo: Option<String>,
}

fn scope_of(who: &Attribution) -> Scope {
    let git = who.context.git.as_ref();
    Scope {
        directory: who
            .purpose
            .repo_path
            .clone()
            .or_else(|| who.process.as_ref().and_then(|p| p.cwd.clone())),
        host: who.purpose.host.clone(),
        repo: git.and_then(|g| g.push_remote_url.clone().or_else(|| g.remote.clone())),
    }
}

/// A poisoned lock must never take SSH down; the worst it costs is one more prompt.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Does an earlier approval still cover this request?
///
/// Kept pure so the window arithmetic is testable without an enclave.
fn reuse_covers(last: Option<&(Scope, Instant)>, scope: &Scope, window: f64, now: Instant) -> bool {
    if window <= 0.0 {
        return false;
    }
    match last {
        Some((s, at)) => s == scope && now.saturating_duration_since(*at).as_secs_f64() < window,
        None => false,
    }
}

pub fn fingerprint(blob: &[u8]) -> String {
    let digest = Sha256::digest(blob);
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    )
}

fn failure() -> Vec<u8> {
    vec![FAILURE]
}

/// The line shown in the Touch ID prompt.
///
/// macOS draws this in a ~260pt-wide panel, so it has to survive being read at
/// a glance: no shell fragments, no quotes, no backticks, and short enough not
/// to wrap into a paragraph. The full command, commit message and process
/// chain are in the app — the prompt only has to answer "consent to what?".
const PROMPT_MAX: usize = 56;

fn prompt_action(who: &Attribution) -> String {
    let p = &who.purpose;
    let host = p.host.clone().unwrap_or_else(|| "unknown host".into());

    let action = match p.kind {
        PurposeKind::CommitSigning => match &p.repo {
            // The commit subject is the interesting part but also the long
            // part; it stays in the app rather than the dialog.
            Some(repo) => format!("Sign a commit in {repo}"),
            None => "Sign a git commit".to_string(),
        },
        PurposeKind::GitPush => match &p.remote_repo {
            Some(r) => format!("git push to {}", short_repo(r)),
            None => format!("git push to {host}"),
        },
        PurposeKind::GitFetch => match &p.remote_repo {
            Some(r) => format!("git fetch from {}", short_repo(r)),
            None => format!("git fetch from {host}"),
        },
        PurposeKind::GitOverSsh => format!("git on {host}"),
        PurposeKind::SshLogin => format!("SSH to {host}"),
        // Deliberately omits the command itself: it is arbitrary shell text and
        // was the single worst thing to read in a narrow dialog.
        PurposeKind::RemoteCommand => format!("Run a command on {host}"),
        PurposeKind::FileTransfer => format!("Copy files with {host}"),
        PurposeKind::Signing => match &p.namespace {
            Some(ns) => format!("Sign data ({ns})"),
            None => "Sign data".to_string(),
        },
        PurposeKind::Unknown => "Authorise a signature".to_string(),
    };

    crate::purpose::shorten(&sanitise(&action), PROMPT_MAX)
}

/// What the system sheet says. The card behind it already carries the headline,
/// the app, the command and the key, so repeating any of it here just makes the
/// small panel wordier than the big one.
fn sheet_reason(who: &Attribution, configured: &str) -> String {
    if !configured.is_empty() {
        return crate::purpose::shorten(&sanitise(configured), PROMPT_MAX);
    }
    let action = prompt_action(who);
    match who.app.as_ref().map(|a| sanitise(&a.name)) {
        Some(app) if action.chars().count() + app.chars().count() + 3 <= PROMPT_MAX => {
            format!("{action} · {app}")
        }
        _ => action,
    }
}

/// owner/repo.git -> owner/repo, and just repo when that is still long.
fn short_repo(r: &str) -> String {
    let r = r.trim_end_matches(".git");
    if r.chars().count() <= 28 {
        return r.to_string();
    }
    r.rsplit('/').next().unwrap_or(r).to_string()
}

/// Strip anything that turns the dialog into noise.
fn sanitise(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '`' | '"' | '\'' | '\n' | '\r' | '\t' => ' ',
            c => c,
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn refresh_identities(ctx: &Ctx) -> Vec<(Vec<u8>, String)> {
    let mut merged: Vec<(Vec<u8>, String)> = Vec::new();
    let mut routes = HashMap::new();
    let mut comments = HashMap::new();

    for (idx, up) in ctx.upstreams.iter().enumerate() {
        match up.identities(ctx.timeout) {
            Ok(ids) => {
                for (blob, comment) in ids {
                    if routes.contains_key(&blob) {
                        continue; // first upstream to claim a key wins
                    }
                    routes.insert(blob.clone(), idx);
                    comments.insert(blob.clone(), comment.clone());
                    merged.push((blob, comment));
                }
            }
            Err(e) => {
                eprintln!("keywardd: upstream {} identities failed: {e}", up.name);
            }
        }
    }

    if let Ok(mut w) = ctx.routes.write() {
        *w = routes;
    }
    if let Ok(mut w) = ctx.comments.write() {
        *w = comments;
    }
    merged
}

fn handle_request_identities(ctx: &Ctx, who: &Attribution) -> Vec<u8> {
    let started = Instant::now();
    let mut ids = refresh_identities(ctx);

    // Our own enclave key is offered first, so ssh tries it before falling
    // back to whatever the upstream agents hold.
    if let Some(e) = &ctx.enclave {
        ids.insert(0, (e.ssh_public_blob(), e.comment.clone()));
    }

    let mut w = Writer::new();
    w.u8(IDENTITIES_ANSWER);
    w.u32(ids.len() as u32);
    for (blob, comment) in &ids {
        w.string(blob);
        w.string(comment.as_bytes());
    }

    let is_self_probe = who.process.as_ref().and_then(|p| p.name.as_deref()) == Some("keywardd");
    if ctx.log_lists && !is_self_probe {
        ctx.log.append(&Event {
        ts: crate::event::now(),
        kind: Kind::ListIdentities,
        who: who.clone(),
        key_fp: None,
        key_comment: None,
        upstream: None,
        bound_host_fp: None,
        scope: None,
        reused: false,
        outcome: format!("{} keys", ids.len()),
        duration_ms: started.elapsed().as_millis() as u64,
        });
    }

    w.buf
}

fn handle_sign(ctx: &Ctx, payload: &[u8], who: &Attribution, bound: &Option<String>) -> Vec<u8> {
    let started = Instant::now();

    let mut r = Reader::new(payload);
    let _ = r.u8();
    let blob = match r.string() {
        Some(b) => b.to_vec(),
        None => return failure(),
    };

    // Is this our own key? Then we sign it here, and we get to write the
    // prompt the user actually sees.
    if let Some(e) = &ctx.enclave {
        if e.ssh_public_blob() == blob {
            let mut r2 = Reader::new(payload);
            let _ = r2.u8();
            let _ = r2.string();
            let data = r2.string().unwrap_or(&[]).to_vec();

            let headline = prompt_action(who);
            let reason = sheet_reason(who, &ctx.sheet_reason);
            let fp = fingerprint(&blob);

            // Outside the scope of the last approval we pass 0, which makes the
            // enclave build a fresh LAContext *and* drop the cached one — so the
            // next in-scope request cannot inherit an authentication the user
            // granted somewhere else.
            let _turn = lock(&ctx.sign_gate);
            let scope = scope_of(who);
            let reused = {
                let last = lock(&ctx.last_approved);
                reuse_covers(last.as_ref(), &scope, ctx.touch_id_reuse_secs, Instant::now())
            };
            let window = if reused { ctx.touch_id_reuse_secs } else { 0.0 };

            let card = crate::ui::show(who, &headline, Some(&e.comment), Some(&fp));
            let signed = e.sign(&data, &reason, window);
            card.done();
            let (reply, outcome) = match signed {
                Ok(sig) => {
                    *lock(&ctx.last_approved) = Some((scope.clone(), Instant::now()));
                    let mut w = Writer::new();
                    w.u8(SIGN_RESPONSE);
                    w.string(&sig);
                    (w.buf, "ok".to_string())
                }
                Err(err) => (failure(), err),
            };

            ctx.log.append(&Event {
                ts: crate::event::now(),
                kind: Kind::Sign,
                who: who.clone(),
                key_fp: Some(fp),
                key_comment: Some(e.comment.clone()),
                upstream: Some("Secure Enclave".to_string()),
                bound_host_fp: bound.clone(),
                scope: Some(scope),
                reused,
                outcome,
                duration_ms: started.elapsed().as_millis() as u64,
            });
            return reply;
        }
    }

    let mut idx = ctx.routes.read().ok().and_then(|m| m.get(&blob).copied());
    if idx.is_none() {
        refresh_identities(ctx);
        idx = ctx.routes.read().ok().and_then(|m| m.get(&blob).copied());
    }
    let comment = ctx
        .comments
        .read()
        .ok()
        .and_then(|m| m.get(&blob).cloned())
        .filter(|c| !c.is_empty());

    let (reply, upstream_name, outcome) = match idx.and_then(|i| ctx.upstreams.get(i)) {
        Some(up) => match up.request(payload, ctx.timeout) {
            Ok(resp) => {
                let ok = resp.first().copied() != Some(FAILURE);
                (
                    resp,
                    Some(up.name.clone()),
                    if ok { "ok" } else { "denied" }.to_string(),
                )
            }
            Err(e) => {
                let kind = if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut
                {
                    "timeout".to_string()
                } else {
                    format!("error: {e}")
                };
                (failure(), Some(up.name.clone()), kind)
            }
        },
        None => (failure(), None, "no upstream holds this key".to_string()),
    };

    ctx.log.append(&Event {
        ts: crate::event::now(),
        kind: Kind::Sign,
        who: who.clone(),
        key_fp: Some(fingerprint(&blob)),
        key_comment: comment,
        upstream: upstream_name,
        bound_host_fp: bound.clone(),
        // An upstream agent owns its own authentication; the reuse scope is ours alone.
        scope: None,
        reused: false,
        outcome,
        duration_ms: started.elapsed().as_millis() as u64,
    });

    reply
}

/// `session-bind@openssh.com` carries the host key of the server ssh is talking
/// to. Neither Secretive nor gpg-agent implements it, so forwarding it only
/// produces upstream errors — we answer it here (a plain FAILURE, exactly what
/// a non-supporting agent returns and what ssh already tolerates) and keep the
/// host key as provenance for the signatures that follow on this connection.
fn handle_extension(
    ctx: &Ctx,
    payload: &[u8],
    who: &Attribution,
    bound: &mut Option<String>,
) -> Vec<u8> {
    let mut r = Reader::new(payload);
    let _ = r.u8();
    let name = r
        .string()
        .map(|n| String::from_utf8_lossy(n).into_owned())
        .unwrap_or_default();

    if name == "session-bind@openssh.com" {
        if let Some(hostkey) = r.string() {
            let fp = fingerprint(hostkey);
            if bound.as_deref() != Some(fp.as_str()) {
                *bound = Some(fp.clone());
                if ctx.log_lists {
                    ctx.log.append(&Event {
                    ts: crate::event::now(),
                    kind: Kind::SessionBind,
                    who: who.clone(),
                    key_fp: None,
                    key_comment: None,
                    upstream: None,
                    bound_host_fp: Some(fp),
                    scope: None,
                    reused: false,
                    outcome: "recorded".to_string(),
                    duration_ms: 0,
                    });
                }
            }
        }
    }
    failure()
}

fn serve(mut stream: UnixStream, ctx: Arc<Ctx>) -> io::Result<()> {
    let who = attrib::attribute(stream.as_raw_fd());
    // A client that opens the socket and then goes quiet must not hold a thread
    // forever; ssh keeps its agent connection only for the length of a session.
    stream.set_read_timeout(Some(Duration::from_secs(3600)))?;
    let mut bound: Option<String> = None;

    loop {
        let mut len = [0u8; 4];
        match stream.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let n = u32::from_be_bytes(len);
        if n == 0 || n > MAX_MSG {
            return Ok(());
        }
        let mut payload = vec![0u8; n as usize];
        stream.read_exact(&mut payload)?;

        let reply = match payload[0] {
            REQUEST_IDENTITIES => handle_request_identities(&ctx, &who),
            SIGN_REQUEST => handle_sign(&ctx, &payload, &who, &bound),
            EXTENSION => handle_extension(&ctx, &payload, &who, &mut bound),
            _ => failure(),
        };

        stream.write_all(&wire::frame(&reply))?;
        stream.flush()?;
    }
}

#[cfg(test)]
mod tests {
    use super::{reuse_covers, Scope};
    use std::time::{Duration, Instant};

    fn scope(dir: &str, host: &str, repo: &str) -> Scope {
        Scope {
            directory: Some(dir.into()),
            host: Some(host.into()),
            repo: Some(repo.into()),
        }
    }

    #[test]
    fn a_fresh_approval_covers_the_same_place() {
        let s = scope("/src/keyward", "github.com", "git@github.com:me/keyward.git");
        let now = Instant::now();
        let last = (s.clone(), now - Duration::from_secs(30));
        assert!(reuse_covers(Some(&last), &s, 300.0, now));
    }

    #[test]
    fn another_directory_host_or_remote_does_not_inherit_it() {
        let approved = scope("/src/keyward", "github.com", "git@github.com:me/keyward.git");
        let now = Instant::now();
        let last = (approved.clone(), now);
        for other in [
            scope("/src/other", "github.com", "git@github.com:me/keyward.git"),
            scope("/src/keyward", "gitlab.com", "git@github.com:me/keyward.git"),
            scope("/src/keyward", "github.com", "git@github.com:me/secrets.git"),
        ] {
            assert!(
                !reuse_covers(Some(&last), &other, 300.0, now),
                "{other:?} must not ride an approval granted for {approved:?}"
            );
        }
    }

    #[test]
    fn the_window_expires_and_zero_disables_it() {
        let s = scope("/src/keyward", "github.com", "git@github.com:me/keyward.git");
        let now = Instant::now();
        let stale = (s.clone(), now - Duration::from_secs(301));
        assert!(!reuse_covers(Some(&stale), &s, 300.0, now), "past the window");
        let fresh = (s.clone(), now);
        assert!(!reuse_covers(Some(&fresh), &s, 0.0, now), "0 asks every time");
        assert!(!reuse_covers(None, &s, 300.0, now), "nothing approved yet");
    }

    /// A push and the fetch that follows it in the same checkout are one approval:
    /// the purpose kind is deliberately outside the scope.
    #[test]
    fn a_different_purpose_in_the_same_place_still_rides_it() {
        let push = scope("/src/keyward", "github.com", "git@github.com:me/keyward.git");
        let fetch = push.clone();
        let now = Instant::now();
        let last = (push, now - Duration::from_secs(5));
        assert!(reuse_covers(Some(&last), &fetch, 300.0, now));
    }
}

pub fn spawn(stream: UnixStream, ctx: Arc<Ctx>) {
    if ctx.conns.load(Ordering::Relaxed) >= MAX_CONNS {
        eprintln!("keywardd: refusing connection, {MAX_CONNS} already open");
        return;
    }
    ctx.conns.fetch_add(1, Ordering::Relaxed);
    std::thread::spawn(move || {
        if let Err(e) = serve(stream, Arc::clone(&ctx)) {
            if e.kind() != io::ErrorKind::UnexpectedEof {
                eprintln!("keywardd: connection ended: {e}");
            }
        }
        ctx.conns.fetch_sub(1, Ordering::Relaxed);
    });
}
