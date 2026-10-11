//! The proxy itself.

use crate::attrib::{self, Attribution};
use crate::enclave::{Enclave, Screen};
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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, TryLockError};
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
    /// Seconds one sign-in lasts. While it is live every request for our own key is
    /// signed without asking, whatever repository or host it comes from. 0 turns the
    /// sign-in off, and each place is approved on its own for `touch_id_reuse_secs`.
    pub sign_in_secs: f64,
    /// Without a sign-in: seconds during which one Touch ID authentication covers
    /// further signatures from the same place. 0 asks every time.
    pub touch_id_reuse_secs: f64,
    /// False signs with our own key without a Touch ID check or an approval card. The
    /// key still cannot leave the enclave; every signature is still logged.
    pub require_approval: bool,
    /// Overrides the system sheet's text. Empty means "describe the action";
    /// a single space means "say as little as macOS allows".
    pub sheet_reason: String,
    /// What each live approval covers, and when it was granted on `clock`. A
    /// sign-in is one entry covering everything. Without one, a window only covers
    /// further requests from the same place, and every place keeps its own: two
    /// agents in two repositories must not evict each other's approval.
    pub approved: Mutex<HashMap<Reach, f64>>,
    /// Counts sign-outs. A signature takes as long as the Touch ID it waits for, and
    /// a sign-out that lands meanwhile must leave nothing of that request behind.
    /// Changed and compared only with `approved` locked.
    pub sign_outs: AtomicU64,
    /// The last look at the screen, by the watch or by a request. Only a sign-in
    /// key looks.
    pub looked: Mutex<Look>,
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Scope {
    /// Where the request came from, kept only when no remote is known: the
    /// repository's main checkout (so a linked worktree shares its clone's
    /// approval) else the caller's working directory. When the remote IS known
    /// it is left out: an approval covers "this host, this repo", not the
    /// checkout it happened in — a test suite that clones a fresh fixture per
    /// push to the same repository used to prompt on every one.
    pub directory: Option<String>,
    /// SSH destination.
    pub host: Option<String>,
    /// The remote being pushed to or fetched from.
    pub repo: Option<String>,
}

fn scope_of(who: &Attribution) -> Scope {
    let git = who.context.git.as_ref();
    let repo = git.and_then(|g| g.push_remote_url.clone().or_else(|| g.remote.clone()));
    let directory = if repo.is_some() {
        None
    } else {
        who.purpose
            .repo_path
            .as_deref()
            .map(|r| crate::context::main_checkout(r).unwrap_or_else(|| r.to_string()))
            .or_else(|| who.process.as_ref().and_then(|p| p.cwd.clone()))
    };
    Scope {
        directory,
        host: who.purpose.host.clone(),
        repo,
    }
}

/// What one approval covers.
///
/// A sign-in is the deliberate exception to the scoping above: the user is asked
/// for hours of signatures everywhere, the prompt and the card say so, and
/// that is the authorisation they give.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Reach {
    /// A sign-in: every request, wherever it comes from.
    Everywhere,
    /// One place, and nothing else.
    Place(Scope),
}

impl Reach {
    /// The key the enclave holds this approval's authenticated context under.
    fn key(&self) -> String {
        match self {
            Reach::Everywhere => "everywhere".to_string(),
            Reach::Place(scope) => serde_json::to_string(scope).unwrap_or_default(),
        }
    }
}

/// What approving a request from `place` covers, and for how many seconds.
fn grant(sign_in_secs: f64, reuse_secs: f64, place: &Scope) -> (Reach, f64) {
    if sign_in_secs > 0.0 {
        (Reach::Everywhere, sign_in_secs)
    } else {
        (Reach::Place(place.clone()), reuse_secs)
    }
}

/// A poisoned lock must never take SSH down; the worst it costs is one more prompt.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The lock, if nobody holds it.
fn idle<T>(m: &Mutex<T>) -> Option<MutexGuard<'_, T>> {
    match m.try_lock() {
        Ok(guard) => Some(guard),
        Err(TryLockError::Poisoned(p)) => Some(p.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    }
}

/// Seconds on a clock that keeps counting while the Mac sleeps. `Instant` stops
/// then, so a sign-in measured with it lasted six hours of waking time, not six hours.
///
/// NaN when the clock cannot be read: every comparison with it is false, so
/// nothing counts as live and every request asks.
fn clock() -> f64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return f64::NAN;
    }
    ts.tv_sec as f64 + ts.tv_nsec as f64 * 1e-9
}

/// Does an earlier approval still cover this request?
///
/// Kept pure so the window arithmetic is testable without an enclave.
fn reuse_covers(approved: &HashMap<Reach, f64>, reach: &Reach, window: f64, now: f64) -> bool {
    window > 0.0 && approved.get(reach).is_some_and(|at| now - *at < window)
}

/// Drop the approvals that have run out, and say which: the enclave is still
/// holding an authenticated context for each of them.
fn expire(approved: &mut HashMap<Reach, f64>, window: f64, now: f64) -> Vec<Reach> {
    let gone: Vec<Reach> = approved
        .iter()
        .filter(|(_, at)| now - **at >= window)
        .map(|(reach, _)| reach.clone())
        .collect();
    for reach in &gone {
        approved.remove(reach);
    }
    gone
}

/// 86400 -> "24 hours", in the largest unit that divides it evenly, so the sheet
/// never says "1440 minutes". Days start at two: one day reads as its hours.
fn span(secs: f64) -> String {
    let s = secs.round().max(1.0) as u64;
    let (n, unit) = match s {
        s if s % 86400 == 0 && s > 86400 => (s / 86400, "day"),
        s if s % 3600 == 0 => (s / 3600, "hour"),
        s if s % 60 == 0 => (s / 60, "minute"),
        s => (s, "second"),
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// When the sign-in a request opens will end.
#[derive(Debug, Clone, PartialEq)]
enum Ends {
    /// After this many seconds.
    After(f64),
    /// When the screen locks, which is where a sign-in key's sign-in stops, or
    /// after this many seconds if it never does.
    AtScreenLock(f64),
}

impl Ends {
    /// On the sheet, where every character comes out of the request beside it.
    fn sheet(&self) -> String {
        match self {
            Ends::After(secs) => format!("for {}", span(*secs)),
            Ends::AtScreenLock(_) => "until screen lock".to_string(),
        }
    }

    /// On the card, which has room for both ends.
    fn card(&self) -> String {
        match self {
            Ends::After(_) => self.sheet(),
            Ends::AtScreenLock(secs) => format!("for {} or until the screen locks", span(*secs)),
        }
    }
}

/// What one request needs, settled before the enclave is touched.
#[derive(Debug, PartialEq)]
struct Plan {
    /// What approving this request covers.
    reach: Reach,
    /// Seconds that approval lasts. 0 keeps nothing: every signature asks.
    window: f64,
    /// An earlier approval still covers this request.
    live: bool,
    /// Approvals that ran out. The enclave still holds a context for each.
    expired: Vec<Reach>,
    /// When the sign-in this request opens will end, when it opens one. Only that
    /// request says so, on the sheet and on the card.
    signing_in: Option<Ends>,
    /// Seconds within which a Touch ID unlock of the Mac may answer the prompt
    /// without it being shown. A place allows it, as it always has. A sign-in
    /// never does: hours everywhere are not handed out unseen.
    unlock_reuse: f64,
}

/// Kept pure, like the arithmetic above, so the rules are testable without an enclave.
///
/// The sign-in is the daemon's own check. With `approve` off there is none: holding
/// a context for hours then would let the one prompt a presence key raises by
/// itself, which names a single action, cover hours of signatures nobody was
/// asked about.
fn decide(
    approve: bool,
    sign_in_secs: f64,
    reuse_secs: f64,
    ends_at_lock: bool,
    place: &Scope,
    approved: &mut HashMap<Reach, f64>,
    now: f64,
) -> Plan {
    let (reach, window) = grant(if approve { sign_in_secs } else { 0.0 }, reuse_secs, place);
    let expired = expire(approved, window, now);
    let live = reuse_covers(approved, &reach, window, now);
    let everywhere = reach == Reach::Everywhere;
    let ends = if ends_at_lock { Ends::AtScreenLock(window) } else { Ends::After(window) };
    Plan {
        signing_in: (everywhere && !live).then_some(ends),
        unlock_reuse: if everywhere { 0.0 } else { window },
        reach,
        window,
        live,
        expired,
    }
}

/// A signature went through. The approval it opened starts now; one it rode
/// stays where it was opened, so a sign-in is six hours from the sign-in and not
/// six hours from its last use.
fn opened(approved: &mut HashMap<Reach, f64>, plan: &Plan, now: f64) {
    if !plan.live && plan.window > 0.0 {
        approved.insert(plan.reach.clone(), now);
    }
}

/// The daemon's half of a sign-out: every approval, and the count `admit` reads.
/// Says whether anybody was signed in.
fn end_approvals(ctx: &Ctx) -> bool {
    let mut approved = lock(&ctx.approved);
    ctx.sign_outs.fetch_add(1, Ordering::SeqCst);
    !std::mem::take(&mut *approved).is_empty()
}

/// Nobody is signed in any more, anywhere. Says whether anybody was.
fn sign_out(ctx: &Ctx, e: &Enclave) -> bool {
    let was = end_approvals(ctx);
    e.forget_all();
    was
}

/// Record the approval a signature opened. False when everybody was signed out while
/// it was being made: the Touch ID it waited for may have been given before the screen
/// locked, so neither the approval nor the signature may be kept.
fn admit(ctx: &Ctx, plan: &Plan, sign_outs: u64) -> bool {
    let mut approved = lock(&ctx.approved);
    if ctx.sign_outs.load(Ordering::SeqCst) != sign_outs {
        return false;
    }
    opened(&mut approved, plan, clock());
    true
}

/// One look at the screen: when, on `clock`, and what was there.
pub struct Look {
    at: f64,
    saw: Screen,
}

impl Look {
    /// What stands in for a look before there has been one.
    pub fn first() -> Look {
        Look { at: clock(), saw: Screen::Unlocked }
    }
}

/// How often the watch looks at the screen.
const LOOK_EVERY: Duration = Duration::from_secs(1);

/// Whether too long went by between two looks to say the screen stayed unlocked. The
/// watch looks every second, so a gap means the daemon was not running: the Mac slept,
/// and can have been locked and unlocked again before anything here woke. A clock
/// that cannot be read is a gap.
fn unseen(last: f64, now: f64) -> bool {
    !(now - last < 3.0)
}

/// One look at the screen, for a sign-in key. Anything but an unlocked screen signs
/// everybody out, and so does a gap since the last look. The log gets a line when
/// the screen changes, which is also how a lock that stopped being seen would show.
fn look(ctx: &Ctx, e: &Enclave) -> Screen {
    // Held to the end. Once this look is recorded the next one takes the screen as
    // watched, so it must not get in before the sign-out this one calls for.
    let mut looked = lock(&ctx.looked);
    let now = clock();
    let screen = crate::enclave::screen();
    let before = std::mem::replace(&mut *looked, Look { at: now, saw: screen });
    if screen != before.saw {
        eprintln!("keywardd: {}", screen.refusal().unwrap_or("screen unlocked"));
    }
    if (screen != Screen::Unlocked || unseen(before.at, now)) && sign_out(ctx, e) {
        match screen.refusal() {
            Some(why) => eprintln!("keywardd: signed out ({why})"),
            None => eprintln!(
                "keywardd: signed out (not watching for {:.0}s, long enough to hide a lock)",
                now - before.at
            ),
        }
    }
    screen
}

/// Why this key may not sign with the screen as it is, if it may not. Only a sign-in
/// key is held to the screen; the older kinds keep what their own policy gives them.
fn barred(ctx: &Ctx, e: &Enclave) -> Option<&'static str> {
    if !e.ends_at_lock {
        return None;
    }
    look(ctx, e).refusal()
}

/// What has run out is let go of by the enclave too, and the log says when that was
/// a sign-in.
fn release(e: &Enclave, gone: &[Reach], window: f64) {
    for reach in gone {
        e.forget(&reach.key());
        if *reach == Reach::Everywhere {
            eprintln!("keywardd: signed out (after {})", span(window));
        }
    }
}

/// Lives as long as the screen watch does. A watch that stopped would leave a daemon
/// that looks alive and signs nobody in: every request would find the screen
/// unwatched and sign out, its own sign-in included. So the daemon goes with it, and
/// launchd starts one that watches.
struct Watching;

impl Drop for Watching {
    fn drop(&mut self) {
        let _ = writeln!(io::stderr(), "keywardd: the screen watch stopped; exiting so launchd restarts it");
        std::process::exit(1);
    }
}

/// A sign-in key's sign-in ends when the screen locks. The lock is read once a second
/// rather than waited for: the notification macOS posts for it needs a run loop this
/// daemon does not have, and is not promised to arrive. `handle_sign` looks too, before
/// and after every signature, so a lock too brief to be seen here still cannot be
/// signed through while it lasts.
pub fn watch_screen(ctx: Arc<Ctx>) {
    std::thread::spawn(move || {
        let Some(e) = ctx.enclave.as_ref() else { return };
        let _watching = Watching;
        let (_, window) = grant(
            if ctx.require_approval { ctx.sign_in_secs } else { 0.0 },
            ctx.touch_id_reuse_secs,
            &Scope::default(),
        );
        loop {
            std::thread::sleep(LOOK_EVERY);
            look(&ctx, e);
            // What has run out is let go of here as well as at the next request, so a
            // secret does not sit in memory waiting for one. Never under a signature:
            // the request in flight decided with the approvals as they were.
            if let Some(_turn) = idle(&ctx.sign_gate) {
                let gone = expire(&mut lock(&ctx.approved), window, clock());
                release(e, &gone, window);
            }
        }
    });
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
///
/// `sign_in` is when the sign-in this prompt opens will end, as `Ends::sheet` puts
/// it. That approval reaches past the action that raised it, so the sheet leads
/// with it.
fn sheet_reason(who: &Attribution, configured: &str, sign_in: Option<&str>) -> String {
    let configured = (!configured.is_empty()).then(|| sanitise(configured));
    // A configured text may replace the action, never the sign-in: the sheet is
    // the one place the grant is certain to be read, the card being best-effort.
    if let Some(ends) = sign_in {
        let rest = configured.unwrap_or_else(|| prompt_action(who));
        let said = match rest.as_str() {
            "" => format!("Sign in {ends}"),
            rest => format!("Sign in {ends} · {rest}"),
        };
        return crate::purpose::shorten(&said, PROMPT_MAX);
    }
    if let Some(configured) = configured {
        return crate::purpose::shorten(&configured, PROMPT_MAX);
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
        sign_in: false,
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
            let fp = fingerprint(&blob);

            // The daemon keeps the only clock. Approvals that have run out are dropped
            // together with the authenticated context the enclave held for each, and
            // without a live one this request's own context is dropped too, so it
            // prompts and cannot inherit an approval the user granted somewhere else.
            let scope = scope_of(who);
            let approve = ctx.require_approval;
            let _turn = lock(&ctx.sign_gate);
            // A sign-in key signs nothing on a locked screen, and its sign-in does not
            // outlive one. `watch_screen` ends it within a second of the lock; this is
            // the same look at the moment it matters, and it refuses without raising
            // a sheet nobody is there to see.
            let refused = barred(ctx, e);
            let sign_outs = ctx.sign_outs.load(Ordering::SeqCst);
            let plan = decide(
                approve,
                ctx.sign_in_secs,
                ctx.touch_id_reuse_secs,
                e.ends_at_lock,
                &scope,
                &mut lock(&ctx.approved),
                clock(),
            );
            let key = plan.reach.key();
            release(e, &plan.expired, plan.window);
            if !plan.live {
                e.forget(&key);
            }
            let reused = approve && plan.live;
            let signed = match refused {
                Some(why) => Err(why.to_string()),
                None => {
                    let on_sheet = plan.signing_in.as_ref().map(Ends::sheet);
                    let on_card = plan.signing_in.as_ref().map(Ends::card);
                    let reason = sheet_reason(who, &ctx.sheet_reason, on_sheet.as_deref());
                    let card = approve.then(|| {
                        crate::ui::show(who, &headline, Some(&e.comment), Some(&fp), on_card.as_deref())
                    });
                    let signed = e.sign(
                        &data,
                        &reason,
                        &key,
                        plan.window > 0.0,
                        plan.unlock_reuse,
                        approve,
                        plan.live,
                    );
                    if let Some(card) = card {
                        card.done();
                    }
                    // The card and the sheet take time, and the screen can lock under
                    // either. A signature made by then stays here.
                    match barred(ctx, e) {
                        Some(why) => Err(why.to_string()),
                        None => signed,
                    }
                }
            };
            let (reply, outcome) = match signed {
                Ok(sig) if admit(ctx, &plan, sign_outs) => {
                    let mut w = Writer::new();
                    w.u8(SIGN_RESPONSE);
                    w.string(&sig);
                    (w.buf, "ok".to_string())
                }
                Ok(_) => {
                    // The sign-out could not see what this request was holding.
                    e.forget(&key);
                    (failure(), "signed out while signing".to_string())
                }
                Err(err) => {
                    // The context this request built may have been authenticated
                    // before the signature failed, and a sign-out meanwhile could not
                    // see it. No approval was opened to end it.
                    if !plan.live || ctx.sign_outs.load(Ordering::SeqCst) != sign_outs {
                        e.forget(&key);
                    }
                    (failure(), err)
                }
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
                sign_in: plan.reach == Reach::Everywhere,
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
        sign_in: false,
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
                    sign_in: false,
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
    use super::{
        admit, decide, end_approvals, expire, grant, lock, opened, reuse_covers, sheet_reason, span,
        unseen, Ctx, Ends, Look, PurposeKind, Reach, Scope, Screen,
    };
    use crate::attrib::{AppInfo, Attribution};
    use crate::event::Log;
    use crate::purpose::Purpose;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Mutex, RwLock};
    use std::time::Duration;

    const DAY: f64 = 86400.0;
    /// Any reading of the daemon's clock; only differences matter.
    const NOW: f64 = 500_000.0;

    fn scope(dir: &str, host: &str, repo: &str) -> Scope {
        Scope {
            directory: Some(dir.into()),
            host: Some(host.into()),
            repo: Some(repo.into()),
        }
    }

    fn place(dir: &str, host: &str, repo: &str) -> Reach {
        Reach::Place(scope(dir, host, repo))
    }

    fn approved(entries: &[(&Reach, f64)]) -> HashMap<Reach, f64> {
        entries.iter().map(|(r, at)| ((*r).clone(), *at)).collect()
    }

    #[test]
    fn a_fresh_approval_covers_the_same_place() {
        let s = place("/src/keyward", "github.com", "git@github.com:me/keyward.git");
        let a = approved(&[(&s, NOW - 30.0)]);
        assert!(reuse_covers(&a, &s, 300.0, NOW));
    }

    #[test]
    fn another_directory_host_or_remote_does_not_inherit_it() {
        let s = place("/src/keyward", "github.com", "git@github.com:me/keyward.git");
        let a = approved(&[(&s, NOW)]);
        for other in [
            place("/src/other", "github.com", "git@github.com:me/keyward.git"),
            place("/src/keyward", "gitlab.com", "git@github.com:me/keyward.git"),
            place("/src/keyward", "github.com", "git@github.com:me/secrets.git"),
        ] {
            assert!(
                !reuse_covers(&a, &other, 300.0, NOW),
                "{other:?} must not ride an approval granted for {s:?}"
            );
        }
    }

    #[test]
    fn the_window_expires_and_zero_disables_it() {
        let s = place("/src/keyward", "github.com", "git@github.com:me/keyward.git");
        let stale = approved(&[(&s, NOW - 301.0)]);
        assert!(!reuse_covers(&stale, &s, 300.0, NOW), "past the window");
        let fresh = approved(&[(&s, NOW)]);
        assert!(!reuse_covers(&fresh, &s, 0.0, NOW), "0 asks every time");
        assert!(!reuse_covers(&HashMap::new(), &s, 300.0, NOW), "nothing approved yet");
    }

    /// A push and the fetch that follows it in the same checkout are one approval:
    /// the purpose kind is deliberately outside the scope.
    #[test]
    fn a_different_purpose_in_the_same_place_still_rides_it() {
        let push = place("/src/keyward", "github.com", "git@github.com:me/keyward.git");
        let fetch = push.clone();
        let a = approved(&[(&push, NOW - 5.0)]);
        assert!(reuse_covers(&a, &fetch, 300.0, NOW));
    }

    /// Two agents in two repositories, approved one after the other: the second
    /// approval must not evict the first, or alternating requests prompt every time.
    #[test]
    fn approvals_in_two_places_coexist() {
        let ccbroker = place("/src/ccbroker", "git@github.com", "git@github.com:me/ccbroker.git");
        let frizz = place("/src/frizz", "git@github.com", "git@github.com:me/frizz.git");
        let a = approved(&[(&ccbroker, NOW - 180.0), (&frizz, NOW - 160.0)]);
        assert!(reuse_covers(&a, &ccbroker, 300.0, NOW));
        assert!(reuse_covers(&a, &frizz, 300.0, NOW));
    }

    /// The sign-in: one approval, granted from one repository, covers a push from
    /// another and a login to a host that has nothing to do with either.
    #[test]
    fn a_sign_in_covers_every_place() {
        let keyward = scope("/src/keyward", "github.com", "git@github.com:me/keyward.git");
        let (reach, window) = grant(DAY, 300.0, &keyward);
        assert_eq!((&reach, window), (&Reach::Everywhere, DAY));
        let a = approved(&[(&reach, NOW - 6.0 * 3600.0)]);
        for other in [
            scope("/src/frizz", "github.com", "git@github.com:me/frizz.git"),
            scope("/home", "root@server.example", ""),
            Scope::default(),
        ] {
            let (theirs, window) = grant(DAY, 300.0, &other);
            assert!(reuse_covers(&a, &theirs, window, NOW), "{other:?} is signed in too");
        }
    }

    #[test]
    fn a_sign_in_lasts_its_day_and_no_longer() {
        let a = approved(&[(&Reach::Everywhere, NOW - DAY + 1.0)]);
        assert!(reuse_covers(&a, &Reach::Everywhere, DAY, NOW), "a second short of a day");
        let a = approved(&[(&Reach::Everywhere, NOW - DAY)]);
        assert!(!reuse_covers(&a, &Reach::Everywhere, DAY, NOW), "a day is up");
    }

    /// `sign_in_secs: 0` is the old behaviour exactly: each place on its own, for
    /// `touch_id_reuse_secs`.
    #[test]
    fn without_a_sign_in_each_place_is_approved_on_its_own() {
        let keyward = scope("/src/keyward", "github.com", "git@github.com:me/keyward.git");
        assert_eq!(grant(0.0, 300.0, &keyward), (Reach::Place(keyward.clone()), 300.0));
        assert_eq!(grant(0.0, 0.0, &keyward), (Reach::Place(keyward), 0.0));
    }

    /// The enclave holds an authenticated context for every approval, under this
    /// key. A place must never be able to name the sign-in's.
    #[test]
    fn a_place_never_shares_the_sign_in_context() {
        let nowhere = Reach::Place(Scope::default());
        assert_ne!(nowhere.key(), Reach::Everywhere.key());
        assert_ne!(
            place("everywhere", "everywhere", "everywhere").key(),
            Reach::Everywhere.key()
        );
    }

    /// What has run out is handed back, so the enclave can be told to let go of it;
    /// what is still live stays.
    #[test]
    fn expired_approvals_are_dropped_and_named() {
        let old = place("/src/ccbroker", "github.com", "git@github.com:me/ccbroker.git");
        let live = place("/src/frizz", "github.com", "git@github.com:me/frizz.git");
        let mut a = approved(&[(&old, NOW - 300.0), (&live, NOW - 299.0)]);
        assert_eq!(expire(&mut a, 300.0, NOW), vec![old]);
        assert_eq!(a.keys().collect::<Vec<_>>(), vec![&live]);
        assert!(expire(&mut a, 300.0, NOW).is_empty());

        let mut signed_in = approved(&[(&Reach::Everywhere, NOW - DAY)]);
        assert_eq!(expire(&mut signed_in, DAY, NOW), vec![Reach::Everywhere]);
        assert!(signed_in.is_empty());
    }

    fn pushing(remote_repo: &str) -> Attribution {
        Attribution {
            pid: 1,
            process: None,
            ancestry: Vec::new(),
            app: Some(AppInfo {
                bundle_path: "/Applications/Ghostty.app".into(),
                name: "Ghostty".into(),
                depth: 2,
            }),
            apps: Vec::new(),
            destination: None,
            purpose: Purpose {
                kind: PurposeKind::GitPush,
                summary: String::new(),
                host: Some("git@github.com".into()),
                repo: None,
                repo_path: None,
                remote_repo: Some(remote_repo.into()),
                namespace: None,
                remote_command: None,
            },
            context: Default::default(),
        }
    }

    /// The sheet cannot be screenshotted, so what it says is pinned here. Approving
    /// a sign-in grants more than the request that raised it: the sheet leads with
    /// that, and gives up the app's name and then the tail of the action to fit.
    #[test]
    fn a_sign_in_leads_the_sheet() {
        let who = pushing("me/keyward.git");
        assert_eq!(sheet_reason(&who, "", None), "git push to me/keyward · Ghostty");
        assert_eq!(
            sheet_reason(&who, "", Some("for 24 hours")),
            "Sign in for 24 hours · git push to me/keyward"
        );
        let long = sheet_reason(&pushing("an-organisation/a-repository.git"), "", Some("for 24 hours"));
        assert_eq!(long, "Sign in for 24 hours · git push to an-organisation/a-rep…");
    }

    /// `sheet_reason` in the config replaces the action. It must not be able to
    /// take the sign-in off the sheet: a single space, "say as little as macOS
    /// allows", would otherwise grant a day on a sheet that mentions none of it.
    #[test]
    fn a_configured_sheet_text_cannot_hide_a_sign_in() {
        let who = pushing("me/keyward.git");
        assert_eq!(sheet_reason(&who, "Approve", None), "Approve");
        assert_eq!(sheet_reason(&who, " ", None), "");
        assert_eq!(sheet_reason(&who, "Approve", Some("for 24 hours")), "Sign in for 24 hours · Approve");
        assert_eq!(sheet_reason(&who, " ", Some("for 24 hours")), "Sign in for 24 hours");
    }

    /// The whole day, as the daemon decides it: the first request anywhere signs
    /// in, everything after rides it from anywhere, and the day runs from the
    /// sign-in rather than from the last signature that rode it.
    #[test]
    fn one_sign_in_a_day_across_every_place() {
        let keyward = scope("/src/keyward", "github.com", "git@github.com:me/keyward.git");
        let frizz = scope("/src/frizz", "github.com", "git@github.com:me/frizz.git");
        let mut a = HashMap::new();

        let first = decide(true, DAY, 0.0, false, &keyward, &mut a, NOW);
        assert_eq!((&first.reach, first.window, first.live), (&Reach::Everywhere, DAY, false));
        assert_eq!(first.signing_in, Some(Ends::After(DAY)), "the sheet and the card say so");
        assert_eq!(first.unlock_reuse, 0.0, "a recent unlock of the Mac never answers a sign-in");
        opened(&mut a, &first, NOW);

        let late = NOW + DAY - 60.0;
        let next = decide(true, DAY, 0.0, false, &frizz, &mut a, late);
        assert!(next.live, "another repository, 23 hours 59 minutes on");
        assert_eq!(next.signing_in, None, "only the request that signs in says so");
        opened(&mut a, &next, late);
        assert_eq!(a[&Reach::Everywhere], NOW, "riding a sign-in does not extend it");

        let after = decide(true, DAY, 0.0, false, &keyward, &mut a, NOW + DAY);
        assert!(!after.live, "a day from the sign-in, not from its last use");
        assert_eq!(after.expired, vec![Reach::Everywhere], "the enclave lets go of its context");
        assert_eq!(after.signing_in, Some(Ends::After(DAY)));
    }

    /// A sign-in key's sign-in stops at the screen lock. The sheet says that, and
    /// the card, which has the room, says how long it lasts if the screen never locks.
    #[test]
    fn a_sign_in_key_signs_in_until_the_screen_locks() {
        let keyward = scope("/src/keyward", "github.com", "git@github.com:me/keyward.git");
        let plan = decide(true, DAY, 0.0, true, &keyward, &mut HashMap::new(), NOW);
        assert_eq!(plan.signing_in, Some(Ends::AtScreenLock(DAY)));
        assert_eq!((&plan.reach, plan.window), (&Reach::Everywhere, DAY), "a day with no lock ends it too");
        assert_eq!(
            sheet_reason(&pushing("me/keyward.git"), "", Some(&Ends::AtScreenLock(DAY).sheet())),
            "Sign in until screen lock · git push to me/keyward"
        );
        assert_eq!(Ends::AtScreenLock(21600.0).card(), "for 6 hours or until the screen locks");
        assert_eq!((Ends::After(DAY).sheet(), Ends::After(DAY).card()), ("for 24 hours".into(), "for 24 hours".into()));

        // The longer lead leaves the action less room, and it is the action that gives.
        let long = sheet_reason(
            &pushing("an-organisation/a-repository.git"),
            "",
            Some(&Ends::AtScreenLock(DAY).sheet()),
        );
        assert_eq!(long, "Sign in until screen lock · git push to an-organisation/…");
    }

    /// Only an unlocked screen has no reason to refuse, and the log says which of
    /// the others it was.
    #[test]
    fn a_screen_that_is_not_unlocked_says_why() {
        assert_eq!(Screen::Unlocked.refusal(), None);
        assert_eq!(Screen::Locked.refusal(), Some("screen locked"));
        assert_eq!(Screen::Away.refusal(), Some("not at the console"));
        assert_eq!(Screen::Unreadable.refusal(), Some("screen state unreadable"));
    }

    /// The watch looks every second. When far longer than that went by the Mac was
    /// asleep, and a lock can hide in a sleep.
    #[test]
    fn a_gap_between_looks_cannot_vouch_for_the_screen() {
        assert!(!unseen(NOW, NOW + 1.0));
        assert!(!unseen(NOW, NOW + 2.5), "a slow second is not a sleep");
        assert!(unseen(NOW, NOW + 3.0));
        assert!(unseen(NOW, NOW + 8.0 * 3600.0));
        assert!(unseen(NOW, f64::NAN), "an unreadable clock vouches for nothing");
        assert!(unseen(f64::NAN, NOW));
    }

    fn ctx() -> Ctx {
        Ctx {
            enclave: None,
            upstreams: Vec::new(),
            routes: RwLock::new(HashMap::new()),
            comments: RwLock::new(HashMap::new()),
            log: Log::new(std::env::temp_dir().join("keyward-test-events.jsonl"), 0),
            timeout: Duration::from_secs(1),
            conns: AtomicUsize::new(0),
            log_lists: false,
            sign_in_secs: DAY,
            touch_id_reuse_secs: 0.0,
            require_approval: true,
            sheet_reason: String::new(),
            approved: Mutex::new(HashMap::new()),
            sign_outs: AtomicU64::new(0),
            looked: Mutex::new(Look::first()),
            sign_gate: Mutex::new(()),
        }
    }

    /// A Touch ID sheet stays up for as long as it is left, and the screen can lock
    /// under it. The sign-out that runs then cannot see what the request is about to
    /// hold, so the request finds out when it comes back, and opens nothing.
    #[test]
    fn a_sign_out_during_a_signature_leaves_nobody_signed_in() {
        let ctx = ctx();
        let keyward = scope("/src/keyward", "github.com", "git@github.com:me/keyward.git");

        let before = ctx.sign_outs.load(Ordering::SeqCst);
        let plan = decide(true, DAY, 0.0, true, &keyward, &mut lock(&ctx.approved), NOW);
        assert!(!end_approvals(&ctx), "nobody was signed in yet");
        assert!(!admit(&ctx, &plan, before), "the signature came back to a sign-out");
        assert!(lock(&ctx.approved).is_empty());

        // The next request starts from the count as it stands, and signs in.
        let before = ctx.sign_outs.load(Ordering::SeqCst);
        let plan = decide(true, DAY, 0.0, true, &keyward, &mut lock(&ctx.approved), NOW);
        assert!(admit(&ctx, &plan, before));
        assert!(lock(&ctx.approved).contains_key(&Reach::Everywhere));

        assert!(end_approvals(&ctx), "a lock signs that out");
        assert!(lock(&ctx.approved).is_empty());
    }

    /// A sign-in that was declined, or whose signature failed, opens nothing: the
    /// next request asks again.
    #[test]
    fn a_sign_in_that_did_not_go_through_leaves_nobody_signed_in() {
        let keyward = scope("/src/keyward", "github.com", "git@github.com:me/keyward.git");
        let mut a = HashMap::new();
        let declined = decide(true, DAY, 0.0, false, &keyward, &mut a, NOW);
        assert!(declined.signing_in.is_some());
        // No `opened`: the signature never happened.
        let again = decide(true, DAY, 0.0, false, &keyward, &mut a, NOW + 1.0);
        assert!(!again.live);
        assert!(again.signing_in.is_some());
    }

    /// `require_approval: false` is the daemon not asking at all, so there is no
    /// sign-in to hold a context for, whatever `sign_in_secs` says.
    #[test]
    fn with_require_approval_off_there_is_no_sign_in() {
        let keyward = scope("/src/keyward", "github.com", "git@github.com:me/keyward.git");
        let mut a = HashMap::new();
        let plan = decide(false, DAY, 0.0, false, &keyward, &mut a, NOW);
        assert_eq!(plan.reach, Reach::Place(keyward.clone()));
        assert_eq!(plan.window, 0.0, "nothing is held");
        assert_eq!(plan.signing_in, None);
        opened(&mut a, &plan, NOW);
        assert!(a.is_empty());

        let windowed = decide(false, DAY, 300.0, false, &keyward, &mut a, NOW);
        assert_eq!((windowed.reach, windowed.window), (Reach::Place(keyward), 300.0));
    }

    /// `sign_in_secs: 0`, as the daemon decides it: one place's approval says
    /// nothing about a sign-in, lets a recent unlock stand in as it always did, and
    /// leaves the next place to ask for itself.
    #[test]
    fn place_by_place_nothing_about_a_sign_in_applies() {
        let keyward = scope("/src/keyward", "github.com", "git@github.com:me/keyward.git");
        let frizz = scope("/src/frizz", "github.com", "git@github.com:me/frizz.git");
        let mut a = HashMap::new();

        let first = decide(true, 0.0, 300.0, false, &keyward, &mut a, NOW);
        assert_eq!((first.signing_in.clone(), first.unlock_reuse), (None, 300.0));
        opened(&mut a, &first, NOW);
        assert!(decide(true, 0.0, 300.0, false, &keyward, &mut a, NOW + 10.0).live);
        assert!(!decide(true, 0.0, 300.0, false, &frizz, &mut a, NOW + 10.0).live);

        let every_time = decide(true, 0.0, 0.0, false, &keyward, &mut HashMap::new(), NOW);
        assert_eq!((every_time.window, every_time.live), (0.0, false));
    }

    /// A length nobody meant falls back to asking, never to a sign-in without end.
    #[test]
    fn a_nonsense_length_is_no_sign_in() {
        let keyward = scope("/src/keyward", "github.com", "git@github.com:me/keyward.git");
        for secs in [-1.0, f64::NAN] {
            let plan = decide(true, secs, 0.0, false, &keyward, &mut HashMap::new(), NOW);
            assert_eq!((plan.reach, plan.window), (Reach::Place(keyward.clone()), 0.0), "{secs}");
        }
    }

    /// A clock that cannot be read is NaN, and then nobody is signed in.
    #[test]
    fn an_unreadable_clock_asks() {
        let mut a = approved(&[(&Reach::Everywhere, NOW)]);
        let plan = decide(true, DAY, 0.0, false, &Scope::default(), &mut a, f64::NAN);
        assert!(!plan.live);
        assert!(plan.signing_in.is_some());
    }

    #[test]
    fn the_sheet_names_the_span_in_its_largest_whole_unit() {
        assert_eq!(span(86400.0), "24 hours");
        assert_eq!(span(7.0 * 86400.0), "7 days");
        assert_eq!(span(3600.0), "1 hour");
        assert_eq!(span(5400.0), "90 minutes");
        assert_eq!(span(60.0), "1 minute");
        assert_eq!(span(45.0), "45 seconds");
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
