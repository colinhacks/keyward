//! Telling the app that a signature is in flight.
//!
//! The system Touch ID sheet cannot be restyled, reparented or screenshotted —
//! it belongs to `coreautha` and sits at window layer 1000 precisely so no app
//! can dress it up or fake it. What we can do is put a card *behind* it. So the
//! daemon asks the app to raise that card, waits briefly for confirmation so
//! the ordering looks deliberate, signs (the sheet appears on top), and tells
//! the app to take it away.
//!
//! Best-effort throughout: if the app is not running the connection simply
//! fails and the signature proceeds. The card is context, never a gate — making
//! it one would mean quitting the UI breaks SSH.

use crate::attrib::Attribution;
use serde::Serialize;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Serialize)]
struct Show<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    headline: &'a str,
    app: Option<String>,
    app_bundle: Option<String>,
    process: Option<String>,
    key: Option<String>,
    fingerprint: Option<String>,
    host: Option<String>,
    repo: Option<String>,
    branch: Option<String>,
    subject: Option<String>,
    /// The actual command or operation — the card has room for it, the sheet
    /// does not, and "run a command" without saying which is useless.
    command: Option<String>,
    /// True when `command` is a script recovered from stdin rather than argv.
    script: bool,
    chain: Vec<String>,
    session: Option<String>,
    /// Working directory of the git (or caller) process, with $HOME shortened to ~.
    directory: Option<String>,
    /// "origin = git@github.com:owner/repo.git" for a push.
    remote: Option<String>,
    /// For a push: the commits about to leave, newest first, and the shortstat.
    commits: Vec<String>,
    commit_count: Option<u32>,
    stat: Option<String>,
    /// For a push: the remote-tracking ref the range was computed against; None means a new branch.
    upstream: Option<String>,
}

/// A name a human recognises for a link in the chain. `node` says nothing when it is the frizz
/// server or a Claude session; the path and arguments say which.
///
/// Only the executable and the entry-point argument are allowed to decide what a process *is*.
/// Matching the whole joined argv labelled the Claude session `frizz server` too, because its
/// `--mcp-config` argument names the server's path — and the card then collapsed two identical
/// consecutive links into one, losing `claude` from the chain entirely.
fn display_name(p: &crate::attrib::ProcInfo) -> Option<String> {
    let name = p.name.clone()?;
    if p.path.as_deref().map_or(false, |path| path.ends_with("/claude")) {
        return Some("claude".into());
    }
    // `node /Users/<user>/.frizz/server-releases/<hash>/<entry>` — argv[1] is the entry point.
    let head = p.path.iter().chain(p.args.iter().take(2));
    if head.clone().any(|s| s.contains(".frizz/server-releases") || s.contains("frizz-server")) {
        return Some("frizz server".into());
    }
    if name == "node" && head.clone().any(|s| s.contains("/claude") || s.contains("claude-code")) {
        return Some("claude".into());
    }
    Some(name)
}

fn short_home(path: &str) -> String {
    match std::env::var("HOME") {
        Ok(h) if path.starts_with(&h) => format!("~{}", &path[h.len()..]),
        _ => path.to_string(),
    }
}

fn socket_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join("Library/Application Support/Keyward/ui.sock")
}

/// Raise the card. Returns the live connection; dropping it hides the card.
pub struct Card(Option<UnixStream>);

impl Card {
    pub fn done(mut self) {
        if let Some(s) = self.0.as_mut() {
            let _ = s.write_all(b"{\"type\":\"done\"}\n");
            let _ = s.flush();
        }
    }
}

/// `ssh host bash -s` names the shell, not the work — the work is on stdin.
fn reads_stdin(cmd: &str) -> bool {
    matches!(
        cmd.trim(),
        "bash -s" | "sh -s" | "zsh -s" | "bash" | "sh" | "zsh" | "bash -" | "sh -" | "cat"
    )
}

/// The script a stdin-reading shell was handed, when it is recoverable.
///
/// zsh writes a heredoc to a temp file, so fd 0 is a plain vnode we can read.
/// Anything genuinely piped is a pipe with no backing file and stays unknown —
/// this returns None there rather than inventing something.
fn stdin_script(pid: i32) -> Option<String> {
    const MAX: u64 = 64 * 1024;
    let path = crate::attrib::fd_path(pid, 0)?;
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX {
        return None;
    }
    let text = std::fs::read_to_string(&path).ok()?;
    let t = text.trim();
    if t.is_empty() { None } else { Some(t.to_string()) }
}

pub fn show(who: &Attribution, headline: &str, key: Option<&str>, fp: Option<&str>) -> Card {
    let mut stream = match UnixStream::connect(socket_path()) {
        Ok(s) => s,
        Err(_) => return Card(None), // app not running; sign without the card
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(600)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(600)));

    let git = who.context.git.as_ref();

    let raw = who
        .purpose
        .remote_command
        .clone()
        .or_else(|| who.process.as_ref().map(|p| p.commandline()));
    let (command, is_script) = match raw {
        Some(c) if reads_stdin(&c) => match who.process.as_ref().and_then(|p| stdin_script(p.pid)) {
            Some(script) => (Some(script), true),
            // Honest about the gap: a pipe leaves nothing to read.
            None => (Some(format!("{c}   (script piped on stdin — not readable)")), false),
        },
        other => (other, false),
    };
    let msg = Show {
        kind: "show",
        headline,
        app: who.app.as_ref().map(|a| a.name.clone()),
        app_bundle: who.app.as_ref().map(|a| a.bundle_path.clone()),
        process: who.process.as_ref().and_then(|p| p.name.clone()),
        key: key.map(str::to_string),
        fingerprint: fp.map(str::to_string),
        host: who.purpose.host.clone(),
        repo: who.purpose.repo.clone(),
        branch: git.and_then(|g| g.branch.clone()),
        subject: git.and_then(|g| g.subject.clone()),
        command: command.clone(),
        script: is_script,
        chain: who
            .ancestry
            .iter()
            .rev()
            .filter_map(display_name)
            .collect(),
        directory: who
            .purpose
            .repo_path
            .clone()
            .or_else(|| who.process.as_ref().and_then(|p| p.cwd.clone()))
            .map(|d| short_home(&d)),
        remote: git.and_then(|g| match (&g.push_remote, &g.push_remote_url) {
            (Some(n), Some(url)) => Some(format!("{n} = {url}")),
            (Some(n), None) => Some(n.clone()),
            (None, _) => None,
        }),
        commits: git.map(|g| g.commits.clone()).unwrap_or_default(),
        commit_count: git.and_then(|g| g.commit_count),
        stat: git.and_then(|g| g.stat.clone()),
        upstream: git.and_then(|g| g.upstream.clone()),
        // The title if we could resolve it, the raw id only as a last resort.
        session: who
            .context
            .session_title
            .clone()
            .or_else(|| who.context.env.get("CLAUDE_CODE_HOST_SESSION_ID").cloned()),
    };

    let Ok(mut line) = serde_json::to_vec(&msg) else {
        return Card(Some(stream));
    };
    line.push(b'\n');
    if stream.write_all(&line).is_err() {
        return Card(None);
    }
    let _ = stream.flush();

    // Wait for the card to actually be on screen before triggering the sheet,
    // so it never flashes up after the sheet it is meant to sit behind.
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return Card(Some(stream)),
    });
    let mut ack = String::new();
    let _ = reader.read_line(&mut ack);

    Card(Some(stream))
}

#[cfg(test)]
mod tests {
    use super::display_name;
    use crate::attrib::ProcInfo;

    fn proc(name: &str, path: &str, args: &[&str]) -> ProcInfo {
        ProcInfo {
            pid: 1,
            name: Some(name.into()),
            path: Some(path.into()),
            cwd: None,
            args: args.iter().map(|a| a.to_string()).collect(),
        }
    }

    #[test]
    fn frizz_server_is_named_by_its_entry_point() {
        let p = proc(
            "node",
            "/Users/someone/.local/share/nvm/v24.0.0/bin/node",
            &["node", "/Users/someone/.frizz/server-releases/a1b2c3/server.mjs"],
        );
        assert_eq!(display_name(&p).as_deref(), Some("frizz server"));
    }

    /// The regression: the session's MCP config names the server, and a whole-argv
    /// match turned the Claude link into a second `frizz server`.
    #[test]
    fn claude_mentioning_the_server_is_still_claude() {
        let p = proc(
            "claude",
            "/Users/someone/.frizz/runtimes/claude/2.1.277/claude",
            &[
                "claude",
                "--mcp-config",
                "{\"frizz\":{\"command\":\"node\",\"args\":[\"/Users/someone/.frizz/server-releases/a1b2c3/mcp.mjs\"]}}",
            ],
        );
        assert_eq!(display_name(&p).as_deref(), Some("claude"));
    }

    #[test]
    fn ordinary_processes_keep_their_own_name() {
        assert_eq!(display_name(&proc("zsh", "/bin/zsh", &["-zsh"])).as_deref(), Some("zsh"));
    }
}
