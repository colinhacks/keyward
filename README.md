# Keyward

An SSH agent proxy that can tell you *what a signature was for*.

It sits where `ssh-agent-mux` sat — in front of Secretive and gpg-agent — and
answers the question neither of them can: not just "a key was used", but
"a git commit in `nixos-config` was signed", "a push went to `github.com`",
"someone logged into `arcturus`".

- `daemon/` — Rust. Speaks the SSH agent protocol, merges the upstream agents,
  attributes and logs every request.
- `app/` — SwiftUI. Live view and history, with app icons and full detail.

![Signing a commit](assets/screenshots/approval-commit.png)

The system Touch ID sheet cannot be restyled or moved, so Keyward lays a card
out *around* it — the sheet docks into a slot sized to fit, and everything worth
reading sits beside it.

![Running a remote command](assets/screenshots/approval-command.png)

A multi-line command is shown in full rather than as `bash -s`, with section
`echo`s rendered as comments.

*(Screenshots use example data.)*

## Why

macOS gives an agent one way to identify its caller: resolve the peer pid with
`NSRunningApplication`. That API only knows GUI apps, and every SSH caller is a
CLI process, so it always returns nil — which is why Secretive's notification
never names anything. Two facts make it recoverable:

1. **The parent chain reaches a real app.** `ssh → zsh → Ghostty`. Keyward walks
   it and matches against `.app` bundles by path, so it works even after the
   process exits, and it reports the whole chain rather than one name.

2. **Intent is visible in the caller's argv.** git signs commits by running
   `ssh-keygen -Y sign -n git` and moves objects by running
   `ssh <host> git-receive-pack '<repo>'`. Neither ever names the *local*
   repository, so that comes from the caller's working directory
   (`proc_pidinfo`/`PROC_PIDVNODEPATHINFO`).

`session-bind@openssh.com` carries the destination host key, which would be the
ideal provenance channel — but neither Secretive nor gpg-agent implements it.
Keyward answers it locally (with the `FAILURE` a non-supporting agent returns,
which ssh already tolerates) and keeps the host key as evidence, instead of
forwarding it upstream to produce errors.

## Failure modes it is built to avoid

`ssh-agent-mux` wedged on 2026-09-06: alive, accepting connections, answering
none. Established ControlMaster sessions kept working while every new handshake
hung, which made a purely local fault look like a mesh outage. launchd never
noticed, because `KeepAlive.Crashed` only sees a process that died.

- **Thread per connection, no shared state across I/O.** One unresponsive
  upstream cannot stall an unrelated caller.
- **Every upstream call is timeout-bounded** (`timeout_secs`, default 10).
- **`keywardd --health`** performs a real request against the socket and exits
  non-zero if it is not answered — the check launchd cannot do. The daemon runs
  the same probe against its own socket every two minutes and exits when nothing
  answers, so KeepAlive replaces a wedged process without a second agent.
- **A stale socket is cleared, a live one is respected.** The old mux
  crash-looped on "Address already in use" forever; Keyward connects first and
  only removes the file if nothing answers.
- Connections are capped (512) so clients cannot pile up unbounded.

## Build

```sh
./build.sh          # -> dist/keywardd and dist/Keyward.app
```

## Configure

`~/.config/keyward/config.json` (all fields optional; these are the defaults):

```json
{
  "listen": "~/.ssh/keyward.sock",
  "log": "~/Library/Application Support/Keyward/events.jsonl",
  "upstreams": [
    { "name": "Secretive", "path": "~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh" },
    { "name": "gpg-agent", "path": "~/.gnupg/S.gpg-agent.ssh" }
  ],
  "timeout_secs": 10,
  "max_log_bytes": 33554432,
  "sign_in_secs": 21600
}
```

Point ssh at it with `IdentityAgent ~/.ssh/keyward.sock`.

The first upstream to claim a key owns it, so ordering decides which agent signs
when both hold the same key.

## Log

One JSON object per request in `events.jsonl`, holding the purpose, the full
process ancestry, the key fingerprint, the upstream that signed, the destination
and the outcome. The app tails it; nothing else writes to it.

## Passing context in

Three channels, none needing cooperation from `ssh` itself.

**1. The repository.** For git work, the branch, remote and the commit message
about to be signed are read from disk. git writes `COMMIT_EDITMSG` before it
asks for the signature, so the message is already there. Nothing to configure.

**2. A declaration file, keyed by pid.** Any process may explain itself:

```sh
echo '{"reason":"release cut","task":"ASTR-441"}' \
  > "$HOME/Library/Application Support/Keyward/context/$$.json"
```

The daemon walks the process ancestry and picks up the file belonging to the
nearest matching pid, so a wrapper can label a single command or a long-running
agent can label its whole session. Nearest wins. This is the only channel that
works for *every* request type.

**3. The environment of the nearest ancestor that exposes one.** Measured
behaviour on macOS 26, not documented policy:

| process | environment readable |
|---|---|
| `/usr/bin/ssh` | no |
| `/usr/bin/ssh-keygen` | **yes** |
| `/bin/zsh`, `/bin/sleep` | no |
| user-installed binaries (agents, terminals) | **yes** |

Both `ssh` and `ssh-keygen` carry identical code-signing flags
(`0x10000(runtime)`), so the code signature does not explain the difference —
treat the table as empirical.

The practical consequence:

- **Commit signing** goes through `ssh-keygen`, so a per-invocation variable
  works: `KEYWARD_REASON="release cut" git commit -S -m …`
- **SSH authentication** goes through `ssh`, which exposes nothing, so a
  per-invocation variable is invisible. Use channel 2 for those.
- Either way the daemon falls back to the nearest readable ancestor, which is
  usually the agent itself — that is where `CLAUDE_CODE_HOST_SESSION_ID`,
  `CLAUDE_CODE_ENTRYPOINT` and W3C `BAGGAGE` come from, with no setup at all.

`KEYWARD_*` is the free-form namespace. Everything else is a strict allow-list
(`ENV_ALLOW` in `daemon/src/context.rs`) with a secret-shaped-name denylist on
top, because the same environment also holds `CLAUDE_CODE_OAUTH_TOKEN`. Widen
the allow-list deliberately, never by dumping the environment.

## Holding the key itself

Keyward can own a Secure Enclave key instead of proxying to Secretive:

```sh
keywardd --generate-key --policy sign-in    # or: presence, biometry, none
keywardd --pubkey                           # the authorized_keys line
```

The private scalar is generated inside the SEP and never leaves it. What lands
on disk (`enclave-key.blob`, mode 600) is a SEP-wrapped handle that is inert on
any other machine.

**Why bother, when Secretive already does this.** Because the agent that
performs the signature is the one that writes the authentication prompt. A
proxy in front of Secretive makes this strictly worse — Secretive sees
`keywardd` as its peer and says *"a request from launchd"*. Keyward knows what
the request is for, so the prompt reads:

> Sign the commit “Read agent context from env, sidecar and repo” in keyward — requested by Ghostty

`--policy` decides what each signature costs:

| policy | the enclave asks | signs while the screen is locked | survives a fingerprint change |
|---|---|---|---|
| `sign-in` | Touch ID, password fallback, once per sign-in | no | yes |
| `none` | never | yes | yes |
| `presence` | Touch ID, password fallback, again about every ten minutes | no | yes |
| `biometry` | Touch ID only, again about every ten minutes | no | **no — the key is destroyed** |

The daemon asks on its own as well: a request that arrives with no live sign-in (below) raises Touch ID whatever the key's policy. `"require_approval": false` in the config turns that off, and with a `none` key nothing asks at all, so agents can push while you are away. A `presence` or `biometry` key is created usable only while the Mac is unlocked, and refuses every signature on a locked screen with `-25308`; a `none` key is created usable after the first unlock, because unattended signing is what it is for.

### The trade-off, stated plainly

Secretive's key is bound to the SEP *and* to Secretive's team identity via the
keychain, so another program cannot use it even with full file access. Keyward's
handle is bound to the SEP only, because the keychain route needs an Apple
signing certificate. Anything running as you that can read the blob can ask the
enclave to sign — which is why `sign-in`, `presence` or `biometry` matters: with
those the enclave wants a Touch ID first.

It does not have to be a Touch ID that Keyward asked for. A program with a copy of
the blob can raise a sheet of its own, under any text it likes. (macOS also lets an
app ask to reuse a Touch ID unlock of the Mac for up to five minutes,
`touchIDAuthenticationAllowableReuseDuration`; whether that gets past an enclave
key's own check with no sheet at all has not been established here.) What one Touch
ID buys depends on the key: about ten minutes of signatures from a `presence` or
`biometry` key, and from a `sign-in` key the secret it signs for, which is good for
as long as the key exists. None of it passes through Keyward, so none of it is in the
log.

It remains far stronger than an on-disk private key. The key cannot be stolen;
an attacker has to stay resident on this Mac.

With a signing certificate, the keychain route is open here too: set
`"enclave_key": "keychain"` in the config before `--generate-key`, and the handle is
stored in the login keychain as an item only keywardd's own code signature can read
without a prompt. That is the setting that makes a `none` key reasonable: nothing gets
to the key except through the daemon, so the daemon's sign-in (below) is the gate. It
closes the gap above for the other kinds as well, because no other program has the
blob to ask with.

### There is no backup

An enclave key cannot be exported, copied or escrowed. If this machine is lost,
so is the key. Authorise a second, non-enclave key for recovery *before* you
depend on this one, and keep the old key in `allowed_signers` forever or
previously signed commits stop verifying.

`--generate-key` refuses to overwrite an existing handle for the same reason.

### Why there is Swift in a Rust daemon

Apple exposes Secure Enclave key *persistence* only through CryptoKit, which is
Swift-only. Everything reachable from C was tried: `SecKeyCreateRandomKey` with
`kSecAttrIsPermanent: true` needs a keychain entitlement (`errSecMissingEntitlement`,
and an ad-hoc signature carrying one gets the process killed), while a
non-permanent key cannot be exported — `SecKeyCopyExternalRepresentation`
returns "export not implemented for key". The `toid` attribute is the right size
(324 bytes) but feeding it back to `SecKeyCreateWithData` **silently generates a
different key**, which signs successfully and is therefore easy to mistake for
success. Check the public key, not the error code.

So `kwse.swift` is compiled to a static archive by `build.rs` and linked into the
daemon. There is no second process and no shipped dylib —
the Swift runtime lives in `/usr/lib/swift` on every macOS.

## The authentication prompt

macOS draws it in a ~260pt-wide panel, and it is a protected surface that
`screencapture` refuses, so it has to be legible without being seen first.
The reason string is therefore short (56 chars max), stripped of quotes,
backticks and newlines, and never carries the remote command — arbitrary shell
text was the single worst thing to read there. The command, the commit message
and the process chain all live in the app instead.

```
SSH to root@server.example · Ghostty
Sign a commit in nixos-config · Claude
git push to owner/repo · Ghostty
```

## Signing in

Keyward's own check asks once every six hours. The first request for its own key raises Touch ID, and that
sign-in covers every signature with that key for the next six hours — any repository,
any host, any agent — so work spread across a dozen checkouts costs one prompt rather
than one per place. The sheet names the grant before the request that happened to
raise it, and the card's first row says the same:

```
Sign in for 6 hours · git push to owner/repo
```

A `sign-in` key's sign-in also ends when the screen locks. Its sheet says that
instead, `Sign in until screen lock · git push to owner/repo`, and the card says both.

A key held by an upstream agent is that agent's to guard, and prompts the way it
always did.

`sign_in_secs` (config, 21600 by default) sets how long it lasts. The time runs from
the sign-in itself, on a clock that keeps counting while the Mac sleeps, and the
signatures that ride it do not extend it. The first request after it runs out signs in
again.

While it lasts nothing asks: anything that can reach the socket gets its signature,
which is every process running as you and any host the agent was forwarded to. Each
one is still logged with the place it came from. On an event, `sign_in` marks a
request made under a sign-in, and `reused` says whether it rode one or was the request
that asked. The sign-in lives in the daemon's memory, so restarting the daemon signs
out:

```sh
launchctl kickstart -k "gui/$(id -u)/dev.danielsol.keyward.agent"
```

It is the daemon's own check, so `"require_approval": false` leaves nothing to sign in
to. Underneath, for a `none`, `presence` or `biometry` key, it is one `LAContext`,
authenticated explicitly and held for as long as the sign-in lasts; a `sign-in` key
holds a secret instead (below). Signing in always asks: macOS can let a Touch ID unlock of the Mac
in the last five minutes answer a prompt without showing it
(`touchIDAuthenticationAllowableReuseDuration`), and a sign-in does not use that.
`sheet_reason` in the config replaces the request on the sheet, never the sign-in.

**A `presence` or `biometry` key is still asked for about every ten minutes.** The
enclave guards those keys itself, and it accepts one authentication for about ten
minutes however long the daemon holds the context. The first signature after that
raises the enclave's own prompt, which names that request and says nothing of a
sign-in, and the event is logged as `reused` because the daemon did not ask. Measured
on macOS 26.6: signatures 9m47s and 8m00s after an authentication were silent, ones
11m41s and 10m09s after were asked, and the silent signatures in between did not
extend it. A `none` key gets one prompt per sign-in, because nothing but the daemon guards
it. A `sign-in` key gets one and keeps the enclave's guard.

### The sign-in key

`--policy sign-in` makes two enclave keys and keeps them in one handle.

- The **signing key** has no Touch ID requirement. Instead the enclave uses it only
  for a caller that presents a secret.
- The **unlock key** does require Touch ID, and all it ever does is reproduce that
  secret, by key agreement with a pair whose private half was thrown away when the key
  was made.

Signing in is one Touch ID on the unlock key. The daemon holds the secret it releases,
in memory, and every signature after that presents it. Nothing is re-authenticated, so
there is no ten minutes to run out. `--generate-key` signs in once with the new key
before it keeps it, so making one costs a Touch ID: a key that could never be opened is
found out there, and not after it has been authorised everywhere.

**The secret is the same for as long as the key exists.** A copy of the handle signs
nothing by itself: the signing key refuses without the secret, and the secret leaves
the enclave only behind a Touch ID. But whoever gets that one Touch ID has the secret
for good, where a `presence` key would have given them ten minutes, and nothing takes
it back short of making a new key. The trade-off above says how a program on this Mac
can come by one. `build.sh` signs the daemon with the hardened runtime, so that a
debugger cannot attach and read the secret out of it while somebody is signed in.

**A sign-in key's sign-in ends when the screen locks**, as well as after
`sign_in_secs`, and nothing is signed while it is locked. The daemon looks at the
screen once a second, and again before and after every signature. On anything but an
unlocked screen at the console it drops the secret and refuses without raising a
sheet, and a signature already made when the lock arrived is thrown away. Three
seconds or more between two looks means the Mac slept, and that signs out as well,
because a lock can hide in a sleep. What can go unseen is a lock undone inside the
second between two looks, with no request during it. The first request after unlocking signs in again,
and its sheet reads `Sign in until screen lock · …`. Both keys are also created usable
only while the Mac is unlocked, so the enclave refuses on its own account too.

`keywardd.log` gets a line whenever the screen changes and whenever somebody is signed
out. A refused request's event says which it was: `screen locked`, `not at the
console`, `screen state unreadable`, or `signed out while signing` when the sign-out
landed under the Touch ID sheet.

A config that fails to parse runs on the defaults without the sign-in, asking for
every signature, so a typo cannot turn into a six-hour grant.

### Approving place by place instead

`"sign_in_secs": 0` turns the sign-in off, and each place is approved on its own.
`touch_id_reuse_secs` (0 = every signature; it does nothing while there is a sign-in)
then holds one authenticated context per place for that long, so a loop over the fleet
asks once instead of once per host. The window is scoped: it covers requests from the
same directory, to the same host and remote as the approval, and anything else prompts. Each place keeps its own window, so
agents working in several repositories at once do not reset one another, and a linked
worktree counts as the clone it came from. Here a Touch ID unlock within the window,
up to macOS's five minutes, can stand in for the prompt.

## Never overwrite the daemon in place

`build.sh` writes `.keywardd.new`, signs it, and renames over the target.
Copying onto a running binary keeps the inode, so the kernel finds pages that
no longer match the cached signature and kills the process with
`CODESIGNING / "Invalid Page"` — and every later exec of that path with it. The
symptom is `Permission denied (publickey)` everywhere, because the agent is
simply gone.

## Install

Building from source is the recommended path, and needs nothing but the Xcode
command line tools plus Rust:

```sh
./build.sh      # daemon + app, daemon embedded in the bundle
./install.sh    # copy to ~/Applications and let it register its agents
```

A DMG is attached to each release. It is **ad-hoc signed and not notarised**,
because Gatekeeper only trusts a Developer ID certificate plus notarisation and
both require the paid Apple Developer Program. macOS will refuse to open it
until the quarantine attribute is cleared:

```sh
xattr -dr com.apple.quarantine /Applications/Keyward.app
```

If that trade is not one you want to make, build it yourself — the toolchain is
the same either way.

Requires macOS 15+ on Apple Silicon; the Secure Enclave key has nowhere to live
otherwise.

### First run

```sh
keywardd --generate-key --policy sign-in    # once; cannot be undone or backed up
keywardd --pubkey                           # authorise this on your servers
```

Then point ssh at it — `IdentityAgent ~/.ssh/keyward.sock` — and keep an
existing key authorised until you have confirmed the new one works.

The daemon ships **inside** `Keyward.app/Contents/MacOS/keywardd`, so the app is
the whole product: one thing to move, one path for launchd, and no dependency
on a checkout that could be cleaned or relocated out from under SSH.

On launch the app writes `dev.danielsol.keyward.agent` into
`~/Library/LaunchAgents`, pointing at the bundle it is running from, and reloads
it only when the contents actually change. Move the app and the next launch
repairs the path by itself. It is the only login item: the daemon is its own
watchdog, and a `.watchdog` agent left by an older build is removed.

`keywardd` is also reachable directly for `--health`, `--pubkey` and
`--generate-key`; `dist/keywardd` is a symlink to the copy inside the bundle.

### What nix owns, and what it deliberately does not

The nix-darwin flake configures Keyward — `IdentityAgent`, `SSH_AUTH_SOCK`,
`~/.config/keyward/config.json` — and installs the built bundle into
`~/Applications` from an activation script. It does **not** declare the launchd
agent. A path baked into the flake pointed into a git checkout, so a clean or a
move would have left SSH with no agent at all; the app owning its own
registration keeps the running daemon and its path in the same place.

Building it in the nix sandbox is not possible: it links a Swift shim that needs
Xcode. The activation script copies whatever `./build.sh` produced and does
nothing when there is no build to copy.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
