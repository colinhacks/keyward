#!/bin/sh
# Put Keyward somewhere stable and let it register its own launchd agents.
#
# The daemon must not live in a checkout: a clean, a rebase, or moving the repo
# would leave SSH with no agent at all. /Applications is the stable path.
set -e
root="$(cd "$(dirname "$0")" && pwd)"
src="$root/dist/Keyward.app"
dst="$HOME/Applications/Keyward.app"

[ -d "$src" ] || { echo "build it first: ./build.sh"; exit 1; }

mkdir -p "$HOME/Applications"
echo "==> installing to $dst"
# Never rsync over a running bundle in place — same signature-invalidation trap
# as the daemon. Stage beside it and swap.
rm -rf "$dst.new"
cp -R "$src" "$dst.new"
if [ -d "$dst" ]; then
  rm -rf "$dst.old"
  mv "$dst" "$dst.old"
fi
mv "$dst.new" "$dst"
rm -rf "$dst.old"

# `open` on a running app is a no-op, so an upgrade would keep the old process alive.
osascript -e 'tell application "Keyward" to quit' >/dev/null 2>&1 && sleep 1
echo "==> launching in the background (it installs its own LaunchAgents on first run)"
open -g "$dst"
# A daemon whose binary was swapped underneath it fails every Secure Enclave
# operation at once: LocalAuthentication checks the caller's code signature
# against the file on disk. Restart it so the running process is the new file.
launchctl kickstart -k "gui/$(id -u)/dev.danielsol.keyward.agent" 2>/dev/null || true
sleep 3
"$dst/Contents/MacOS/keywardd" --health || \
  echo "    not answering yet — launchd retries a blocked socket every 10s"
