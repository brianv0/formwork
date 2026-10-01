#!/bin/bash
# Temporary: characterize Seatbelt behaviour on a hosted runner. Removed before merge.
set +e
W=/tmp/fwprobe; rm -rf $W; mkdir -p $W; cd $W
t() { perl -e 'alarm shift; exec @ARGV' "$@"; }
sb() { local prof="$1"; shift; t 60 sandbox-exec -p "$prof" "$@"; }
h() { echo; echo "=================== $* ==================="; }
logs() { sleep 4; log show --last "${1:-30s}" --style compact --predicate 'sender == "Sandbox" OR eventMessage CONTAINS "Sandbox:"' 2>/dev/null | grep -v '^Timestamp' | grep -E "$2" | sed -E 's/^.*Sandbox: //' | sort | uniq -c | head -${3:-60}; }
sw_vers -productVersion

h "deny-record tagging"
for p in '(version 1)(allow default)(deny file-read* (literal "/private/etc/hosts") (with message "fw-tag-1"))' \
         '(version 1)(allow default)(deny file-read* (with message "fw-tag-2") (literal "/private/etc/hosts"))' \
         '(version 1)(allow default)(deny mach-lookup (with message "fw-tag-3") (global-name "com.apple.pasteboard.1"))' \
         '(version 1)(allow default)(deny file-read-data (with message "fw-tag-4"))(allow file-read-data (subpath "/System") (subpath "/usr") (subpath "/bin") (subpath "/private/var/db") (subpath "/Library") (subpath "/dev"))'; do
  printf 'compile => '; sb "$p" /usr/bin/true 2>&1 | head -2; echo
  sb "$p" /bin/cat /etc/hosts >/dev/null 2>&1; echo x | sb "$p" pbcopy 2>/dev/null
done
logs 30s 'fw-tag|hosts|pasteboard' 20
log show --last 40s --style ndjson --predicate 'sender == "Sandbox"' 2>/dev/null | grep -m3 'fw-tag' | cut -c1-1500

h "C9 Claude Code"
t 240 npm install -g @anthropic-ai/claude-code >/dev/null 2>&1; echo "install rc $?"; command -v claude
mkdir -p $W/home/.claude
P='(version 1)(allow default)(deny mach-lookup (global-name "com.apple.SecurityServer") (global-name "com.apple.securityd"))(deny lsopen)(deny appleevent-send)(allow mach-lookup (with report) (global-name-regex #"^com\.apple\.(security|Security|lsd|coreservices)"))'
printf 'version => '; HOME=$W/home sb "$P" claude --version 2>&1 | tail -2
printf 'prompt => '; HOME=$W/home ANTHROPIC_API_KEY= sb "$P" claude -p hi 2>&1 | tail -3
printf 'unconfined security calls: '; HOME=$W/home t 30 claude -p hi 2>&1 | tail -2
logs 120s 'claude|node|security|lsopen' 40
echo done
