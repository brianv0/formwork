#!/bin/bash
# Temporary: characterize Seatbelt behaviour on a hosted runner. Removed before merge.
set +e
D=$(cd "$(dirname "$0")" && pwd)
W=/tmp/fwprobe; rm -rf $W; mkdir -p $W; cd $W
t() { perl -e 'alarm shift; exec @ARGV' "$@"; }
sb() { local prof="$1"; shift; t 30 sandbox-exec -p "$prof" "$@"; }
h() { echo; echo "=================== $* ==================="; }
logs() { sleep 4; log show --last "${1:-30s}" --style compact --predicate 'sender == "Sandbox" OR eventMessage CONTAINS "Sandbox:"' 2>/dev/null | grep -v '^Timestamp' | grep -E "$2" | sed -E 's/^.*Sandbox: //' | sort | uniq -c | head -${3:-60}; }
PY=$(command -v python3)
GO=$(ls -d /Users/runner/hostedtoolcache/go/*/arm64/bin/go 2>/dev/null | tail -1)
sw_vers -productVersion; echo "GO=$GO"; ls /Users/runner/hostedtoolcache 2>/dev/null | tr '\n' ' '; echo
cc -o $W/peer $D/peer.c && cc -o $W/procargs $D/procargs.c || echo "CC FAILED"

h "C6 target forms with a sibling in another process group"
perl -e 'setpgrp(0,0); exec "sleep", "60"' & SIB=$!
sleep 0.3; echo "sibling $SIB pgid $(ps -o pgid= -p $SIB) mine $(ps -o pgid= -p $$)"
for tgt in self children pgrp others same-sandbox descendants; do
  printf 'compile (target %s) => ' $tgt; sb "(version 1)(allow default)(allow signal (target $tgt))" /usr/bin/true 2>&1 | head -1; [ ${PIPESTATUS[0]} -eq 0 ] && echo ok
done
ISO='(version 1)(allow default)(deny process-info* (target others))(allow process-info* (target children))(allow process-info* (target pgrp))(deny signal (target others))(allow signal (target children))(allow signal (target pgrp))'
printf 'kill -0 other-pgrp sibling => '; sb "$ISO" /bin/sh -c "kill -0 $SIB 2>/dev/null && echo SIGNALABLE || echo refused"
printf 'lsof other-pgrp sibling => '; sb "$ISO" /bin/sh -c "lsof -p $SIB >/dev/null 2>&1 && echo VISIBLE || echo refused"
printf 'procargs other-pgrp sibling => '; sb "$ISO" $W/procargs $SIB
printf 'kill -0 parent (formwork stand-in) => '; sb "$ISO" /bin/sh -c 'kill -0 $PPID 2>/dev/null && echo SIGNALABLE || echo refused'
SS='(version 1)(allow default)(deny process-info* (target others))(allow process-info* (target same-sandbox))(deny signal (target others))(allow signal (target same-sandbox))'
printf 'same-sandbox: kill -0 sibling => '; sb "$SS" /bin/sh -c "kill -0 $SIB 2>/dev/null && echo SIGNALABLE || echo refused"
printf 'same-sandbox: kill -0 parent => '; sb "$SS" /bin/sh -c 'kill -0 $PPID 2>/dev/null && echo SIGNALABLE || echo refused'
printf 'same-sandbox: job control => '; sb "$SS" /bin/bash -c 'set -m; sleep 5 & kill -TERM %1; wait; echo ok'
printf 'same-sandbox: reparented grandchild => '; sb "$SS" /bin/sh -c '(perl -e "setpgrp(0,0); sleep 5" & echo $! > gc) ; sleep 0.3; kill $(cat gc) && echo ok'
printf 'same-sandbox: setsid child => '; sb "$SS" $PY -c '
import os,signal,subprocess,time
p=subprocess.Popen(["sleep","5"],start_new_session=True); time.sleep(0.2); os.kill(p.pid,signal.SIGTERM); print("rc",p.wait())'
cat > $W/mp.py <<'PYS'
import multiprocessing as mp
def f(x): return x*x
if __name__ == "__main__":
    with mp.Pool(2) as p: print("ok", sum(p.map(f, range(10))))
PYS
printf 'same-sandbox: python multiprocessing => '; sb "$SS" $PY $W/mp.py 2>&1 | tail -1
printf 'same-sandbox: node child_process => '; sb "$SS" node -e 'const c=require("child_process");const p=c.spawn("sleep",["5"]);setTimeout(()=>p.kill(),200);p.on("exit",(code,s)=>console.log("exit",s))'
mkdir -p mk; printf 'all: a b c\na:\n\tsleep 0.2\nb:\n\tsleep 0.2\nc:\n\tsleep 0.2\n' > mk/Makefile
printf 'same-sandbox: make -j3 => '; sb "$SS" make -s -j3 -C mk && echo ok
printf 'same-sandbox: lsof sibling => '; sb "$SS" /bin/sh -c "lsof -p $SIB >/dev/null 2>&1 && echo VISIBLE || echo refused"
printf 'same-sandbox: procargs sibling => '; sb "$SS" $W/procargs $SIB
printf 'same-sandbox: procargs self-child => '; sb "$SS" /bin/sh -c "FW_CANARY=x sleep 2 & $W/procargs \$!"
logs 40s 'deny' 30
kill $SIB

h "C5 procargs2 from a non-setuid reader"
FW_CANARY=canary-77 sleep 60 & SIB=$!; sleep 0.3
printf 'control => '; $W/procargs $SIB
printf 'deny kern.procargs2 => '; sb '(version 1)(allow default)(deny sysctl-read (sysctl-name "kern.procargs2"))' $W/procargs $SIB
sb '(version 1)(allow default)(allow sysctl-read (with report))' $W/procargs $SIB >/dev/null
logs 15s 'sysctl' 10
kill $SIB

h "launchctl submit control and confined"
rm -f /tmp/fwprobe-marker
t 20 launchctl submit -l dev.formwork.ctl -- /bin/sh -c 'echo launchd >> /tmp/fwprobe-marker'; echo "control rc $?"; sleep 2; launchctl remove dev.formwork.ctl; echo "marker: $(cat /tmp/fwprobe-marker 2>&1)"; rm -f /tmp/fwprobe-marker
sb '(version 1)(allow default)' launchctl submit -l dev.formwork.sb -- /bin/sh -c 'echo launchd >> /tmp/fwprobe-marker'; echo "allow-default rc $?"; sleep 2; launchctl remove dev.formwork.sb 2>/dev/null; echo "marker: $(cat /tmp/fwprobe-marker 2>&1)"; rm -f /tmp/fwprobe-marker
sb '(version 1)(allow default)' launchctl load -w /dev/null 2>&1 | head -2
printf 'launchctl bootstrap gui => '; cat > $W/job.plist <<PL
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>dev.formwork.boot</string><key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>echo boot &gt;&gt; /tmp/fwprobe-marker</string></array><key>RunAtLoad</key><true/></dict></plist>
PL
sb '(version 1)(allow default)' launchctl bootstrap gui/$(id -u) $W/job.plist; echo "rc $?"; sleep 2; launchctl bootout gui/$(id -u)/dev.formwork.boot 2>/dev/null; echo "marker: $(cat /tmp/fwprobe-marker 2>&1)"; rm -f /tmp/fwprobe-marker
t 20 launchctl bootstrap gui/$(id -u) $W/job.plist; echo "control bootstrap rc $?"; sleep 2; launchctl bootout gui/$(id -u)/dev.formwork.boot 2>/dev/null; echo "marker: $(cat /tmp/fwprobe-marker 2>&1)"; rm -f /tmp/fwprobe-marker
logs 30s 'launchctl|job' 10

h "AppleEvents: applet fixture"
osacompile -s -o $W/FwApplet.app -e 'on fwmark()' -e 'do shell script "echo applet >> /tmp/fwprobe-marker"' -e 'return "marked"' -e 'end fwmark' -e 'on idle' -e 'return 30' -e 'end idle' && echo compiled
t 20 open -g $W/FwApplet.app; sleep 3; pgrep -fl FwApplet | head -2
printf 'control AE => '; t 20 osascript -e "tell application \"$W/FwApplet.app\" to fwmark()" 2>&1; sleep 1; echo "marker: $(cat /tmp/fwprobe-marker 2>&1)"; rm -f /tmp/fwprobe-marker
printf 'allow-default AE => '; sb '(version 1)(allow default)' osascript -e "tell application \"$W/FwApplet.app\" to fwmark()" 2>&1; sleep 1; echo "marker: $(cat /tmp/fwprobe-marker 2>&1)"; rm -f /tmp/fwprobe-marker
printf 'deny appleevent-send AE => '; sb '(version 1)(allow default)(deny appleevent-send)' osascript -e "tell application \"$W/FwApplet.app\" to fwmark()" 2>&1; sleep 1; echo "marker: $(cat /tmp/fwprobe-marker 2>&1)"; rm -f /tmp/fwprobe-marker
printf 'deny AE mach name only => '; sb '(version 1)(allow default)(deny mach-lookup (global-name "com.apple.coreservices.appleevents"))' osascript -e "tell application \"$W/FwApplet.app\" to fwmark()" 2>&1; sleep 1; echo "marker: $(cat /tmp/fwprobe-marker 2>&1)"; rm -f /tmp/fwprobe-marker
printf 'System Events control => '; t 20 osascript -e 'tell application "System Events" to get name of first process' 2>&1
sb '(version 1)(allow default)(allow mach-lookup (with report))(allow appleevent-send (with report))' osascript -e "tell application \"$W/FwApplet.app\" to fwmark()" >/dev/null 2>&1
logs 40s 'appleevent|osascript' 30
osascript -e "tell application \"$W/FwApplet.app\" to quit" 2>/dev/null

h "screen capture under service denies"
for prof in '(deny mach-lookup (global-name-regex #"^com\.apple\.(screencapture|replayd)"))' \
            '(deny mach-lookup (global-name "com.apple.windowserver.active"))' \
            '(deny mach-lookup (global-name "com.apple.windowserver.active") (global-name "com.apple.CARenderServer") (global-name-regex #"^com\.apple\.(screencapture|replayd)"))'; do
  rm -f $W/shot.png; sb "(version 1)(allow default)$prof" screencapture -x $W/shot.png 2>&1 | head -2; echo "rc ${PIPESTATUS[0]} file: $(ls $W/shot.png 2>/dev/null || echo none)"
done
WS='(version 1)(allow default)(deny mach-lookup (global-name "com.apple.windowserver.active") (global-name "com.apple.CARenderServer"))'
for c in "git --version" "$PY -c print(1)" "node -e 1" "swift --version" "cargo --version" "gh --version" "brew --version" "open -g $W/FwApplet.app"; do sb "$WS" $c >/dev/null 2>&1; echo "under windowserver deny: $c rc $?"; done

h "securityd deny vs TLS clients"
KS='(version 1)(allow default)(deny mach-lookup (global-name "com.apple.SecurityServer"))'
security create-keychain -p pw $W/fw.keychain; security add-generic-password -s fw-svc -a fw -w keychain-secret $W/fw.keychain
printf 'keychain item => '; sb "$KS" security find-generic-password -s fw-svc -w $W/fw.keychain 2>&1
printf 'login keychain list => '; sb "$KS" security list-keychains 2>&1 | head -2
for c in "/usr/bin/curl -sS -o /dev/null -w %{http_code} https://example.com" "git ls-remote https://github.com/octocat/Hello-World HEAD" "$PY -c import\ urllib.request;print(urllib.request.urlopen('https://example.com').status)" "node -e fetch('https://example.com').then(r=>console.log(r.status))" "gh api /zen" "$GO version"; do
  printf '%s => ' "$c"; sb "$KS" $c 2>&1 | tail -1
done
cat > $W/get.swift <<'SW'
import Foundation
let s = DispatchSemaphore(value: 0)
URLSession.shared.dataTask(with: URL(string: CommandLine.arguments[1])!) { _, r, e in
  print((r as? HTTPURLResponse)?.statusCode ?? -1, e?.localizedDescription ?? ""); s.signal() }.resume()
s.wait()
SW
t 120 swiftc -O -o $W/swiftget $W/get.swift && echo "swiftget built"
printf 'swift URLSession control => '; t 20 $W/swiftget https://example.com
printf 'swift URLSession securityd deny => '; sb "$KS" $W/swiftget https://example.com
if [ -n "$GO" ]; then
cat > $W/get.go <<'GOS'
package main
import ("fmt";"net/http";"os")
func main(){ r,err:=http.Get(os.Args[1]); if err!=nil {fmt.Println("err",err); os.Exit(1)}; fmt.Println(r.StatusCode)}
GOS
(cd $W && t 120 $GO build -o goget get.go) && echo "goget built"
printf 'go control => '; t 20 $W/goget https://example.com
printf 'go securityd deny => '; sb "$KS" $W/goget https://example.com
fi
logs 60s 'SecurityServer|trustd' 20

h "iokit deny vs toolchains"
IOD='(version 1)(allow default)(deny iokit-open)'
printf 'compile iokit-open deny => '; sb "$IOD" /usr/bin/true && echo ok
mkdir -p $W/swpkg/Sources/hello && printf '// swift-tools-version:5.9\nimport PackageDescription\nlet package = Package(name: "hello", targets: [.executableTarget(name: "hello")])\n' > $W/swpkg/Package.swift && echo 'print("hi")' > $W/swpkg/Sources/hello/main.swift
mkdir -p $W/rspkg/src && printf '[package]\nname="hello"\nversion="0.1.0"\nedition="2021"\n' > $W/rspkg/Cargo.toml && echo 'fn main(){println!("hi");}' > $W/rspkg/src/main.rs
for c in "git --version" "$PY -c print(1)" "node -e 1" "cc -o $W/a.out -x c /dev/null -Wl,-undefined,dynamic_lookup -nostartfiles -c" "swift build --package-path $W/swpkg" "cargo build --manifest-path $W/rspkg/Cargo.toml" "gh --version" "brew --version" "/usr/bin/curl -sI https://example.com" "xcrun --show-sdk-path" "caffeinate -t 1" "$W/swiftget https://example.com" "pbcopy </dev/null" "screencapture -x $W/io.png"; do
  sb "$IOD" $c >/dev/null 2>&1; echo "iokit deny: $c rc $?"
done
logs 120s 'iokit' 40

h "wildcard bind inbound from the LAN address"
LAN=$(ipconfig getifaddr en0 || ipconfig getifaddr en1); echo "LAN=$LAN"
P='(version 1)(allow default)(deny network*)(allow network-bind (local ip "localhost:*"))(allow network-inbound (local ip "localhost:*"))'
rm -f port; sb "$P" $PY -c '
import socket
s=socket.socket(); s.bind(("0.0.0.0",0)); s.listen(1); open("port","w").write(str(s.getsockname()[1])); s.settimeout(8)
try:
  c,a=s.accept(); print("accepted from", a, c.recv(64))
except Exception as e: print("accept:", e)' & SB=$!
for i in 1 2 3 4 5 6 7 8 9 10; do [ -s port ] && break; sleep 0.3; done
$PY -c "import socket;c=socket.create_connection(('$LAN',int(open('port').read())),timeout=5);c.sendall(b'lan-nonce');print('client sent')" 2>&1; wait $SB
logs 20s 'network' 10

h "peer check"
$W/peer
MARK='(version 1)(allow default)(deny file-read* (literal "/private/var/empty/fw-abc/a"))(allow file-read* (literal "/private/var/empty/fw-abc/b"))'
$PY -c 'import socket,time;s=socket.socket();s.bind(("127.0.0.1",18090));s.listen(9);time.sleep(30)' & L=$!
sleep 0.5
sb "$MARK" $PY -c 'import socket,time;c=socket.create_connection(("127.0.0.1",18090));time.sleep(15)' & M=$!
$PY -c 'import socket,time;c=socket.create_connection(("127.0.0.1",18090));time.sleep(15)' & U=$!
sb '(version 1)(deny default)(allow process*)(allow file-read*)(allow network*)(allow sysctl-read)(allow mach-lookup)(allow file-ioctl)(allow file-write-data (literal "/dev/null"))' $PY -c 'import socket,time;c=socket.create_connection(("127.0.0.1",18090));time.sleep(15)' & DD=$!
sb '(version 1)(allow default)' $PY -c 'import socket,time;c=socket.create_connection(("127.0.0.1",18090));time.sleep(15)' & AD=$!
sleep 2
for p in $M $U $DD $AD; do echo "--- pid $p: $(ps -o command= -p $p | cut -c1-70)"; $W/peer $p /private/var/empty/fw-abc/a /private/var/empty/fw-abc/b | grep -v '^sizeof\|^off\|^SOCK\|^SANDBOX'; done
printf 'peer check from inside a sandbox => '; sb '(version 1)(allow default)(deny file-read* (literal "/x"))' $W/peer $M /private/var/empty/fw-abc/a | grep 'sandbox_check' | head -1
logs 30s 'fw-abc' 10
kill $L $M $U $DD $AD 2>/dev/null
echo done
