#!/bin/bash
# Temporary: characterize Seatbelt behaviour on a hosted runner. Removed before merge.
set +e
W=/tmp/fwprobe; rm -rf $W; mkdir -p $W; cd $W
t() { perl -e 'alarm shift; exec @ARGV' "$@"; }
sb() { local prof="$1"; shift; t 20 sandbox-exec -p "$prof" "$@"; }
h() { echo; echo "=================== $* ==================="; }
logs() { sleep 4; log show --last "${1:-30s}" --style compact --predicate 'sender == "Sandbox" OR eventMessage CONTAINS "Sandbox:"' 2>/dev/null | grep -v '^Timestamp' | grep -E "$2" | sed -E 's/^.*Sandbox: //' | sort | uniq -c | head -${3:-60}; }
PY=$(command -v python3)

h runner
sw_vers; uname -a; id; csrutil status; DevToolsSecurity -status 2>&1; launchctl managername
echo PY=$PY; for c in go swift node npm cargo rustup gh brew curl git uv pip3; do printf '%s: ' $c; (command -v $c && t 10 $c --version 2>&1 | head -1) | tr '\n' ' '; echo; done
ls /Applications | head -30

h "C1 remote filters"
for f in '"127.0.0.1:8080"' '"localhost:8080"' '"*:8080"' '"::1:8080"' '"localhost:*"'; do
  printf '%s => ' "$f"; sb "(version 1)(allow default)(deny network*)(allow network-outbound (remote tcp $f))" /usr/bin/true 2>&1 && echo ok
done
printf 'remote ip 127.0.0.1 => '; sb '(version 1)(allow default)(deny network*)(allow network-outbound (remote ip "127.0.0.1:8080"))' /usr/bin/true 2>&1 && echo ok
# Does localhost:P admit a connect to 127.0.0.1:P and [::1]:P?
$PY -c 'import socket,time;s=socket.socket();s.bind(("127.0.0.1",18080));s.listen(9);s6=socket.socket(socket.AF_INET6);s6.bind(("::1",18080));s6.listen(9);time.sleep(30)' & SRV=$!
sleep 1
for a in 127.0.0.1 ::1 127.0.0.2; do printf 'connect %s:18080 under localhost:18080 => ' $a; sb '(version 1)(allow default)(deny network*)(allow network-outbound (remote tcp "localhost:18080"))' $PY -c "import socket,sys;fam=socket.AF_INET6 if ':' in '$a' else socket.AF_INET;s=socket.socket(fam);s.settimeout(2);s.connect(('$a',18080));print('connected')" 2>&1 | tail -1; done
printf 'connect 127.0.0.1:18081 (other port) => '; sb '(version 1)(allow default)(deny network*)(allow network-outbound (remote tcp "localhost:18080"))' $PY -c "import socket;s=socket.socket();s.settimeout(2);s.connect(('127.0.0.1',18081));print('connected')" 2>&1 | tail -1
kill $SRV

h "FW-E2E-091 loopback bind/accept under deny network + localhost bind/inbound"
P='(version 1)(allow default)(deny network*)(allow network-bind (local ip "localhost:*"))(allow network-inbound (local ip "localhost:*"))'
rm -f port; sb "$P" $PY -c '
import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(1); open("port","w").write(str(s.getsockname()[1]))
c,_=s.accept(); print("got", c.recv(64).decode())' & SB=$!
for i in 1 2 3 4 5 6 7 8 9 10; do [ -s port ] && break; sleep 0.3; done
$PY -c "import socket;c=socket.create_connection(('127.0.0.1',int(open('port').read())));c.sendall(b'nonce-42')"; wait $SB; echo "exit $?"
printf 'bind localhost name => '; sb "$P" $PY -c 'import socket;s=socket.socket();s.bind(("localhost",0));s.listen(1);print("bound",s.getsockname())' 2>&1 | tail -1
printf 'bind ::1 => '; sb "$P" $PY -c 'import socket;s=socket.socket(socket.AF_INET6);s.bind(("::1",0));s.listen(1);print("bound",s.getsockname())' 2>&1 | tail -1
printf 'bind 0.0.0.0 => '; sb "$P" $PY -c 'import socket;s=socket.socket();s.bind(("0.0.0.0",0));s.listen(1);print("bound",s.getsockname())' 2>&1 | tail -1

h "fixture app"
APP=$W/FwFixture.app; mkdir -p $APP/Contents/MacOS
cat > $APP/Contents/Info.plist <<PL
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleExecutable</key><string>fixture</string><key>CFBundleIdentifier</key><string>dev.formwork.fixture</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleName</key><string>FwFixture</string><key>LSUIElement</key><true/></dict></plist>
PL
printf '#!/bin/sh\necho "launched $$ $*" >> /tmp/fwprobe-marker\n' > $APP/Contents/MacOS/fixture; chmod +x $APP/Contents/MacOS/fixture
rm -f /tmp/fwprobe-marker; t 20 open -g -n $APP; sleep 2; echo "control open: $(cat /tmp/fwprobe-marker 2>&1)"

h "C3 mach-lookup names (allow with report)"
REP='(version 1)(allow default)(allow mach-lookup (with report))'
printf 'compile with-report => '; sb "$REP" /usr/bin/true && echo ok
rm -f /tmp/fwprobe-marker
echo nonce-clip | sb "$REP" pbcopy; echo "pbcopy rc $?"
sb "$REP" pbpaste; echo "pbpaste rc $?"
logs 20s 'pbcopy|pbpaste'
sb "$REP" open -g -n $APP; echo "open rc $?"; sleep 2; echo "marker: $(cat /tmp/fwprobe-marker 2>&1)"
logs 20s '\(.*open\(|open\[| open'
sb "$REP" launchctl submit -l dev.formwork.probe -- /bin/sh -c 'echo launchd >> /tmp/fwprobe-marker'; echo "launchctl rc $?"; sleep 2; launchctl remove dev.formwork.probe 2>/dev/null; echo "marker: $(cat /tmp/fwprobe-marker 2>&1)"
logs 20s 'launchctl'
sb "$REP" osascript -e 'tell application id "dev.formwork.fixture" to activate'; echo "osascript rc $?"; sleep 1
logs 20s 'osascript'
security create-keychain -p pw $W/fw.keychain; security add-generic-password -s fw-svc -a fw -w keychain-secret $W/fw.keychain
printf 'control keychain: '; security find-generic-password -s fw-svc -w $W/fw.keychain
sb "$REP" security find-generic-password -s fw-svc -w $W/fw.keychain; echo "security rc $?"
logs 20s 'security'
sb "$REP" screencapture -x $W/shot.png; echo "screencapture rc $? $(ls -la $W/shot.png 2>&1)"
logs 20s 'screencapture'

h "C3b deny-all mach-lookup, which names deny"
DEN='(version 1)(allow default)(deny mach-lookup)'
echo x | sb "$DEN" pbcopy; echo "pbcopy rc $?"; sb "$DEN" pbpaste; echo "pbpaste rc $?"
sb "$DEN" security find-generic-password -s fw-svc -w $W/fw.keychain; echo "security rc $?"
logs 20s 'deny' 80

h "C4 lsopen / appleevent under sandbox"
rm -f /tmp/fwprobe-marker
sb '(version 1)(allow default)' open -g -n $APP; echo "allow-default open rc $?"; sleep 2; echo "marker: $(cat /tmp/fwprobe-marker 2>&1)"; rm -f /tmp/fwprobe-marker
sb '(version 1)(allow default)(deny lsopen)' open -g -n $APP; echo "deny-lsopen open rc $?"; sleep 2; echo "marker: $(cat /tmp/fwprobe-marker 2>&1)"; rm -f /tmp/fwprobe-marker
sb '(version 1)(allow default)(deny lsopen)(deny appleevent-send)(deny mach-lookup (global-name "com.apple.coreservices.appleevents"))' osascript -e 'tell application id "dev.formwork.fixture" to activate'; echo "deny-ae osascript rc $?"; sleep 2; echo "marker: $(cat /tmp/fwprobe-marker 2>&1)"; rm -f /tmp/fwprobe-marker
t 20 osascript -e 'tell application id "dev.formwork.fixture" to activate'; echo "control osascript rc $?"; sleep 2; echo "marker: $(cat /tmp/fwprobe-marker 2>&1)"; rm -f /tmp/fwprobe-marker
sb '(version 1)(allow default)(deny lsopen)' launchctl submit -l dev.formwork.probe2 -- /bin/sh -c 'echo launchd >> /tmp/fwprobe-marker'; echo "launchctl under deny-lsopen rc $?"; sleep 2; launchctl remove dev.formwork.probe2 2>/dev/null; echo "marker: $(cat /tmp/fwprobe-marker 2>&1)"; rm -f /tmp/fwprobe-marker
logs 40s 'deny' 40

h "C5 procargs2"
FW_CANARY=canary-77 sleep 60 & SIB=$!
sleep 0.5
printf 'control ps -E: '; ps -E -p $SIB -o command= | grep -o 'FW_CANARY=[^ ]*' || echo "not shown"
printf 'confined ps -E: '; sb '(version 1)(allow default)(deny sysctl-read (sysctl-name "kern.procargs2"))' ps -E -p $SIB -o command= | grep -o 'FW_CANARY=[^ ]*' || echo "not shown"
printf 'confined ps -ww command: '; sb '(version 1)(allow default)(deny sysctl-read (sysctl-name "kern.procargs2"))' ps -ww -p $SIB -o command=
sb '(version 1)(allow default)(allow sysctl-read (with report))' ps -E -p $SIB -o command= >/dev/null
logs 20s 'sysctl' 40

h "C6 isolate processes target forms"
ISO='(version 1)(allow default)(deny process-info* (target others))(allow process-info* (target children))(allow process-info* (target pgrp))(deny signal (target others))(allow signal (target children))(allow signal (target pgrp))'
printf 'compile => '; sb "$ISO" /usr/bin/true && echo ok
printf 'kill -0 sibling => '; sb "$ISO" /bin/sh -c "kill -0 $SIB && echo SIGNALABLE || echo refused"
printf 'ps sibling => '; sb "$ISO" /bin/sh -c "ps -p $SIB -o pid= || echo hidden"
printf 'ps -ax count => '; sb "$ISO" /bin/sh -c 'ps -ax | wc -l'; printf 'control ps -ax count => '; ps -ax | wc -l
printf 'job control => '; sb "$ISO" /bin/sh -c 'sleep 0.2 & kill %1 2>/dev/null; wait; sleep 0.1 & wait $!; echo ok'
printf 'bash job control => '; sb "$ISO" /bin/bash -c 'set -m; sleep 5 & kill -TERM %1; wait; echo ok'
printf 'setsid child signal => '; sb "$ISO" $PY -c '
import os,signal,subprocess,time
p=subprocess.Popen(["sleep","5"],start_new_session=True); time.sleep(0.2); os.kill(p.pid,signal.SIGTERM); print("rc",p.wait())'
printf 'grandchild signal => '; sb "$ISO" /bin/sh -c 'sh -c "sleep 5 & echo \$! > gc; wait" & sleep 0.3; kill $(cat gc) && echo ok'
printf 'python multiprocessing => '; sb "$ISO" $PY -c '
import multiprocessing as mp
def f(x): return x*x
if __name__=="__main__":
    with mp.Pool(2) as p: print(sum(p.map(f, range(10))))'
printf 'node child_process => '; sb "$ISO" node -e 'const c=require("child_process");const p=c.spawn("sleep",["5"]);setTimeout(()=>{p.kill();},200);p.on("exit",(code,s)=>console.log("exit",s))'
mkdir -p mk; printf 'all: a b c\na:\n\tsleep 0.2\nb:\n\tsleep 0.2\nc:\n\tsleep 0.2\n' > mk/Makefile
printf 'make -j3 => '; sb "$ISO" make -s -j3 -C mk && echo ok
printf 'proc_pidinfo sibling (lsof) => '; sb "$ISO" /bin/sh -c "lsof -p $SIB >/dev/null 2>&1 && echo VISIBLE || echo refused"
logs 60s 'deny' 40
kill $SIB

h "C7 posix ipc prefix"
IPC='(version 1)(allow default)(deny ipc-posix*)(allow ipc-posix* (ipc-posix-name-prefix "/fw"))'
printf 'compile => '; sb "$IPC" /usr/bin/true && echo ok
printf 'shared_memory default name => '; sb "$IPC" $PY -c 'from multiprocessing import shared_memory as s; m=s.SharedMemory(create=True,size=16); print("ok",m.name); m.close(); m.unlink()' 2>&1 | tail -1
printf 'shared_memory /fw name => '; sb "$IPC" $PY -c 'from multiprocessing import shared_memory as s; m=s.SharedMemory(name="fwx",create=True,size=16); print("ok",m.name); m.close(); m.unlink()' 2>&1 | tail -1
printf 'mp Lock => '; sb "$IPC" $PY -c 'import multiprocessing as mp; l=mp.Lock(); print("ok")' 2>&1 | tail -1
printf 'sysv deny compile + ipcs => '; sb '(version 1)(allow default)(deny ipc-sysv*)' $PY -c 'print("ok")'
printf 'node worker => '; sb "$IPC" node -e 'const {Worker}=require("worker_threads");new Worker("process.exit(0)",{eval:true}).on("exit",c=>console.log("ok",c))'

h "C8 iokit with report"
IOK='(version 1)(allow default)(allow iokit-open (with report))'
printf 'compile => '; sb "$IOK" /usr/bin/true && echo ok
sb '(version 1)(allow default)(allow iokit-open-user-client (with report))' /usr/bin/true && echo "iokit-open-user-client ok"
sb '(version 1)(allow default)(allow iokit-open-service (with report))' /usr/bin/true && echo "iokit-open-service ok"
for c in "git --version" "$PY -c print(1)" "node -e 1" "swift --version" "cc --version" "go version" "cargo --version" "gh --version" "brew --version" "curl -sI https://example.com"; do sb "$IOK" $c >/dev/null 2>&1; echo "$c rc $?"; done
logs 90s 'iokit' 60

h "CRED16 PT_DENY_ATTACH"
cat > $W/deny.py <<PYS
import ctypes,sys,time,os
libc=ctypes.CDLL(None)
if sys.argv[1]=="deny": print("ptrace rc",libc.ptrace(31,0,None,0),flush=True)
time.sleep(40)
PYS
SECRET_TOKEN=sekrit-1 $PY $W/deny.py deny & D=$!
SECRET_TOKEN=sekrit-2 $PY $W/deny.py none & N=$!
sleep 1
printf 'ps -E denied proc: '; ps -E -p $D -o command= | grep -o 'SECRET_TOKEN=[^ ]*' || echo "not shown"
printf 'lldb attach to plain: '; t 30 lldb -p $N --batch -o 'detach' 2>&1 | grep -E 'Process .* stopped|attach failed|error' | head -2
printf 'lldb attach to denied: '; t 30 lldb -p $D --batch -o 'detach' 2>&1 | grep -E 'Process .* stopped|attach failed|error' | head -2
kill $D $N 2>/dev/null
echo done
