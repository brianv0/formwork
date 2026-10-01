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
sw_vers -productVersion
cc -o $W/peer $D/peer.c && cc -o $W/procargs $D/procargs.c && cc -o $W/confstr $D/confstr.c || echo "CC FAILED"

h "C5 which rule hides another process's environment"
perl -e 'setpgrp(0,0); exec "sleep", "90"' &
SIBP=$!; FW_CANARY=canary-77 perl -e 'setpgrp(0,0); exec "sleep", "90"' & SIB=$!; sleep 0.3
for r in '(deny process-info* (target others))' '(deny process-info-pidinfo (target others))' '(deny process-info-pidfdinfo (target others))' '(deny process-info-codesignature (target others))' '(deny process-info-listpids)' '(deny process-info-rusage (target others))' '(deny sysctl-read (sysctl-name "kern.procargs2"))' '(deny sysctl-read (sysctl-name-prefix "kern.procargs"))' '(deny sysctl-read (sysctl-name-prefix "kern.proc"))' '(deny process-info* (target others))(allow process-info-pidinfo (target others))'; do
  printf '%s => ' "$r"; sb "(version 1)(allow default)$r" $W/procargs $SIB 2>&1 | tail -1
done
printf 'with report: '; sb '(version 1)(allow default)(allow process-info* (with report))(allow sysctl-read (with report))' $W/procargs $SIB
logs 20s 'procargs' 20
NARROW='(version 1)(allow default)(deny process-info* (target others))(allow process-info* (target same-sandbox))'
printf 'narrow: kill -0 sibling => '; sb "$NARROW" /bin/sh -c "kill -0 $SIB 2>/dev/null && echo SIGNALABLE || echo refused"
printf 'narrow: pgrep sleep => '; sb "$NARROW" pgrep -l sleep 2>&1 | head -3; echo
printf 'narrow: node process.kill(sib,0) => '; sb "$NARROW" node -e "try{process.kill($SIB,0);console.log('alive')}catch(e){console.log(e.code)}"
printf 'narrow: python psutil-less os.kill(sib,0) => '; sb "$NARROW" $PY -c "import os;os.kill($SIB,0);print('alive')" 2>&1 | tail -1
kill $SIB $SIBP

h "signal to the unconfined parent"
cat > $W/parent.py <<'PYS'
import os, signal, subprocess, sys, time
got = []
signal.signal(signal.SIGUSR1, lambda *a: got.append(1))
p = subprocess.run(["sandbox-exec", "-p", sys.argv[1], "/bin/sh", "-c", "kill -USR1 $PPID; echo child-rc=$?"])
time.sleep(0.3)
print("parent received SIGUSR1:", bool(got))
PYS
for r in '(deny signal (target others))(allow signal (target same-sandbox))' '(deny signal)(allow signal (target self))'; do printf '%s => ' "$r"; $PY $W/parent.py "(version 1)(allow default)$r"; done
logs 15s 'signal' 5

h "session marker forms for sandbox_check"
mkdir -p $W/mark && touch $W/mark/a $W/mark/b
MP="(version 1)(allow default)(deny file-read* (literal \"$W/mark/a\"))(allow file-read* (literal \"$W/mark/b\"))(deny mach-lookup (global-name \"dev.formwork.mark-a\"))"
$PY -c 'import socket,time;s=socket.socket();s.bind(("127.0.0.1",18090));s.listen(9);time.sleep(40)' & L=$!
sleep 0.5
rm -f $W/pid-*
sandbox-exec -p "$MP" $PY -c "import os,socket,time;open('$W/pid-m','w').write(str(os.getpid()));c=socket.create_connection(('127.0.0.1',18090));time.sleep(20)" &
$PY -c "import os,socket,time;open('$W/pid-u','w').write(str(os.getpid()));c=socket.create_connection(('127.0.0.1',18090));time.sleep(20)" &
sandbox-exec -p '(version 1)(deny default)(allow process*)(allow file-read*)(allow file-write*)(allow network*)(allow sysctl-read)(allow mach-lookup)(allow file-ioctl)' $PY -c "import os,socket,time;open('$W/pid-d','w').write(str(os.getpid()));c=socket.create_connection(('127.0.0.1',18090));time.sleep(20)" &
sandbox-exec -p '(version 1)(allow default)' $PY -c "import os,socket,time;open('$W/pid-a','w').write(str(os.getpid()));c=socket.create_connection(('127.0.0.1',18090));time.sleep(20)" &
sleep 2
for k in m u d a; do p=$(cat $W/pid-$k); echo "--- $k pid $p"; $W/peer $p $W/mark/a $W/mark/b /nonexistent/x | grep -v '^sizeof\|^off\|^SOCK\|^SANDBOX'; done
logs 20s 'mark' 10
kill $L; wait 2>/dev/null

h "inbound filters"
listen() { # profile bindaddr connectaddr
  rm -f $W/port; sb "$1" $PY -c "
import socket
fam = socket.AF_INET6 if ':' in '$2' else socket.AF_INET
s=socket.socket(fam); s.bind(('$2',0)); s.listen(1); open('$W/port','w').write(str(s.getsockname()[1])); s.settimeout(5)
try:
  c,a=s.accept(); print('accepted', a[0], c.recv(16))
except Exception as e: print('accept:', type(e).__name__, e)" 2>&1 | tail -1 & local S=$!
  for i in $(seq 20); do [ -s $W/port ] && break; sleep 0.2; done
  $PY -c "import socket;c=socket.create_connection(('$3',int(open('$W/port').read())),timeout=3);c.sendall(b'n')" 2>/dev/null
  wait $S
}
LAN=$(ipconfig getifaddr en0 || ipconfig getifaddr en1)
BASE='(version 1)(allow default)(deny network*)'
for f in '(allow network-bind (local ip "localhost:*"))(allow network-inbound (local ip "localhost:*"))' \
         '(allow network-bind (local ip "localhost:*"))(allow network-inbound (remote ip "localhost:*"))' \
         '(allow network-bind (local ip "localhost:*"))(allow network-inbound (local ip "localhost:*") (remote ip "localhost:*"))' \
         '(allow network-bind (local ip "localhost:*"))(allow network-inbound (require-all (local ip "localhost:*") (remote ip "localhost:*")))'; do
  echo "## $f"
  printf '  compile => '; sb "$BASE$f" /usr/bin/true 2>&1 | head -1; echo
  printf '  127.0.0.1 <- 127.0.0.1 => '; listen "$BASE$f" 127.0.0.1 127.0.0.1
  printf '  0.0.0.0 <- 127.0.0.1 => '; listen "$BASE$f" 0.0.0.0 127.0.0.1
  printf '  0.0.0.0 <- LAN => '; listen "$BASE$f" 0.0.0.0 $LAN
  printf '  ::1 <- ::1 => '; listen "$BASE$f" ::1 ::1
done
for f in '(allow network-bind (local ip "127.0.0.1:*"))' '(allow network-bind (local ip4 "localhost:*"))' '(allow network-bind (local tcp "localhost:*"))' '(deny job-creation)' '(deny iokit-open*)' '(deny iokit-open-user-client)' '(deny iokit-open-service)'; do printf 'compile %s => ' "$f"; sb "(version 1)(allow default)$f" /usr/bin/true 2>&1 | head -1; echo; done
logs 60s 'network' 10

h "System Events as an AppleEvent target"
printf 'control do shell script => '; t 20 osascript -e "tell application \"System Events\" to do shell script \"echo se >> $W/se-marker\"" 2>&1; echo " marker: $(cat $W/se-marker 2>&1)"; rm -f $W/se-marker
printf 'control make folder => '; t 20 osascript -e "tell application \"System Events\" to make new folder at end of folder \"$W\" with properties {name:\"se-folder\"}" 2>&1; echo " folder: $(ls -d $W/se-folder 2>&1)"; rm -rf $W/se-folder
printf 'deny appleevent-send make folder => '; sb '(version 1)(allow default)(deny appleevent-send)' osascript -e "tell application \"System Events\" to make new folder at end of folder \"$W\" with properties {name:\"se-folder\"}" 2>&1; echo " folder: $(ls -d $W/se-folder 2>&1)"; rm -rf $W/se-folder
printf 'allow-default make folder => '; sb '(version 1)(allow default)' osascript -e "tell application \"System Events\" to make new folder at end of folder \"$W\" with properties {name:\"se-folder\"}" 2>&1; echo " folder: $(ls -d $W/se-folder 2>&1)"; rm -rf $W/se-folder

h "swift build under a sandbox"
mkdir -p $W/swpkg/Sources/hello && printf '// swift-tools-version:5.9\nimport PackageDescription\nlet package = Package(name: "hello", targets: [.executableTarget(name: "hello")])\n' > $W/swpkg/Package.swift && echo 'print("hi")' > $W/swpkg/Sources/hello/main.swift
printf 'allow-default swift build => '; sb '(version 1)(allow default)' swift build --package-path $W/swpkg 2>&1 | tail -2
printf 'iokit deny swift build --disable-sandbox => '; sb '(version 1)(allow default)(deny iokit-open)' swift build --disable-sandbox --package-path $W/swpkg 2>&1 | tail -2
cat > $W/metal.swift <<'SW'
import Metal
print(MTLCreateSystemDefaultDevice()?.name ?? "no device")
SW
t 120 swiftc -o $W/metal $W/metal.swift 2>&1 | tail -2
printf 'metal control => '; t 20 $W/metal
printf 'metal iokit report => '; sb '(version 1)(allow default)(allow iokit-open (with report))(allow iokit-open-user-client (with report))(allow iokit-open-service (with report))' $W/metal
printf 'metal iokit deny => '; sb '(version 1)(allow default)(deny iokit-open)(deny iokit-open-user-client)' $W/metal
logs 60s 'iokit' 20

h "log stream startup"
(log stream --style ndjson --predicate 'sender == "Sandbox"' > $W/stream.txt 2>&1 &) ; sleep 2
sb '(version 1)(allow default)(deny file-read* (literal "/etc/hosts"))' cat /etc/hosts >/dev/null 2>&1
sleep 2; pkill -f 'log stream --style ndjson'; echo "first line: $(head -c 300 $W/stream.txt)"; echo "lines: $(wc -l < $W/stream.txt)"; grep -c 'deny(1) file-read-data /private/etc/hosts' $W/stream.txt

h "confstr temp dir vs TMPDIR"
$W/confstr; TMPDIR=$W/ $W/confstr
echo done
