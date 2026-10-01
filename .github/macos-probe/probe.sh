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
for c in peer procargs conceal; do cc -o $W/$c $D/$c.c || echo "CC $c FAILED"; done

h "Mach-name marker"
M='(version 1)(allow default)(deny mach-lookup (global-name "dev.formwork.session.x.d"))(allow mach-lookup (global-name "dev.formwork.session.x.a"))'
sandbox-exec -p "$M" /bin/sh -c 'echo $$ > m; exec sleep 20' &
sleep 20 & echo $! > u
sandbox-exec -p '(version 1)(deny default)(allow process*)(allow file-read*)(allow file-write*)(allow sysctl-read)' /bin/sh -c 'echo $$ > d; exec sleep 20' &
sandbox-exec -p '(version 1)(deny default)(allow process*)(allow file-read*)(allow file-write*)(allow sysctl-read)(allow mach-lookup)' /bin/sh -c 'echo $$ > d2; exec sleep 20' &
sandbox-exec -p '(version 1)(allow default)' /bin/sh -c 'echo $$ > a; exec sleep 20' &
sleep 1
for k in m u d d2 a; do echo "-- $k ($(cat $k))"; $W/peer $(cat $k) dev.formwork.session.x.d dev.formwork.session.x.a; done
printf -- '-- m checked from inside a sandbox:\n'; sb '(version 1)(allow default)' $W/peer $(cat m) dev.formwork.session.x.d dev.formwork.session.x.a
logs 10s 'formwork.session' 5
kill $(cat m u d d2 a) 2>/dev/null

h "signal and process-info: deny all, allow same-sandbox"
cat > $W/parent.py <<'PYS'
import os, signal, subprocess, sys, time
got = []
signal.signal(signal.SIGUSR1, lambda *a: got.append(1))
p = subprocess.run(["sandbox-exec", "-p", sys.argv[1], "/bin/sh", "-c", "kill -USR1 $PPID; echo child-rc=$?"])
time.sleep(0.3)
print("parent received SIGUSR1:", bool(got))
PYS
SIG='(deny signal)(allow signal (target same-sandbox))'
printf 'parent under %s => ' "$SIG"; $PY $W/parent.py "(version 1)(allow default)$SIG"
ISO="(version 1)(allow default)$SIG(deny process-info*)(allow process-info* (target same-sandbox))"
ISO2="(version 1)(allow default)$SIG(deny process-info* (target others))(deny process-info* (target pgrp))(allow process-info* (target same-sandbox))"
FW_CANARY=canary-77 perl -e 'setpgrp(0,0); exec "sleep", "60"' & SIB=$!; sleep 0.3
cat > $W/mp.py <<'PYS'
import multiprocessing as mp
def f(x): return x*x
if __name__ == "__main__":
    with mp.Pool(2) as p: print("ok", sum(p.map(f, range(10))))
PYS
mkdir -p mk; printf 'all: a b c\na:\n\tsleep 0.2\nb:\n\tsleep 0.2\nc:\n\tsleep 0.2\n' > mk/Makefile
for P in "$ISO" "$ISO2"; do
  echo "## $P"
  printf '  kill -0 sibling => '; sb "$P" /bin/sh -c "kill -0 $SIB 2>/dev/null && echo SIGNALABLE || echo refused"
  printf '  lsof sibling => '; sb "$P" /bin/sh -c "lsof -p $SIB >/dev/null 2>&1 && echo VISIBLE || echo refused"
  printf '  pgrep sleep => '; sb "$P" pgrep sleep 2>&1 | tr '\n' ' '; echo
  printf '  bash job control => '; sb "$P" /bin/bash -c 'set -m; sleep 5 & kill -TERM %1; wait; echo ok' 2>/dev/null
  printf '  reparented grandchild => '; sb "$P" /bin/sh -c '(perl -e "setpgrp(0,0); sleep 5" & echo $! > gc) ; sleep 0.3; kill $(cat gc) && echo ok'
  printf '  python multiprocessing => '; sb "$P" $PY $W/mp.py 2>&1 | tail -1
  printf '  node child_process => '; sb "$P" node -e 'const c=require("child_process");const p=c.spawn("sleep",["5"]);setTimeout(()=>p.kill(),200);p.on("exit",(code,s)=>console.log("exit",s))'
  printf '  make -j3 => '; sb "$P" make -s -j3 -C mk && echo ok
  printf '  node os.cpus+exec => '; sb "$P" node -e 'require("child_process").execSync("true");console.log(require("os").cpus().length>0)'
  printf '  python subprocess.run => '; sb "$P" $PY -c 'import subprocess;print(subprocess.run(["echo","ok"],capture_output=True).stdout.decode().strip())'
  printf '  cargo --version => '; sb "$P" cargo --version | head -1
  printf '  git status => '; sb "$P" git -C $D status --short >/dev/null && echo ok
  printf '  parent signal => '; $PY $W/parent.py "$P"
done
logs 60s 'deny\(1\) (signal|process-info)' 15
kill $SIB

h "C5 environment concealment"
printf 'unconditional sysctl-read deny => '; FW_CANARY=c1 sleep 30 & S1=$!; sleep 0.2; sb '(version 1)(allow default)(deny sysctl-read)' $W/procargs $S1 2>&1 | tail -1; kill $S1
FW_CANARY=c2 $W/conceal 20 & C=$!; sleep 0.5
printf 'after concealing, unconfined reader => '; $W/procargs $C
printf 'after concealing, ps -E => '; ps -E -p $C -o command= | grep -o 'FW_CANARY=[^ ]*' || echo "not shown"
kill $C

h "binding the LAN address and the wildcard"
LAN=$(ipconfig getifaddr en0 || ipconfig getifaddr en1)
for f in '(local ip "localhost:*")' '(local ip4 "localhost:*")' '(local tcp "localhost:*")'; do
  P="(version 1)(allow default)(deny network*)(allow network-bind $f)(allow network-inbound $f)"
  for a in 127.0.0.1 $LAN 0.0.0.0; do printf '%s bind+listen %s => ' "$f" $a; sb "$P" $PY -c "import socket;s=socket.socket();s.bind(('$a',0));s.listen(1);print('listening',s.getsockname())" 2>&1 | tail -1; done
done
P='(version 1)(allow default)(deny network*)(allow network-bind (local ip "localhost:*"))'
printf 'bind-only 0.0.0.0 then listen => '; sb "$P" $PY -c "import socket;s=socket.socket();s.bind(('0.0.0.0',0));print('bound');s.listen(1);print('listening')" 2>&1 | tail -1
logs 30s 'network' 10

h "NSTemporaryDirectory vs TMPDIR"
cat > $W/tmp.swift <<'SW'
import Foundation
print(NSTemporaryDirectory(), FileManager.default.temporaryDirectory.path)
SW
t 120 swiftc -o $W/tmpdir $W/tmp.swift && TMPDIR=$W/session-tmp/ $W/tmpdir

h "system keychain trust for a test CA"
openssl req -x509 -newkey rsa:2048 -nodes -keyout $W/ca.key -out $W/ca.pem -days 2 -subj "/CN=Formwork Probe CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout $W/leaf.key -out $W/leaf.csr -subj "/CN=localhost" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > $W/ext
openssl x509 -req -in $W/leaf.csr -CA $W/ca.pem -CAkey $W/ca.key -CAcreateserial -out $W/leaf.pem -days 2 -extfile $W/ext 2>/dev/null
cat > $W/srv.py <<'PYS'
import http.server, ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[1], sys.argv[2])
s = http.server.HTTPServer(("127.0.0.1", 18443), http.server.SimpleHTTPRequestHandler)
s.socket = ctx.wrap_socket(s.socket, server_side=True); s.serve_forever()
PYS
$PY $W/srv.py $W/leaf.pem $W/leaf.key 2>/dev/null & SRV=$!; sleep 1
cat > $W/get.swift <<'SW'
import Foundation
let s = DispatchSemaphore(value: 0)
URLSession.shared.dataTask(with: URL(string: CommandLine.arguments[1])!) { _, r, e in
  print((r as? HTTPURLResponse)?.statusCode ?? -1, e?.localizedDescription ?? ""); s.signal() }.resume()
s.wait()
SW
t 120 swiftc -o $W/swiftget $W/get.swift
printf 'before trust: '; t 15 $W/swiftget https://localhost:18443/
printf 'add-trusted-cert => '; t 30 sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $W/ca.pem; echo "rc $?"
printf 'after trust: '; t 15 $W/swiftget https://localhost:18443/
GO=$(ls -d /Users/runner/hostedtoolcache/go/*/arm64/bin/go 2>/dev/null | tail -1)
printf 'package main\nimport ("fmt";"net/http";"os")\nfunc main(){ r,err:=http.Get(os.Args[1]); if err!=nil {fmt.Println("err",err); os.Exit(1)}; fmt.Println(r.StatusCode)}\n' > $W/get.go
(cd $W && t 120 $GO build -o goget get.go) && printf 'go after trust: ' && t 15 $W/goget https://localhost:18443/
printf 'cargo/rustup TLS libs: '; otool -L $(command -v cargo) 2>/dev/null | grep -iE 'ssl|security|curl' | tr '\n' ' '; echo
t 30 sudo security delete-certificate -c "Formwork Probe CA" /Library/Keychains/System.keychain; echo "removed rc $?"
kill $SRV
echo done
