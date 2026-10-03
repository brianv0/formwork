#!/usr/bin/env bash
# TEMPORARY: does Seatbelt's `localhost:<P>` rule depend on sockaddr_in.sin_zero?
set -u
sw_vers
work=$(mktemp -d); cd "$work"
cat > conn.c <<'C'
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static int try4(int port) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a; memset(&a, 0, sizeof a);
  a.sin_len = sizeof a; a.sin_family = AF_INET; a.sin_port = htons(port);
  inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
  int r = connect(s, (struct sockaddr *)&a, sizeof a); int e = r ? errno : 0; close(s); return e;
}
static int try6(int port) {
  int s = socket(AF_INET6, SOCK_STREAM, 0);
  struct sockaddr_in6 a; memset(&a, 0, sizeof a);
  a.sin6_len = sizeof a; a.sin6_family = AF_INET6; a.sin6_port = htons(port);
  inet_pton(AF_INET6, "::1", &a.sin6_addr);
  int r = connect(s, (struct sockaddr *)&a, sizeof a); int e = r ? errno : 0; close(s); return e;
}
int main(int argc, char **argv) {
  int port = atoi(argv[1]), n = atoi(argv[2]);
  int c4[128] = {0}, c6[128] = {0};
  if (n == 1) { int e = try4(port); if (e) printf("errno %d: v4\\n", e); return 0; }
  for (int i = 0; i < n; i++) { int e = try4(port); c4[e < 128 ? e : 127]++; }
  for (int i = 0; i < n; i++) { int e = try6(port); c6[e < 128 ? e : 127]++; }
  for (int e = 0; e < 128; e++) if (c4[e]) printf("sin_zero=v4 127.0.0.1 errno %d: %d/%d\n", e, c4[e], n);
  for (int e = 0; e < 128; e++) if (c6[e]) printf("sin_zero=v6 ::1 errno %d: %d/%d\n", e, c6[e], n);
  return 0;
}
C
cc -o conn conn.c
cat > FORMWORK.toml <<'T'
extends = ["builtin:default"]
rules = ["readwrite:$CWD/**", "allow:127.0.0.1:9"]
T
cat > probe.sh <<'P'
p=${HTTP_PROXY##*:}; p=${p%/}
echo "gateway port $p"
fails=0
for i in $(seq 1 ${PROCS:-3000}); do
  out=$(./conn "$p" 1)
  case "$out" in *"errno 1:"*) fails=$((fails+1)); echo "sin_zero=EPERM in process $i: $out";; esac
done
echo "sin_zero=fresh processes in one session: $fails/${PROCS:-3000} refused"
P
"$GITHUB_WORKSPACE/target/debug/formwork" run -- /bin/sh probe.sh 2>&1 | grep -E "gateway port|sin_zero="
cat > one.sh <<'P'
p=${HTTP_PROXY##*:}; p=${p%/}
./conn "$p" 1 | grep "errno 1:" && echo "sin_zero=EPERM first connect, session port $p"
true
P
fails=0
for i in $(seq 1 400); do
  out=$("$GITHUB_WORKSPACE/target/debug/formwork" run -- /bin/sh one.sh 2>/dev/null)
  case "$out" in *EPERM*) fails=$((fails+1)); echo "$out";; esac
done
echo "sin_zero=fresh sessions: $fails/400 refused"
