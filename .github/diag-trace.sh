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
#include <sys/time.h>
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
static double now(void) { struct timeval t; gettimeofday(&t, 0); return t.tv_sec + t.tv_usec / 1e6; }
int main(int argc, char **argv) {
  int port = atoi(argv[1]); double secs = atof(argv[2]);
  double t0 = now(); int n = 0, e4 = 0, e6 = 0;
  while (now() - t0 < secs) {
    int a = try4(port), b = try6(port); n++;
    if (a == EPERM) { e4++; printf("sin_zero=EPERM v4 at %.3f\n", now()); }
    if (b == EPERM) { e6++; printf("sin_zero=EPERM v6 at %.3f\n", now()); }
    usleep(10000);
  }
  printf("sin_zero=summary %d rounds, v4 EPERM %d, v6 EPERM %d\n", n, e4, e6);
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
./conn "$p" 75
P
"$GITHUB_WORKSPACE/target/debug/formwork" run -- /bin/sh probe.sh 2>&1 | grep -E "gateway port|sin_zero=" | sed 's/sin_zero=//' | head -60
