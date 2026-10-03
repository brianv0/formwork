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
static int try(int port, unsigned char fill) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a;
  memset(&a, fill, sizeof a);
  a.sin_len = sizeof a;
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
  int r = connect(s, (struct sockaddr *)&a, sizeof a);
  int e = r ? errno : 0;
  close(s);
  return e;
}
int main(int argc, char **argv) {
  int port = atoi(argv[1]);
  unsigned char fills[] = {0x00, 0x01, 0xa4, 0xff};
  for (int i = 0; i < 4; i++) {
    int fails = 0, last = 0;
    for (int n = 0; n < 20; n++) { int e = try(port, fills[i]); if (e) { fails++; last = e; } }
    printf("sin_zero=0x%02x: %d/20 refused (errno %d)\n", fills[i], fails, last);
  }
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
./conn "$p"
P
"$GITHUB_WORKSPACE/target/debug/formwork" run -- /bin/sh probe.sh 2>&1 | grep -v -E "INFO|WARN|refused \(|FW-EGR9"
