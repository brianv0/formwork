// Temporary probe: read another process's environment through kern.procargs2, as ps -E does.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/sysctl.h>
int main(int argc, char **argv) {
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, atoi(argv[1])};
    char buf[65536]; size_t len = sizeof buf;
    if (sysctl(mib, 3, buf, &len, NULL, 0) != 0) { printf("procargs2: %s\n", strerror(errno)); return 2; }
    for (size_t i = 0; i + 10 < len; i++) if (!memcmp(buf + i, "FW_CANARY=", 10)) { printf("seen %s\n", buf + i); return 0; }
    printf("procargs2 readable, canary absent\n"); return 1;
}
