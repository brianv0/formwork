// Temporary probe: sandbox_check with Mach-name markers.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int sandbox_check(pid_t pid, const char *operation, int type, ...);
int main(int argc, char **argv) {
    pid_t pid = atoi(argv[1]);
    for (int i = 2; i < argc; i++) printf("  mach-lookup %s => %d\n", argv[i], sandbox_check(pid, "mach-lookup", 2 | 0x40000000, argv[i]));
    printf("  sandboxed => %d\n", sandbox_check(pid, NULL, 0));
    return 0;
}
