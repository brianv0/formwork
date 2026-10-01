// Temporary probe: move the environment to the heap and zero the exec-time strings, then sleep.
#include <crt_externs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    char ***envp = _NSGetEnviron();
    size_t n = 0; while ((*envp)[n]) n++;
    char **copy = calloc(n + 1, sizeof(char *));
    for (size_t i = 0; i < n; i++) copy[i] = strdup((*envp)[i]);
    char **orig = *envp; *envp = copy;
    for (size_t i = 0; i < n; i++) memset(orig[i], 0, strlen(orig[i]));
    printf("concealed %zu, getenv FW_CANARY=%s\n", n, getenv("FW_CANARY")); fflush(stdout);
    sleep(atoi(argv[1]));
    return 0;
}
