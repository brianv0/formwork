#include <stdio.h>
#include <unistd.h>
int main(void) { char b[1024]; size_t n = confstr(_CS_DARWIN_USER_TEMP_DIR, b, sizeof b); printf("confstr temp=%s (n=%zu)\n", n ? b : "(none)", n); return 0; }
