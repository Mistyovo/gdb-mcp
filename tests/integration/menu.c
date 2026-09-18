#include <stdio.h>

/* minimal interactive target for the inferior-stdio smoke test:
   prints a prompt, echoes one line back, exits. */
int main(void) {
    char buf[64];
    printf("menu:> ");
    fflush(stdout);
    if (!fgets(buf, sizeof buf, stdin)) {
        return 0;
    }
    printf("got:%s", buf);
    fflush(stdout);
    return 0;
}
