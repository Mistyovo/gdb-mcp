/* crasher.c - tiny NULL-deref crasher for gdb-mcp integration tests.

 * Usage:
 *   ./crasher        -> crashes with SIGSEGV (NULL deref)
 *   ./crasher loop   -> infinite loop (for interrupt testing)
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline)) void crash(void) {
    volatile int *p = 0;
    printf("[crasher] about to deref NULL\n");
    fflush(stdout);
    *p = 0x41; /* SIGSEGV, fault addr 0x0 */
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "loop") == 0) {
        printf("[crasher] looping forever\n");
        fflush(stdout);
        for (;;) {
            sleep(1);
        }
    }
    printf("[crasher] entering main\n");
    fflush(stdout);
    crash();
    return 0;
}
