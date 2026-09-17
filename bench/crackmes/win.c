#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* bench crackme #1: argv-based stack overflow with a win function.
   Compile (in WSL):
     gcc -g -O0 -fno-stack-protector -no-pie -o /tmp/win_bench win.c
   Solve: overwrite the saved return address of main with &win.
   Success marker printed by win(): WIN{...}
*/

void win(void) {
    puts("WIN{gdb-mcp-bench-ok}");
    exit(0);
}

int main(int argc, char **argv) {
    char buf[64];
    if (argc < 2) {
        puts("usage: win_bench <payload>");
        return 1;
    }
    strcpy(buf, argv[1]);
    puts("back from strcpy");
    return 0;
}
