/* bench crackme #3: format string (stdin delivery; NUL bytes allowed).
   Compile (in WSL):
     gcc -g -O0 -fno-stack-protector -no-pie -o /tmp/fmt_bench fmt.c
   Solve:
     1. printf(buf) is the vulnerability. `locked` is a .bss global at a
        fixed address (no-PIE): elf_symbols("locked") returns it.
     2. Probe positional args: a payload of "%6$p|%7$p|...|%N$p|" plus
        8-byte markers planted after the format string reveals which
        arg index maps to which payload offset (buf sits in printf's
        stack-args area, so its contents are addressable positionally).
     3. Write: "%4919c%<idx>$n" padded to the marker offset, then
        p64(&locked) — %n stores 4919 (0x1337) into locked.
   Success marker printed when locked == 0x1337: WIN{fmt-bench-ok}.
*/

#include <stdio.h>
#include <unistd.h>

int locked;

int main(void) {
    /* unbuffered so probe output survives even a later crash */
    setvbuf(stdout, NULL, _IONBF, 0);
    char buf[128];
    ssize_t n = read(0, buf, 400);
    if (n < 0) {
        n = 0;
    }
    buf[n] = '\0';
    printf(buf);
    putchar('\n');
    if (locked == 0x1337) {
        puts("WIN{fmt-bench-ok}");
    }
    return 0;
}
