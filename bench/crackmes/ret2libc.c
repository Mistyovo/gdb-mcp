/* bench crackme #2: ret2libc (two-stage, ASLR defeated via a GOT leak).
   Compile (in WSL):
     gcc -g -O0 -fno-stack-protector -no-pie -o /tmp/ret2libc_bench ret2libc.c
   Solve (stdin delivery; raw address bytes contain NULs):
     1. cyclic pattern -> overflow offset (buf[64] + saved rbp).
     2. ROP stage 1: pop rdi; ret / puts@got / puts@plt / back to main
        to leak the runtime address of libc puts from the GOT.
        The PLT address is visible in `disassemble main` (call <puts@plt>);
        the GOT slot in the PLT stub's `jmp [rip+X] # 0x... <puts@got>`.
     3. libc_lookup("puts"/"system") gives the file offsets; libc base =
        leak - puts offset; system = base + system offset.
     4. ROP stage 2: ret (stack realign for system's movaps) /
        pop rdi; ret / &g_cmd (find it with elf_strings) / &system.
        g_cmd runs `echo PWN{...}` via /bin/sh -c -> success marker.
   The binary exports pop_rdi_gadget (pop rdi; ret) so the challenge
   grades exploit CONSTRUCTION, not gadget hunting.
   Scoring is output-based: PWN{...} in the inferior output.
*/

#include <stdio.h>
#include <unistd.h>

const char *g_cmd = "echo PWN{ret2libc-bench-ok}";

__asm__(
    ".text\n"
    ".globl pop_rdi_gadget\n"
    "pop_rdi_gadget:\n"
    " pop %rdi\n"
    " ret\n"
);

int main(void) {
    /* unbuffered so stage-1 leaks survive even a later crash */
    setvbuf(stdout, NULL, _IONBF, 0);
    char buf[64];
    ssize_t n = read(0, buf, 200);
    if (n < 0) {
        n = 0;
    }
    buf[n] = '\0';
    puts("go");
    return 0;
}
