/* Target for run_pc_control_smoke.sh (issue 13 real-gdb coverage).
 *
 * handle() copies the attacker-controlled global g_input into a fixed
 * 32-byte buffer that sits right before a function pointer, then calls
 * through that pointer. Overwriting bytes 32..39 with a value controls PC.
 *
 * Built twice:
 *   pc_control_vuln  -> strcpy (unbounded): payload at offset 32 hijacks PC
 *   pc_control_safe  -> strncpy bounded to the buffer: PC cannot be moved
 *
 * ``done`` is reached only when the call returns, so it is a guaranteed
 * stop for the non-controllable build.
 */
#include <string.h>

char g_input[256];

static void safe_target(void) {}

__attribute__((noinline)) void handle(void) {
    struct rec {
        char buf[32];
        void (*fp)(void);
    } r;
    r.fp = safe_target;
#ifdef VULN
    strcpy(r.buf, g_input);
#else
    strncpy(r.buf, g_input, sizeof(r.buf));
#endif
    r.fp();
}

__attribute__((noinline)) void done(void) {
    __asm__ volatile("" ::: "memory");
}

int main(void) {
    handle();
    done();
    return 0;
}
