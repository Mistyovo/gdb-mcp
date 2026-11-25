#include <unistd.h>

__attribute__((noinline)) int break_here(int value) { return value + 1; }

int main(void) {
    int value = break_here(41);
    pause();
    return value != 42;
}
