// force_ssp.c
#include <string.h>

void __attribute__((noinline)) vulnerable_func(const char *input) {
    char buffer[8];  // 小缓冲区
    strcpy(buffer, input);  // 明显的缓冲区溢出风险
}

void test_overflow() {
    vulnerable_func("this is a long string that will overflow");
}