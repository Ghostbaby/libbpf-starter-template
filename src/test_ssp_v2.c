// test_ssp_v2.c
#include <string.h>

// 全局变量防止优化
volatile int result;

void test1() {
    char buf[4];
    buf[0] = 'a';
    result = buf[0];  // 防止优化掉
}

void test2() {
    char buf[16];
    buf[0] = 'a';
    result = buf[0];
}

void test3() {
    char buf[4];
    memset(buf, 0, sizeof(buf));
    result = buf[0];
}

void test4() {
    char buf[16];
    memset(buf, 0, sizeof(buf));
    result = buf[0];
}

void test5() {
    struct { char buf[16]; } s;
    memset(&s, 0, sizeof(s));
    result = s.buf[0];
}