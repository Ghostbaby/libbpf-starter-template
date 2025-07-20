// test_ssp.c
#include <string.h>

// 测试1：小数组，不取地址
void test1() {
    char buf[4];
    buf[0] = 'a';
}

// 测试2：大数组，不取地址
void test2() {
    char buf[16];
    buf[0] = 'a';
}

// 测试3：小数组，取地址
void test3() {
    char buf[4];
    memset(buf, 0, sizeof(buf));
}

// 测试4：大数组，取地址
void test4() {
    char buf[16];
    memset(buf, 0, sizeof(buf));
}

// 测试5：结构体中的数组
void test5() {
    struct { char buf[16]; } s;
    memset(&s, 0, sizeof(s));
}