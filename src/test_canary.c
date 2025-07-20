#include <stdio.h>
#include <string.h>

void test() {
    char buf[8];
    strcpy(buf, "test");
    printf("buf: %s\n", buf);
}

int main() {
    test();
    return 0;
}
