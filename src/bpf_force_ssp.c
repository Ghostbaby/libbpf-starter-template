// bpf_force_ssp.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/test")
int force_ssp(void *ctx) {
    char buffer[8];
    // 模拟 strcpy 行为
    buffer[0] = 't';
    buffer[1] = 'h';
    buffer[2] = 'i';
    buffer[3] = 's';
    buffer[4] = ' ';
    buffer[5] = 'i';
    buffer[6] = 's';
    buffer[7] = ' ';
    buffer[8] = 'l';  // 越界访问！
    buffer[9] = 'o';
    buffer[10] = 'n';
    buffer[11] = 'g';
    
    return buffer[0];
}

char _license[] SEC("license") = "GPL";