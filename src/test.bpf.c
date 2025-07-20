// test.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16

SEC("kprobe/do_unlinkat")
int test_minimal(struct pt_regs *ctx)
{
    return 0;
}

SEC("kprobe/do_unlinkat") 
int test_with_comm(struct pt_regs *ctx)
{
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, TASK_COMM_LEN);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";