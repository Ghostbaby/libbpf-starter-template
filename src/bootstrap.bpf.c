// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event *e;
	pid_t pid;
	u64 ts;

	/* remember time exec() was executed for this PID */
	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* don't emit exec events when minimum duration is specified */
	if (min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = false;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
	struct task_struct *task;
	struct event *e;
	pid_t pid, tid;
	u64 id, ts, *start_ts, duration_ns = 0;
	
	/* get PID and TID of exiting thread/process */
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

	/* ignore thread exits */
	if (pid != tid)
		return 0;

	/* if we recorded start of the process, calculate lifetime duration */
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
	if (start_ts)
		duration_ns = bpf_ktime_get_ns() - *start_ts;
	else if (min_duration_ns)
		return 0;
	bpf_map_delete_elem(&exec_start, &pid);

	/* if process didn't live long enough, return early */
	if (min_duration_ns && duration_ns < min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = true;
	e->duration_ns = duration_ns;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

#define TASK_COMM_LEN 16

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[TASK_COMM_LEN]);
} comm_buf SEC(".maps");

// 该 prog 用于拦截 do_unlinkat 系统调用，当删除文件时，打印文件名和进程名
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    const char *filename;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (pid_tgid << 32) >> 32;
    __u32 tgid = pid_tgid >> 32;
    long ret;

	u32 key = 0;
    char *comm = bpf_map_lookup_elem(&comm_buf, &key);
    if (!comm)
        return 0;

    filename = BPF_CORE_READ(name, name);

    bpf_get_current_comm(comm, TASK_COMM_LEN);
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 8;
}  


#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

struct tp_event {
 unsigned int pid;
 unsigned int tpid;
 int sig;
 int ret;
 char comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct tp_event);
} values SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx)
{
	struct tp_event event;

	 __u64 pid_tgid = bpf_get_current_pid_tgid();
	 __u32 tid = (__u32)pid_tgid;
	 event.pid = pid_tgid >> 32;
	 event.tpid = (pid_t)ctx->args[0];
	 event.sig = (int)ctx->args[1];;
	 bpf_get_current_comm(event.comm, sizeof(event.comm));
	 
	 bpf_map_update_elem(&values, &tid, &event, BPF_ANY);


	 return 0;
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx)
{
	struct tp_event *eventp;

	 __u64 pid_tgid = bpf_get_current_pid_tgid();
	 __u32 tid = (__u32)pid_tgid;

	 eventp = bpf_map_lookup_elem(&values, &tid);
	 if (!eventp)
	 	return 0;

	 eventp->ret = ctx->ret;
	 bpf_printk("PID %d (%s) sent signal %d ",
	           eventp->pid, eventp->comm, eventp->sig);
	 bpf_printk("to PID %d, ret = %d",
	           eventp->tpid, eventp->ret);

cleanup:
	bpf_map_delete_elem(&values, &tid);


	 return 0;
}
