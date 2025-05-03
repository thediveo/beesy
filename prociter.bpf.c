//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// https://elixir.bootlin.com/linux/v6.12/source/tools/sched_ext/include/scx/common.bpf.h#L329
void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

// See:
// - https://elixir.bootlin.com/linux/v6.12/source/include/linux/types.h#L27
// - https://elixir.bootlin.com/linux/v6.12/source/include/uapi/asm-generic/posix_types.h#L28
typedef int pid_t; 

// https://elixir.bootlin.com/linux/v6.12/source/include/linux/sched.h#L778
struct task_struct {
    pid_t pid;
    pid_t tgid;
} __attribute__((preserve_access_index));

// https://elixir.bootlin.com/linux/v6.12/source/tools/testing/selftests/bpf/progs/bpf_iter.h#L52
struct bpf_iter_meta {
	struct seq_file *seq;
	__u64 session_id;
	__u64 seq_num;
} __attribute__((preserve_access_index));


// https://elixir.bootlin.com/linux/v6.12/source/tools/testing/selftests/bpf/progs/bpf_iter.h#L68
struct bpf_iter__task {
	struct bpf_iter_meta *meta;
	struct task_struct *task;
} __attribute__((preserve_access_index));


// proc_status defines the binary representation of the per-task status
// information.
struct procstatus {
    int pid;
    int tid;
};

const struct procstatus _meh __attribute__((unused)); // force emitting struct procstatus

SEC("iter/task")
int dump_task_status(struct bpf_iter__task *ctx)
{
    struct seq_file *m = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    if (task == NULL) {
        return 0;
    }

    struct procstatus stat;
    
    bpf_rcu_read_lock();
    stat.pid = task->tgid,  // user-space PID <=> kernel-space tgid
    stat.tid = task->pid,   // user-space TID <=> kernel-space pid
    bpf_rcu_read_unlock();

    bpf_seq_write(m, &stat, sizeof(stat));

    return 0;
}
