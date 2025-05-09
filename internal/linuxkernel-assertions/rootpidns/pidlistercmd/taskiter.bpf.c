//go:build ignore

#include "iter.h"
#include "strncpy.h"
#include "bpf_core_read.h"

char __license[] SEC("license") = "GPL";

// https://elixir.bootlin.com/linux/v6.12/source/tools/sched_ext/include/scx/common.bpf.h#L329
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

// task_info defines the binary representation of the per-task information we
// are going to send to user space when iterating over tasks.
struct task_info {
    int  pid;
    int  tid;
    char fullname[TASK_COMM_LEN];
    char callername[TASK_COMM_LEN];
};

const struct task_info _meh __attribute__((unused)); // force emitting struct procstatus

// the "iterator" program that gets called on each iteration of an eBPF task
// iterator.
SEC("iter/task")
int dump_task_info(struct bpf_iter__task *ctx)
{
    struct seq_file *m = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    if (task == NULL) {
        return 0;
    }

    struct task_info stat;
    stat.pid = task->tgid,  // user-space PID <=> kernel-space tgid
    stat.tid = task->pid,   // user-space TID <=> kernel-space pid
    bee_strncpy(stat.fullname, task->comm, TASK_COMM_LEN-1);
    stat.fullname[TASK_COMM_LEN-1] = '\0';
    bpf_get_current_comm(stat.callername, TASK_COMM_LEN);

    bpf_seq_write(m, &stat, sizeof(stat));

    return 0;
}
