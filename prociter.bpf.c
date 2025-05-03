//go:build ignore

#include "common.h"
#include "bpf_core_read.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// https://elixir.bootlin.com/linux/v6.12/source/tools/sched_ext/include/scx/common.bpf.h#L329
void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

// See:
// - https://elixir.bootlin.com/linux/v6.12/source/include/linux/types.h#L27
// - https://elixir.bootlin.com/linux/v6.12/source/include/uapi/asm-generic/posix_types.h#L28
typedef int pid_t; 

// https://elixir.bootlin.com/linux/v6.14.4/source/include/linux/sched.h#L307
#define TASK_COMM_LEN 16

// https://elixir.bootlin.com/linux/v6.14.5/source/include/linux/sched.h#L1695
#define PF_KTHREAD 0x00200000 /* I am a kernel thread */

// https://elixir.bootlin.com/linux/v6.12/source/include/linux/sched.h#L778
struct task_struct {
    pid_t pid;
    pid_t tgid;

    char comm[TASK_COMM_LEN];
    
    unsigned int flags;
    void *worker_private;
} __attribute__((preserve_access_index));

struct kthread {
    char *full_name;
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


// https://elixir.bootlin.com/linux/v6.14.5/source/fs/proc/array.c#L99
#define TASKFULLNAMELEN 64

void bee_strncpy(char *dst, const char *src, int len) {
    while (len) {
        if (!(*dst = *src)) {
            src++;
        }
        dst++;
        len--;
    }
}

void task_name(struct task_struct *task, char *buf, int len)
{
    if (len < 1) { // pacify the verify
        return;
    }
    // eBPF: return of the deeply nester ;)
    if (task->flags & PF_KTHREAD) {
        struct kthread *kt = BPF_CORE_READ(task, worker_private);
        if (kt != NULL) {
            const char *fn = BPF_CORE_READ(kt, full_name);
            if (fn != NULL) {
                bpf_core_read_str(buf, len-1, fn);
                buf[len-1] = '\0';
                return;
            }
        }
        // otherwise fall through to the default task->comm name.
    }
    if (len > TASK_COMM_LEN) {
        len = TASK_COMM_LEN;
    }
    bee_strncpy(buf, task->comm, len-1);
    buf[len-1] = '\0';
}

// proc_status defines the binary representation of the per-task status
// information.
struct procstatus {
    int  pid;
    int  tid;
    char name[TASKFULLNAMELEN];
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
    task_name(task, stat.name, sizeof(stat.name));
    bpf_rcu_read_unlock();

    bpf_seq_write(m, &stat, sizeof(stat));

    return 0;
}
