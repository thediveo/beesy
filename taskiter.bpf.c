//go:build ignore

#include "common.h"
#include "bpf_core_read.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// https://elixir.bootlin.com/linux/v6.12/source/tools/sched_ext/include/scx/common.bpf.h#L329
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

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
    
    struct task_struct *real_parent;

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

/*
 * bee_strncpy copies len byte-wide chars from *src to *dst, filling in zero
 * chars when the end of src has been reached before len. This helper does not
 * ensure a trailing zero byte, it is up to the caller to ensure such a zero
 * byte terminator where necessary.
 */
void bee_strncpy(char *dst, const char *src, int len) {
    while (len) {
        if ((*dst = *src) != 0) {
            src++;
        }
        dst++;
        len--;
    }
}

/*
 * task_name copies the name of the *task into the *buf of len, ensuring that
 * the name is always properly zero byte terminated.
 *
 * Please note that task_name does not pad *buf with zeros, except for a single
 * zero byte char right at the end of the task name.
 *
 * This is not your average strncpy(buf, task->name, 15) variant, but instead it
 * correctly handles kthread "full names" that can be up to 63 chars long (and
 * with an additional trailing zero byte char in tow).
 */
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
                // according to
                // https://docs.ebpf.io/linux/helper-function/bpf_probe_read_kernel_str
                // we either end up with an always properly zero-terminated
                // string in our buffer, or in an unlikely event with nothing
                // copied at all.
                int l = bpf_probe_read_kernel_str(buf, len, fn);
                if (l >= 0) {
                    return;
                }
                // fall back on using the "length-challenged" task->comm name if
                // we can't retrieve the full name for some strange reason.
            }
        }
    }
    // use the "length-challenged" task->comm name that is always present.
    if (len > TASK_COMM_LEN) {
        len = TASK_COMM_LEN;
    }
    bee_strncpy(buf, task->comm, len-1);
    buf[len-1] = '\0';
    return;
}

// taskstatus defines the binary representation of the per-task status
// information.
struct task_status {
    int  pid;
    int  tid;
    int  ppid;
    char fullname[TASKFULLNAMELEN];
};

const struct task_status _meh __attribute__((unused)); // force emitting struct procstatus

SEC("iter/task")
int dump_task_status(struct bpf_iter__task *ctx)
{
    struct seq_file *m = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    if (task == NULL) {
        return 0;
    }

    struct task_status stat;
    
    stat.pid = task->tgid,  // user-space PID <=> kernel-space tgid
    stat.tid = task->pid,   // user-space TID <=> kernel-space pid
    task_name(task, stat.fullname, sizeof(stat.fullname));

    struct task_struct *parent = bpf_task_acquire(task->real_parent);
    if (parent != NULL) {
        stat.ppid = parent->tgid;
        bpf_task_release(parent);
    } else {
        stat.ppid = 0;
    }

    bpf_seq_write(m, &stat, sizeof(stat));

    return 0;
}
