#ifndef __BEESY_TASK_H
#define __BEESY_TASK_H

#include "common.h"

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

// https://elixir.bootlin.com/linux/v6.12/source/kernel/kthread.c#L53
struct kthread {
    char *full_name;
} __attribute__((preserve_access_index));


// https://elixir.bootlin.com/linux/v6.14.5/source/fs/proc/array.c#L99
#define TASKFULLNAMELEN 64

#endif
