#ifndef __BEESY_TID_CURRENT_PIDNS
#define __BEESY_TID_CURRENT_PIDNS

#include "task.h"
#include "bpf_core_read.h"

/*
 * tid_current_pidns returns the (user-space) TID for the specified task as seen
 * from the PID namespace of the current task, or 0.
 * 
 * To get the PID of a task, pass task->group_leader instead.
 */
pid_t tid_current_pidns(struct task_struct *task)
{
    struct pid *thrpid = task->thread_pid;
    unsigned int thrlevel = BPF_CORE_READ(thrpid, level);
    
    struct task_struct *current = (struct task_struct *) bpf_get_current_task();
    unsigned int clevel = BPF_CORE_READ(current, thread_pid, level);
    
    if (clevel > thrlevel) {
        return 0;
    }
    struct upid upid = BPF_CORE_READ(thrpid, numbers[clevel]);
    return upid.nr;
}

#endif
