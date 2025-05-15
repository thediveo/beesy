// SPDX-License-Identifier: GPL-2.0

// Note: This file is licenced differently from the rest of the project
// Copyright 2025 Harald Albrecht

//go:build ignore

#include "iter.h"
#include "tid_current_pidns.h"

char __license[] SEC("license") = "GPL";

// info defines the binary representation of the per-task information we are
// going to send to user space when iterating over tasks.
struct info {
    int  root_tid; // user-space TID in initial PID namespace
    int  tid;      // user-space TID as seen from caller's PID namespace
};

const struct info _meh __attribute__((unused)); // force emitting struct procstatus

// the "iterator" program that gets called on each iteration of an eBPF task
// iterator.
SEC("iter/task")
int dump_task_tid(struct bpf_iter__task *ctx)
{
    struct seq_file *m = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    if (task == NULL) {
        return 0;
    }

    struct info info;
    info.root_tid = task->pid,   // user-space TID <=> kernel-space pid
    info.tid = tid_current_pidns(task);

    bpf_seq_write(m, &info, sizeof(info));

    return 0;
}
