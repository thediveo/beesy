#ifndef __BEESY_ITER_H
#define __BEESY_ITER_H

#include "task.h"

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


#endif
