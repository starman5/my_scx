/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Modified version of the builtin simple scheduler, to intelligently avoid waking up idle cpus under certain conditions
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

static u64 vtime_now;
UEI_DEFINE(uei);

// Structure for the tracepoint arguments
struct sys_enter_read_args {
    unsigned long long unused;  
    long syscall_nr;            
    unsigned int fd;            
    char *buf;                  
    size_t count;               
};

// Structure for the tracepoint arguments
struct sys_exit_read_args {
    unsigned long long unused;  
    long syscall_nr;            
    long ret;                   
};

struct sys_enter_write_args {
    unsigned long long unused;  
    long syscall_nr;            
    unsigned int fd;            
    const char *buf;           
    size_t count;              
};

struct sys_exit_write_args {
    unsigned long long unused;  
    long syscall_nr;            
    long ret;                  
};

struct sys_enter_epoll_wait_args {
    unsigned long long unused;  
    long syscall_nr;            
    int epfd;                   
    struct epoll_event *events; 
    int maxevents;              
    int timeout;                
};

struct sys_exit_epoll_wait_args {
    unsigned long long unused;  
    long syscall_nr;            
    long ret;                   
};

struct sys_enter_recvmsg_args {
    unsigned long long unused;  
    long syscall_nr;            
    int fd;                    
    struct msghdr *msg;         
    int flags;                  
};

struct sys_exit_recvmsg_args {
    unsigned long long unused;  
    long syscall_nr;            
    long ret;                   
};

struct sys_enter_pselect6_args {
    unsigned long long unused;  
    long syscall_nr;            
    int nfds;                  
    fd_set *readfds;            
    fd_set *writefds;         
    fd_set *exceptfds;          
    struct timespec *timeout;   
    void *sigmask;              
};

struct sys_exit_pselect6_args {
    unsigned long long unused;  
    long syscall_nr;            
    long ret;                  
};


#define SHARED_DSQ 9

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");


struct pid_slice_info {
	u64 count;
	s64 mean;
	s64 sum_squared_diff;
};

// Store the difference between the time core is selected and time task runs on core
// Gives a rough approximation of the scheduling overhead once a core has been decided
struct pid_timestamps {
	u64 scheduled_ts;
	u64 running_ts;
	bool waiting;	// If a scheduled_ts has a corresponding running_ts;
	u64 total_sched_time;
	u64 num;
	bool is_idle_bypass;
	u32 cpu;
};

struct my_sys_info {
	bool in_blocking_syscall;
	int syscall_nm;	// Not the actual syscall number, just for my own debugging purposes
};

// Used for average and stdev of the slice left when a task stops
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(key_size, sizeof(pid_t));
	__uint(value_size, sizeof(struct pid_slice_info));
	__uint(max_entries, 1000);
} pid_slice_info_map SEC(".maps");

// Used for calculating the scheduling overhead
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(pid_t));
	__uint(value_size, sizeof(struct pid_timestamps));
	__uint(max_entries, 1000);
} pid_timestamps_map SEC(".maps");

// Keeps track of whether a task is currently executing a blocking system call
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct my_sys_info));
	__uint(max_entries, 1000);
} my_sys_info_map SEC(".maps");

static __inline bool is_idle(u32 cpu) {
	const struct cpumask* idle_mask = scx_bpf_get_idle_cpumask();
	if (bpf_cpumask_test_cpu(cpu, idle_mask)) {
		scx_bpf_put_idle_cpumask(idle_mask);
		return true;
	}
	scx_bpf_put_idle_cpumask(idle_mask);
	return false;
}

static bool is_task_in_kernel_mode(struct task_struct *task)
{
    struct pt_regs *regs;

    regs = (struct pt_regs *)bpf_task_pt_regs(task);
    if (!regs) {
        return false;  // Unable to access pt_regs, so to be safe assume user mode
    }
    // Check the cs register to determine user mode (0x3 indicates user mode in x86)
    if ((regs->cs & 0x3) == 0x3) {
		return false;
	} else {
		if (regs->orig_ax > 0) {
			bpf_printk("SYSCALL: %d", regs->orig_ax);
		}
		return true;
	}
}

static bool is_task_in_blocking_syscall(u64 pid) {
	struct my_sys_info* info = bpf_map_lookup_elem(&my_sys_info_map, &pid);
	if (!info) {
		return false;
	}
	return info->in_blocking_syscall;
}

static void update_scheduled_ts(pid_t pid, bool is_idle_bypass, u32 cpu) {
	u64 scheduled_ts = bpf_ktime_get_ns();
	struct pid_timestamps* pid_timestamps = bpf_map_lookup_elem(&pid_timestamps_map, &pid);
	if (pid_timestamps) {
		if (pid_timestamps->waiting) {
			return;
		}
		pid_timestamps->scheduled_ts = scheduled_ts;
		pid_timestamps->waiting = true;
		pid_timestamps->is_idle_bypass = is_idle_bypass;
		pid_timestamps->cpu = cpu;
		bpf_map_update_elem(&pid_timestamps_map, &pid, pid_timestamps, BPF_ANY);
	} else {
		struct pid_timestamps zero = {0};
		bpf_map_update_elem(&pid_timestamps_map, &pid, &zero, BPF_ANY);
	}
}

static void update_running_ts(pid_t pid, u32 cpu) {
	u64 running_ts = bpf_ktime_get_ns();
	struct pid_timestamps* pid_timestamps = bpf_map_lookup_elem(&pid_timestamps_map, &pid);
	if (pid_timestamps) {
		if (cpu == pid_timestamps->cpu) {
			pid_timestamps->running_ts = running_ts;
			++pid_timestamps->num;
			pid_timestamps->waiting = false;
			u64 diff = pid_timestamps->running_ts - pid_timestamps->scheduled_ts;
			pid_timestamps->total_sched_time += diff;
			bpf_map_update_elem(&pid_timestamps_map, &pid, pid_timestamps, BPF_ANY);
			u64 lookup_pid = pid;
			bpf_printk("Idle Bypass: %d, pid %d scheduled in %u nanoseconds onto cpu %u", pid_timestamps->is_idle_bypass, pid, diff, cpu);
		}
	}
}

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

static bool my_select_this_cpu(pid_t pid, u32 iter_cpu) {
	if (!is_idle(iter_cpu)) {
	// Get the task associated with the cpu
		struct rq* iter_rq = scx_bpf_cpu_rq(iter_cpu);
		if (iter_rq) {
			struct task_struct* iter_p = iter_rq->curr;
			if (iter_p) {
				u64 iter_pid = BPF_CORE_READ(iter_p, pid);
				
				// compare its slice with the mean slice
				struct pid_slice_info* iter_pid_slice_info = bpf_map_lookup_elem(&pid_slice_info_map, &iter_pid);
				if (!iter_pid_slice_info) {
					struct pid_slice_info zero = {0};
					bpf_map_update_elem(&pid_slice_info_map, &iter_pid, &zero, BPF_ANY);
				}
				else {
					s64 mean_slice = iter_pid_slice_info->mean;
					bool will_block = is_task_in_blocking_syscall(iter_pid);
					if (will_block && iter_p->scx.slice <= mean_slice) {
						int nqueued = scx_bpf_dsq_nr_queued(iter_cpu);
						if (nqueued == 0) {
							return true;
						}
					}
				}
			}
		}
	}

	return false;
}

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{

	// NOTE: If done in a loop, the verifier will likely reject this. So instead, it is manually unrolled in this way.

	u32 num_cpus = 8;
	u32 cpu;
	pid_t pid = 1;
	if (p) {
		pid = BPF_CORE_READ(p, pid);
	}
	if (my_select_this_cpu(pid, 0)) {
		scx_bpf_dispatch(p, 0, SCX_SLICE_DFL, 0);
		update_scheduled_ts(pid, 1, 0);
		return 0;
	} else if (my_select_this_cpu(pid, 1)) {
		scx_bpf_dispatch(p, 1, SCX_SLICE_DFL, 0);
		update_scheduled_ts(pid, 1, 1);
		return 1;
	} else if (my_select_this_cpu(pid, 2)) {
		scx_bpf_dispatch(p, 2, SCX_SLICE_DFL, 0);
		update_scheduled_ts(pid, 1, 2);
		return 2;
	} else if (my_select_this_cpu(pid, 3)) {
		scx_bpf_dispatch(p, 3, SCX_SLICE_DFL, 0);
		update_scheduled_ts(pid, 1, 3);	
		return 3;	
	} else if (my_select_this_cpu(pid, 4)) {
		scx_bpf_dispatch(p, 4, SCX_SLICE_DFL, 0);
		update_scheduled_ts(pid, 1, 4);	
		return 4;
	} else if (my_select_this_cpu(pid, 5)) {
		scx_bpf_dispatch(p, 5, SCX_SLICE_DFL, 0);
		update_scheduled_ts(pid, 1, 5);	
		return 5;
	} else if (my_select_this_cpu(pid, 6)) {
		scx_bpf_dispatch(p, 6, SCX_SLICE_DFL, 0);
		update_scheduled_ts(pid, 1, 6);	
		return 6;
	} else if (my_select_this_cpu(pid, 7)) {
		scx_bpf_dispatch(p, 7, SCX_SLICE_DFL, 0);
		update_scheduled_ts(pid, 1, 7);	
		return 7;
	}

	bool is_idle = false;

	// Fall back on default core selection at this point
	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc(0);	/* count local queueing */
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		update_scheduled_ts(pid, 0, cpu);

	}

	return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(1);	/* count global queueing */

	if (fifo_sched) {
		scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		/*
		 * Limit the amount of budget that an idling task can accumulate
		 * to one slice.
		 */
		if (vtime_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;

		scx_bpf_dispatch_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
				       enq_flags);
	}
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_consume(cpu);
	scx_bpf_consume(SHARED_DSQ);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
	if (p) {
		pid_t pid = BPF_CORE_READ(p, pid);
		update_running_ts(pid, bpf_get_smp_processor_id());
	}
	if (fifo_sched)
		return;

	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

// in this context, bpf_get_smp_processor_id() gives the cpu that the task is executing on
void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
	pid_t pid = 1;
	if (p) {
		pid = BPF_CORE_READ(p, pid);
	}
	u64 new_data = p->scx.slice;
	struct pid_slice_info* pid_slice_info = bpf_map_lookup_elem(&pid_slice_info_map, &pid);
	if (!pid_slice_info) {
		return;
	}
	pid_slice_info->count += 1;
	s64 delta = new_data - pid_slice_info->mean;
	pid_slice_info->mean += delta / pid_slice_info->count;
	s64 delta2 = new_data - pid_slice_info->mean;
	pid_slice_info->sum_squared_diff = delta * delta2;

	if (fifo_sched)
		return;

	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
	int ret;
	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret < 0) {
		return ret;
	}
	int num_cpus = 8;
	int iter_cpu;
	for (iter_cpu = 0; iter_cpu < num_cpus; ++iter_cpu) {
		ret = scx_bpf_create_dsq(iter_cpu, -1);
		if (ret < 0) {
			return ret;
		}
	}
	return 0;
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(simple_ops,
	       .select_cpu		= (void *)simple_select_cpu,
	       .enqueue			= (void *)simple_enqueue,
	       .dispatch		= (void *)simple_dispatch,
	       .running			= (void *)simple_running,
	       .stopping		= (void *)simple_stopping,
	       .enable			= (void *)simple_enable,
	       .init			= (void *)simple_init,
	       .exit			= (void *)simple_exit,
	       .flags			= SCX_OPS_KEEP_BUILTIN_IDLE,
	       .name			= "simple");



static void on_enter(int syscall_nm) {
	u64 thread_id = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	struct my_sys_info* info = bpf_map_lookup_elem(&my_sys_info_map, &thread_id);
	if (!info) {
		struct my_sys_info new_entry = {1};
		new_entry.syscall_nm = syscall_nm;
		bpf_map_update_elem(&my_sys_info_map, &thread_id, &new_entry, BPF_ANY);
	} else {
		info->in_blocking_syscall = 1;
		info->syscall_nm = syscall_nm;
		bpf_map_update_elem(&my_sys_info_map, &thread_id, info, BPF_ANY);
	}
}

static void on_exit() {
	u64 thread_id = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	struct my_sys_info* info = bpf_map_lookup_elem(&my_sys_info_map, &thread_id);
	if (info) {
		info->in_blocking_syscall = 0;
		info->syscall_nm = 0;
		bpf_map_update_elem(&my_sys_info_map, &thread_id, info, BPF_ANY);
	}
}

SEC("tracepoint/syscalls/sys_enter_read")
int on_read(struct sys_enter_read_args *ctx) {
	on_enter(1);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int on_write(struct sys_enter_write_args *ctx) {
	on_enter(2);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_wait")
int on_epoll_wait(struct sys_enter_epoll_wait_args *ctx) {
	on_enter(3);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int on_recvmsg(struct sys_enter_recvmsg_args *ctx) {
	on_enter(4);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pselect6")
int on_pselect6(struct sys_enter_pselect6_args *ctx) {
	on_enter(5);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int on_read_exit(struct sys_exit_read_args *ctx) {
	on_exit();
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int on_write_exit(struct sys_exit_write_args *ctx) {
	on_exit();
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_wait")
int on_exit_epoll_wait(struct sys_exit_epoll_wait_args *ctx) {
	on_exit();
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int on_exit_recvmsg(struct sys_exit_recvmsg_args *ctx) {
	on_exit();
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_pselect6")
int on_exit_pselect6(struct sys_exit_pselect6_args *ctx) {
	on_exit();
	return 0;
}