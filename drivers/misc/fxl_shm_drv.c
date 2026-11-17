// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/string.h>

#define FXL_SHM_FIXED_VA        0x2026118000ULL
#define FXL_SHM_MAGIC           0x46584C5F4B524E31ULL
#define FXL_SHM_SESSION_TOKEN   0xA94F82E17C3B65D4ULL
#define FXL_SHM_MAX_BATCH       128U
#define FXL_SCRATCH_MAX_PAYLOAD 0x100000U

#define FXL_CMD_NOP             0U
#define FXL_CMD_READ_MEM        3U
#define FXL_CMD_WRITE_MEM       4U
#define FXL_CMD_BATCH_READ      5U

struct fxl_batch_item {
	u64 src_addr;
	u64 dst_offset;
	u32 size;
	s32 status;
	u64 user_tag;
};

struct fxl_shm_header {
	u64 magic;
	u64 session_token;
	u8  reserved_10[0x20];
	u64 protocol_ver;
	u32 req_seq;
	u32 client_pid;
	u32 ack_seq;
	u32 ready;
	s32 target_pid;
	u32 cmd;
	s32 status;
	u32 batch_count;
	u64 target_addr;
} __attribute__((aligned(64)));

struct fxl_kernel_scratch {
	struct fxl_batch_item items[FXL_SHM_MAX_BATCH];
	u8 payload[FXL_SCRATCH_MAX_PAYLOAD];
};

static struct task_struct *g_worker_task;
static struct fxl_kernel_scratch *g_scratch;

static inline u32 fxl_sign_nonce32(u32 nonce)
{
	u64 z = ((u64)nonce ^ 0xA94F82E1ULL) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	z = z ^ (z >> 31);
	u32 sig = (u32)(z & 0xFFFFFFFFULL);
	return (sig == 0) ? 0x13579BDFU : sig;
}

static inline int fxl_verify_session_token(u64 tok)
{
	u32 nonce, sig;
	if (tok == FXL_SHM_SESSION_TOKEN)
		return 1;
	nonce = (u32)(tok >> 32);
	sig = (u32)(tok & 0xFFFFFFFFULL);
	if (nonce == 0 || sig == 0)
		return 0;
	return (fxl_sign_nonce32(nonce) == sig) ? 1 : 0;
}

static struct pid *scan_for_client_pid(int *out_pid, u64 *out_va, u64 *out_token)
{
	int cand_pids[16];
	int cand_cnt = 0;
	struct task_struct *tsk;
	int i;

	rcu_read_lock();
	for_each_process(tsk) {
		if (tsk == g_worker_task)
			continue;
		if (strcmp(tsk->comm, "kgsl_worker") == 0) {
			if (cand_cnt < 16)
				cand_pids[cand_cnt++] = task_pid_nr(tsk);
		}
	}
	rcu_read_unlock();

	for (i = 0; i < cand_cnt; ++i) {
		struct pid *ps = find_get_pid(cand_pids[i]);
		struct task_struct *ctsk;
		u64 auth[2] = { 0, 0 };

		if (!ps)
			continue;
		ctsk = pid_task(ps, PIDTYPE_PID);
		if (ctsk && access_process_vm(ctsk, FXL_SHM_FIXED_VA, auth, sizeof(auth), 0) == (int)sizeof(auth)) {
			if (auth[0] == FXL_SHM_MAGIC && fxl_verify_session_token(auth[1])) {
				*out_pid = cand_pids[i];
				*out_va = FXL_SHM_FIXED_VA;
				*out_token = auth[1];
				return ps;
			}
		}
		put_pid(ps);
	}
	return NULL;
}

static int fxl_worker_thread(void *unused)
{
	struct pid *client_ps = NULL;
	int client_pid = 0;
	u64 client_va = FXL_SHM_FIXED_VA;
	u64 active_token = 0;
	u32 idle_loops = 0;
	u32 no_client_scans = 0;
	struct pid *cached_target_ps = NULL;
	int cached_target_pid = -1;

	while (!kthread_should_stop()) {
		struct task_struct *client_tsk;
		struct fxl_shm_header hdr;
		struct task_struct *target_tsk = NULL;
		u32 req;
		s32 status = 0;
		int n;

		if (!client_ps) {
			client_ps = scan_for_client_pid(&client_pid, &client_va, &active_token);
			if (!client_ps) {
				no_client_scans++;
				msleep_interruptible((no_client_scans < 30) ? 10 : 250);
				continue;
			}
			no_client_scans = 0;
			idle_loops = 0;
		}

		client_tsk = pid_task(client_ps, PIDTYPE_PID);
		if (!client_tsk) {
			put_pid(client_ps);
			client_ps = NULL;
			client_pid = 0;
			active_token = 0;
			continue;
		}

		n = access_process_vm(client_tsk, (unsigned long)client_va, &hdr, sizeof(hdr), 0);
		if (n != (int)sizeof(hdr) || hdr.magic != FXL_SHM_MAGIC || hdr.session_token != active_token) {
			put_pid(client_ps);
			client_ps = NULL;
			client_pid = 0;
			active_token = 0;
			if (cached_target_ps) {
				put_pid(cached_target_ps);
				cached_target_ps = NULL;
				cached_target_pid = -1;
			}
			continue;
		}

		if (hdr.ready != 1U) {
			u32 ready = 1U;
			access_process_vm(client_tsk,
				(unsigned long)(client_va + offsetof(struct fxl_shm_header, ready)),
				&ready, sizeof(ready), FOLL_WRITE);
		}

		if (hdr.req_seq == hdr.ack_seq) {
			idle_loops++;
			if (idle_loops < 32)
				cpu_relax();
			else if (idle_loops < 2000)
				usleep_range(250, 500);
			else
				msleep_interruptible(5);
			continue;
		}

		idle_loops = 0;
		req = hdr.req_seq;

		if (hdr.cmd == FXL_CMD_READ_MEM || hdr.cmd == FXL_CMD_WRITE_MEM || hdr.cmd == FXL_CMD_BATCH_READ) {
			if (hdr.target_pid <= 0) {
				status = -22;
			} else {
				if (!cached_target_ps || cached_target_pid != hdr.target_pid) {
					if (cached_target_ps) {
						put_pid(cached_target_ps);
						cached_target_ps = NULL;
					}
					cached_target_ps = find_get_pid(hdr.target_pid);
					cached_target_pid = cached_target_ps ? hdr.target_pid : -1;
				}
				if (cached_target_ps)
					target_tsk = pid_task(cached_target_ps, PIDTYPE_PID);
				if (!target_tsk)
					status = -3;
			}
		}

		if (status == 0) {
			switch (hdr.cmd) {
			case FXL_CMD_NOP:
				break;
			case FXL_CMD_READ_MEM: {
				u32 sz = hdr.batch_count;
				if (sz == 0 || sz > FXL_SCRATCH_MAX_PAYLOAD || hdr.target_addr < 0x10000ULL) {
					status = -22;
				} else {
					int r = access_process_vm(target_tsk, (unsigned long)hdr.target_addr, g_scratch->payload, (int)sz, 0);
					if (r == (int)sz) {
						int w = access_process_vm(client_tsk,
							(unsigned long)(client_va + sizeof(struct fxl_shm_header)),
							g_scratch->payload, (int)sz, FOLL_WRITE);
						status = (w == (int)sz) ? 0 : -14;
					} else {
						status = -14;
					}
				}
				break;
			}
			case FXL_CMD_WRITE_MEM: {
				u32 sz = hdr.batch_count;
				if (sz == 0 || sz > FXL_SCRATCH_MAX_PAYLOAD || hdr.target_addr < 0x10000ULL) {
					status = -22;
				} else {
					int r = access_process_vm(client_tsk,
						(unsigned long)(client_va + sizeof(struct fxl_shm_header)),
						g_scratch->payload, (int)sz, 0);
					if (r == (int)sz) {
						int w = access_process_vm(target_tsk, (unsigned long)hdr.target_addr, g_scratch->payload, (int)sz, FOLL_WRITE);
						status = (w == (int)sz) ? 0 : -14;
					} else {
						status = -14;
					}
				}
				break;
			}
			case FXL_CMD_BATCH_READ: {
				u32 cnt = hdr.batch_count;
				if (cnt == 0 || cnt > FXL_SHM_MAX_BATCH) {
					status = -22;
				} else {
					int items_sz = (int)(cnt * sizeof(struct fxl_batch_item));
					int rd = access_process_vm(client_tsk,
						(unsigned long)(client_va + sizeof(struct fxl_shm_header)),
						g_scratch->items, items_sz, 0);
					if (rd != items_sz) {
						status = -14;
					} else {
						u32 i;
						for (i = 0; i < cnt; ++i) {
							struct fxl_batch_item *it = &g_scratch->items[i];
							if (it->size == 0 ||
							    it->dst_offset < (u64)items_sz ||
							    it->dst_offset + it->size > FXL_SCRATCH_MAX_PAYLOAD ||
							    it->src_addr < 0x10000ULL) {
								it->status = -22;
								continue;
							}
							{
								int r = access_process_vm(target_tsk, (unsigned long)it->src_addr,
									g_scratch->payload + it->dst_offset, (int)it->size, 0);
								if (r == (int)it->size) {
									int wr = access_process_vm(client_tsk,
										(unsigned long)(client_va + sizeof(struct fxl_shm_header) + it->dst_offset),
										g_scratch->payload + it->dst_offset, (int)it->size, FOLL_WRITE);
									it->status = (wr == (int)it->size) ? 0 : -14;
								} else {
									it->status = -14;
								}
							}
						}
						access_process_vm(client_tsk,
							(unsigned long)(client_va + sizeof(struct fxl_shm_header)),
							g_scratch->items, items_sz, FOLL_WRITE);
						status = 0;
					}
				}
				break;
			}
			default:
				status = -38;
				break;
			}
		}

		access_process_vm(client_tsk,
			(unsigned long)(client_va + offsetof(struct fxl_shm_header, status)),
			&status, sizeof(status), FOLL_WRITE);
		access_process_vm(client_tsk,
			(unsigned long)(client_va + offsetof(struct fxl_shm_header, ack_seq)),
			&req, sizeof(req), FOLL_WRITE);
	}

	if (cached_target_ps)
		put_pid(cached_target_ps);
	if (client_ps)
		put_pid(client_ps);
	return 0;
}

static int __init fxl_shm_drv_init(void)
{
	g_scratch = vmalloc(sizeof(struct fxl_kernel_scratch));
	if (!g_scratch)
		return -ENOMEM;

	g_worker_task = kthread_run(fxl_worker_thread, NULL, "kgsl_worker");
	if (IS_ERR(g_worker_task)) {
		g_worker_task = NULL;
		vfree(g_scratch);
		g_scratch = NULL;
		return -ENOMEM;
	}
	return 0;
}

late_initcall(fxl_shm_drv_init);
