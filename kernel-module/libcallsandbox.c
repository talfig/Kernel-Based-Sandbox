
// SPDX-License-Identifier: MIT
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/hashtable.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/kprobes.h>

#define DEVICE_NAME "libcallsandbox"

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Your Team");
MODULE_DESCRIPTION("In-kernel per-process libcalls sandbox enforcing dummy() automata");
MODULE_VERSION("1.0");

// ---------------------- Policy format (compact NFA) ----------------------

struct edge {
  u32 src;
  u32 dst;
  s32 match_id;    // id to match: either dummyID or uniqueID depending on id_mode
  u8  is_epsilon;  // 1 if epsilon
};

struct policy_blob {
  u32 pid;
  u32 num_nodes;
  u32 num_edges;
  u32 id_mode;     // 0=dummy, 1=unique
  // Followed by num_edges * struct edge
  // Start set assumed: all nodes with in-degree==0 (simple heuristic)
};

struct frontier {
  u32 num_nodes;
  unsigned long *bitmap; // bitset of active states
};

struct proc_policy {
  u32 pid;
  u32 num_nodes;
  u32 num_edges;
  u32 id_mode;
  struct edge *edges; // array
  struct frontier fr;
  struct hlist_node hnode;
};

DEFINE_HASHTABLE(proc_tbl, 8); // 256 buckets
static DEFINE_MUTEX(tbl_lock);

// Allocate and zero a frontier
static int frontier_init(struct frontier *fr, u32 n)
{
  fr->num_nodes = n;
  fr->bitmap = kcalloc(BITS_TO_LONGS(n), sizeof(unsigned long), GFP_KERNEL);
  if (!fr->bitmap) return -ENOMEM;
  return 0;
}

static void frontier_free(struct frontier *fr)
{
  kfree(fr->bitmap);
  fr->bitmap = NULL;
  fr->num_nodes = 0;
}

static void frontier_set(struct frontier *fr, u32 idx)
{
  __set_bit(idx, fr->bitmap);
}

static bool frontier_test(struct frontier *fr, u32 idx)
{
  return test_bit(idx, fr->bitmap);
}

static void frontier_clear_all(struct frontier *fr)
{
  bitmap_zero(fr->bitmap, fr->num_nodes);
}

// Compute epsilon-closure: repeatedly add dst for every epsilon edge from active states
static void epsilon_closure(struct proc_policy *pp)
{
  bool changed;
  do {
    changed = false;
    for (u32 i = 0; i < pp->num_edges; ++i) {
      struct edge *e = &pp->edges[i];
      if (!e->is_epsilon)
        continue;
      if (frontier_test(&pp->fr, e->src) && !frontier_test(&pp->fr, e->dst)) {
        frontier_set(&pp->fr, e->dst);
        changed = true;
      }
    }
  } while (changed);
}

// Advance on an observed id (dummy/unique)
static void advance_frontier(struct proc_policy *pp, s32 observed)
{
  // new frontier
  unsigned long *next = kcalloc(BITS_TO_LONGS(pp->fr.num_nodes), sizeof(unsigned long), GFP_ATOMIC);
  if (!next) return;

  for (u32 i = 0; i < pp->num_edges; ++i) {
    struct edge *e = &pp->edges[i];
    if (e->is_epsilon) continue;
    if (e->match_id != observed) continue;
    if (frontier_test(&pp->fr, e->src)) {
      __set_bit(e->dst, next);
    }
  }

  // replace frontier
  memcpy(pp->fr.bitmap, next, BITS_TO_LONGS(pp->fr.num_nodes) * sizeof(unsigned long));
  kfree(next);

  // epsilon closure after move
  epsilon_closure(pp);
}

static bool frontier_empty(struct frontier *fr)
{
  for (u32 i = 0; i < BITS_TO_LONGS(fr->num_nodes); ++i) {
    if (fr->bitmap[i]) return false;
  }
  return true;
}

// ---------------------- Policy table helpers ----------------------

static struct proc_policy *lookup_ppid(u32 pid)
{
  struct proc_policy *pp;
  hash_for_each_possible(proc_tbl, pp, hnode, pid) {
    if (pp->pid == pid) return pp;
  }
  return NULL;
}

// ---------------------- IOCTL interface ----------------------

#define IOCTL_MAGIC 'L'
#define IOCTL_LOAD_POLICY _IOW(IOCTL_MAGIC, 0x01, struct policy_blob*)

static long sandbox_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
  if (cmd == IOCTL_LOAD_POLICY) {
    struct policy_blob hdr;
    if (copy_from_user(&hdr, (void __user *)arg, sizeof(hdr)))
      return -EFAULT;
    if (hdr.num_nodes == 0 || hdr.num_edges > (1u<<20)) // sanity
      return -EINVAL;

    // allocate kernel copy
    struct policy_blob *ub = (struct policy_blob*)arg;
    struct edge *edges = kcalloc(hdr.num_edges, sizeof(struct edge), GFP_KERNEL);
    if (!edges) return -ENOMEM;
    if (copy_from_user(edges, (void __user *)(ub + 1), hdr.num_edges * sizeof(struct edge))) {
      kfree(edges);
      return -EFAULT;
    }

    // create/replace entry
    mutex_lock(&tbl_lock);
    struct proc_policy *pp = lookup_ppid(hdr.pid);
    if (pp) {
      hash_del(&pp->hnode);
      kfree(pp->edges);
      frontier_free(&pp->fr);
      kfree(pp);
    }
    pp = kzalloc(sizeof(*pp), GFP_KERNEL);
    if (!pp) { mutex_unlock(&tbl_lock); kfree(edges); return -ENOMEM; }
    pp->pid = hdr.pid;
    pp->num_nodes = hdr.num_nodes;
    pp->num_edges = hdr.num_edges;
    pp->id_mode = hdr.id_mode;
    pp->edges = edges;
    frontier_init(&pp->fr, hdr.num_nodes);

    // Initialize start set: nodes with in-degree 0
    {
      u32 *indeg = kcalloc(hdr.num_nodes, sizeof(u32), GFP_KERNEL);
      if (indeg) {
        for (u32 i = 0; i < hdr.num_edges; ++i) {
          if (!edges[i].is_epsilon) // count only consuming edges for start heuristic
            indeg[edges[i].dst]++;
        }
        for (u32 n = 0; n < hdr.num_nodes; ++n) {
          if (indeg[n] == 0) frontier_set(&pp->fr, n);
        }
        kfree(indeg);
      } else {
        // fallback: start at node 0
        frontier_set(&pp->fr, 0);
      }
      epsilon_closure(pp);
    }

    hash_add(proc_tbl, &pp->hnode, pp->pid);
    mutex_unlock(&tbl_lock);

    pr_info(DEVICE_NAME ": loaded policy for pid=%u nodes=%u edges=%u mode=%s\n",
            pp->pid, pp->num_nodes, pp->num_edges, pp->id_mode ? "unique" : "dummy");
    return 0;
  }
  return -ENOTTY;
}

static const struct file_operations sandbox_fops = {
  .owner = THIS_MODULE,
  .unlocked_ioctl = sandbox_ioctl,
#ifdef CONFIG_COMPAT
  .compat_ioctl = sandbox_ioctl,
#endif
};

static struct miscdevice sandbox_dev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = DEVICE_NAME,
  .fops = &sandbox_fops,
  .mode = 0600,
};

// ---------------------- Hook into dummy syscall ----------------------

static struct kprobe kp = {
  .symbol_name = "__x64_sys_dummy", // x86-64; adjust for your arch
};

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
#ifdef CONFIG_X86_64
  s32 id = (s32)regs->di; // first arg
#else
  s32 id = 0; // TODO: arch-specific
#endif
  u32 pid = (u32)task_pid_nr(current);

  mutex_lock(&tbl_lock);
  struct proc_policy *pp = lookup_ppid(pid);
  if (pp) {
    advance_frontier(pp, id);
    if (frontier_empty(&pp->fr)) {
      pr_err(DEVICE_NAME ": policy violation pid=%u on id=%d, sending SIGKILL\n", pid, id);
      send_sig(SIGKILL, current, 0);
    }
  }
  mutex_unlock(&tbl_lock);
  return 0;
}

static int __init sandbox_init(void)
{
  int ret = misc_register(&sandbox_dev);
  if (ret) return ret;

  kp.pre_handler = handler_pre;
  ret = register_kprobe(&kp);
  if (ret) {
    pr_err(DEVICE_NAME ": kprobe register failed: %d\n", ret);
    misc_deregister(&sandbox_dev);
    return ret;
  }

  pr_info(DEVICE_NAME ": initialized; device /dev/%s\n", DEVICE_NAME);
  return 0;
}

static void __exit sandbox_exit(void)
{
  unregister_kprobe(&kp);
  misc_deregister(&sandbox_dev);

  // free policies
  int bkt;
  struct proc_policy *pp;
  struct hlist_node *tmp;
  mutex_lock(&tbl_lock);
  hash_for_each_safe(proc_tbl, bkt, tmp, pp, hnode) {
    hash_del(&pp->hnode);
    kfree(pp->edges);
    frontier_free(&pp->fr);
    kfree(pp);
  }
  mutex_unlock(&tbl_lock);
}

module_init(sandbox_init);
module_exit(sandbox_exit);
