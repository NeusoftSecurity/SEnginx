/**
 * wdfp.h
 *
 * by Paul Yang <y_y@neusoft.com>
 */

#ifndef _WDFP_H_INCLUDED_
#define _WDFP_H_INCLUDED_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/proc_fs.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/rcupdate.h>
#include <linux/dcache.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>


#define WDFP_PROC_DIR "wdfp"
#define WDFP_PROC_ENABLED "enabled"
#define WDFP_PROC_PROTECTION_PATH "protection_path"
#define WDFP_PROC_SCT_ADDR "syscall_table_addr"

#define WDFP_MAX_PATH 2047

typedef
asmlinkage int (*sys_write_p)(unsigned int, const char __user *, size_t);

struct wdfp_pp {
    char *path;
    unsigned int len;
};

struct wdfp {
    u8 enabled;
    sys_write_p orig_write;
    struct wdfp_pp *protection_path;

    u64 cr0;
    unsigned long *sys_call_table;

    struct proc_dir_entry *proc_dir;
    struct proc_dir_entry *proc_enabled;
    struct proc_dir_entry *proc_protection_path;
    struct proc_dir_entry *proc_sct_addr;
};

extern int wdfp_proc_init(struct wdfp *);
extern void wdfp_proc_exit(struct wdfp *);

extern void wdfp_hijack_sys_write(struct wdfp *wdfp);

#endif
