/**
 * wdfp_main.c
 *
 * by Paul Yang <y_y@neusoft.com>
 */

#include "wdfp.h"

/* the main wdfp */
static struct wdfp *wdfp = NULL;

static u64 wdfp_clear_and_save_cr0(void)
{
    u64 cr0 = 0;
    u64 ret;

    asm volatile ("mov %%cr0, %0"
            :"=a"(cr0)
            );

    ret = cr0;
    cr0 &= 0xfffffffffffeffff;

    asm volatile ("mov %0, %%cr0"
            :
            :"a"(cr0)
            );

    return ret;
}

static void wdfp_restore_cr0(u64 cr0)
{
    asm volatile ("mov %0, %%cr0"
            :
            :"a"(cr0)
            );
}

asmlinkage int wdfp_sys_write(unsigned int fd, const char __user *buf,
        size_t count)
{
    struct wdfp_pp *pp;
    struct file *file;
    char *tmp, *full_path;

    if (!wdfp->enabled) {
        return wdfp->orig_write(fd, buf, count);
    }

    tmp = kmalloc(WDFP_MAX_PATH + 1, GFP_KERNEL);
    if (!tmp)
        return -ENOMEM;

    memset(tmp, 0, WDFP_MAX_PATH + 1);

    rcu_read_lock();

    pp = rcu_dereference(wdfp->protection_path);

    if (!pp) {
        rcu_read_unlock();
        return wdfp->orig_write(fd, buf, count);
    }

    /* protection path is set */
    file = fget(fd);
    if (file) {
        /* check permission */
        full_path = d_path(&file->f_path, tmp, WDFP_MAX_PATH);
        if (IS_ERR(full_path)) {
            goto out;
        }

        /* get the full path */
        if (strlen(full_path) < pp->len) {
            /* is not the protection path, pass */
            goto out;
        }

        if (!memcmp(full_path, pp->path, pp->len)) {
            fput(file);
            rcu_read_unlock();

            kfree(tmp);

            return -EACCES;
        }
    }

out:
    fput(file);
    rcu_read_unlock();

    kfree(tmp);

    return wdfp->orig_write(fd, buf, count);
}

void wdfp_hijack_sys_write(struct wdfp *wdfp)
{
    if (wdfp->sys_call_table) {
        wdfp->orig_write = (sys_write_p)wdfp->sys_call_table[__NR_write];

        wdfp->cr0 = wdfp_clear_and_save_cr0();
        wdfp->sys_call_table[__NR_write] = (unsigned long)wdfp_sys_write;
        wdfp_restore_cr0(wdfp->cr0);
    }

    printk("wdfp: sys_write hijacked.\n");
}

void wdfp_restore_sys_write(struct wdfp *wdfp)
{
    if(wdfp->sys_call_table) {
        wdfp->cr0 = wdfp_clear_and_save_cr0();

        wdfp->sys_call_table[__NR_write] = (unsigned long)(wdfp->orig_write);

        wdfp_restore_cr0(wdfp->cr0);
        printk("wdfp: sys_write recovered.\n");
    }
}

static int wdfp_init(void)
{
    int ret;

    printk("wdfp: module init.\n");

    wdfp = kmalloc(sizeof(struct wdfp), GFP_KERNEL);
    if (!wdfp) {
        return -ENOMEM;
    }

    memset(wdfp, 0, sizeof(struct wdfp));

    /* set up proc file system entries */
    ret = wdfp_proc_init(wdfp);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

static void wdfp_cleanup(void)
{
    printk("wdfp: module clean up.\n");
    /* set back sys_write */
    wdfp_restore_sys_write(wdfp);

    /* destroy entries in proc file system */
    wdfp_proc_exit(wdfp);

    kfree(wdfp);

    return;
}

module_init(wdfp_init);
module_exit(wdfp_cleanup);

MODULE_LICENSE("GPL");
