/**
 * wdfp_proc.c
 *
 * by Paul Yang <y_y@neusoft.com>
 */

#include "wdfp.h"


static int wdfp_proc_enabled_read(char *buf, char **start, off_t offset,
        int count, int *eof, void *data)
{
    struct wdfp *wdfp = data;
    int len = 0;

    len = sprintf(buf, "%d\n", wdfp->enabled);

    return len;
}

static int wdfp_proc_enabled_write(struct file *file, const char __user *buffer,
        unsigned long count, void *data)
{
    struct wdfp *wdfp = data;
    char tmp = 0;

    if (count == 0 || count > 2)
        return -EFAULT;

    if (copy_from_user(&tmp, buffer, 1))
        return -EFAULT;

    if(tmp == '1')
        wdfp->enabled = 1;
    else if (tmp == '0')
        wdfp->enabled = 0;
    else
        return -EFAULT;

    return count;
}

static int wdfp_proc_protection_path_read(char *buf, char **start, off_t offset,
        int count, int *eof, void *data)
{
    struct wdfp *wdfp = data;
    int len = 0;
    char *not_set = "wdfp: protection path is not set";
    char *tmp = NULL;
    struct wdfp_pp *pp;

    rcu_read_lock();

    pp = rcu_dereference(wdfp->protection_path);

    if (pp) {
        tmp = kmalloc(pp->len + 1, GFP_KERNEL);
        if (!tmp) {
            rcu_read_unlock();
            return -ENOMEM;
        }

        memcpy(tmp, pp->path, pp->len);
        tmp[pp->len] = 0;
    } else
        tmp = not_set;

    rcu_read_unlock();

    len = sprintf(buf, "%s\n", tmp);

    return len;
}

static int wdfp_proc_protection_path_write(struct file *file,
        const char __user *buffer, unsigned long count, void *data)
{
    struct wdfp *wdfp = data;
    struct wdfp_pp *new = NULL, *old = NULL;
    unsigned long len = count;

    if (count == 0 || count > WDFP_MAX_PATH)
        return -EFAULT;

    new = kmalloc(sizeof(struct wdfp_pp), GFP_KERNEL);
    if (!new)
        return -ENOMEM;

    new->path = kmalloc(count, GFP_KERNEL);
    if (!new->path)
        return -ENOMEM;

    if (copy_from_user(new->path, buffer, count)) {
        kfree(new->path);
        kfree(new);
        return -EFAULT;
    }

    if (new->path[count - 1] == '\n')
        len--;

    new->len = len;

    old = wdfp->protection_path;

    rcu_assign_pointer(wdfp->protection_path, new);
    synchronize_rcu();

    if (old) {
        if (old->path)
            kfree(old->path);
        kfree(old);
    }

    return count;
}

static int wdfp_proc_sct_addr_read(char *buf, char **start, off_t offset,
        int count, int *eof, void *data)
{
    struct wdfp *wdfp = data;
    int len = 0;

    len = sprintf(buf, "0x%lx\n", (unsigned long)wdfp->sys_call_table);

    return len;
}

static int wdfp_proc_sct_addr_write(struct file *file, const char __user *buffer,
        unsigned long count, void *data)
{
    struct wdfp *wdfp = data;
    char *tmp = NULL;
    unsigned long parsed_addr = 0;

    if (count == 0 || count > 17)
        return -EFAULT;

    tmp = kmalloc(count, GFP_KERNEL);
    if (!tmp)
        return -ENOMEM;

    if (copy_from_user(tmp, buffer, count)) {
        kfree(tmp);
        return -EFAULT;
    }

    if (tmp[count - 1] == '\n')
        tmp[count - 1] = 0;

    parsed_addr = simple_strtoul(tmp, NULL, 16);

    if (parsed_addr != 0) {
        wdfp->sys_call_table = (unsigned long *)parsed_addr;
        /* hijack sys_write */
        wdfp_hijack_sys_write(wdfp);
    }

    return count;
}

int wdfp_proc_init(struct wdfp *wdfp)
{
    printk("wdfp: set up entries in proc fs.\n");

    wdfp->proc_dir = proc_mkdir(WDFP_PROC_DIR, NULL);
    if (!wdfp->proc_dir) {
        return -ENOMEM;
    }

    wdfp->proc_dir->read_proc = NULL;
    wdfp->proc_dir->write_proc = NULL;

    wdfp->proc_enabled =
        create_proc_entry(WDFP_PROC_ENABLED, 0644, wdfp->proc_dir);
    if (!wdfp->proc_enabled) {
        return -ENOMEM;
    }

    wdfp->proc_enabled->read_proc = wdfp_proc_enabled_read;
    wdfp->proc_enabled->write_proc = wdfp_proc_enabled_write;
    wdfp->proc_enabled->data = wdfp;

    wdfp->proc_protection_path =
        create_proc_entry(WDFP_PROC_PROTECTION_PATH, 0644, wdfp->proc_dir);
    if (!wdfp->proc_protection_path) {
        return -ENOMEM;
    }

    wdfp->proc_protection_path->read_proc = wdfp_proc_protection_path_read;
    wdfp->proc_protection_path->write_proc = wdfp_proc_protection_path_write;
    wdfp->proc_protection_path->data = wdfp;

    wdfp->proc_sct_addr =
        create_proc_entry(WDFP_PROC_SCT_ADDR, 0644, wdfp->proc_dir);
    if (!wdfp->proc_protection_path) {
        return -ENOMEM;
    }

    wdfp->proc_sct_addr->read_proc = wdfp_proc_sct_addr_read;
    wdfp->proc_sct_addr->write_proc = wdfp_proc_sct_addr_write;
    wdfp->proc_sct_addr->data = wdfp;

    return 0;
}

void wdfp_proc_exit(struct wdfp *wdfp)
{
    printk("wdfp: destroy entries in proc fs.\n");

    remove_proc_entry(wdfp->proc_enabled->name, wdfp->proc_dir);
    remove_proc_entry(wdfp->proc_protection_path->name, wdfp->proc_dir);
    remove_proc_entry(wdfp->proc_sct_addr->name, wdfp->proc_dir);
    remove_proc_entry(wdfp->proc_dir->name, NULL);

    if (wdfp->protection_path) {
        kfree(wdfp->protection_path->path);
        kfree(wdfp->protection_path);
    }
}
