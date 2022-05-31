#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <uapi/linux/mount.h>
#include "internal.h"

struct dentry *seccompfs_setup(struct super_block *sb, struct dentry *parent_d,
        const char *name, unsigned int ino, umode_t mode);

static const struct super_operations seccompfs_sops;
static const struct inode_operations seccompfs_inode_ops;
static const struct file_operations  seccompfs_dir_ops;

/* dentry pointers */
static struct dentry *config_dentry_p;
static struct dentry *begin_dentry_p;

/* seccomp_info list */
LIST_HEAD(seccomp_info_list);
int seccomp_info_list_len = 0;

/* seccomp_info now */
static struct seccomp_info* seccomp_info_now;

/* seccomp_info operations */
struct seccomp_info *new_seccomp_info(void)
{
    struct seccomp_info* this;

    this = kmalloc(sizeof(struct seccomp_info), GFP_KERNEL);
    if (!this)
        return NULL;

    this->pid = 0;
    this->len = 0;
    this->dir = NULL;
    this->log = NULL;

    return this;
}

void seccomp_info_set_filters(struct seccomp_info* this, pid_t pid,
        unsigned int len, unsigned int *filter)
{
    int i;

    this->pid = pid;
    this->len = len;
    for (i = 0; i < len; ++i)
        this->filter[i] = filter[i];
}

int seccomp_info_create_file(struct seccomp_info* this, struct super_block *sb)
{
    char dir_name[BUF_SIZE];

    // init dir
    sprintf(dir_name, "%d", this->pid);
    this->dir = seccompfs_setup(sb, sb->s_root, dir_name, INO_DIR(this->pid),
            S_IFDIR | 0500);
    if (!this->dir) {
        pr_info("seccompfs_fill_super: setup dir error.");
        return -ENOMEM;
    }

    // init log
    this->log = seccompfs_setup(sb, this->dir, "log", INO_LOG(this->pid),
            S_IFREG | 0400);
    if (!this->dir) {
        pr_info("seccompfs_fill_super: setup log error.");
        return -ENOMEM;
    }

    return 0;
}

struct seccomp_info *get_seccomp_info_by_pid(pid_t pid) {
    struct seccomp_info* item;

    list_for_each_entry(item, &seccomp_info_list, list) {
        if (pid == item->pid) {
            return item;
        }
    }
    return NULL;
}

struct seccomp_info *get_seccomp_info_by_dir_ino(unsigned int ino) {
    struct seccomp_info* item;

    list_for_each_entry(item, &seccomp_info_list, list) {
        if (ino == INO_DIR(item->pid)) {
            return item;
        }
    }
    return NULL;
}

struct bpf_prog *seccomp_info_to_bpf_prog(struct seccomp_info *this)
{
    struct bpf_prog *pf = NULL;
    struct sock_fprog_kern fprog;
    int i;
    int ret;

    fprog.len    = this->len + 3;
    fprog.filter = kmalloc(sizeof(struct sock_filter) * fprog.len, GFP_KERNEL);

    if (!fprog.filter)
        return NULL;

    // A = sys_number
    // if (A == filter[i]) jump ALLOW
    // return KILL
    // return ALLOW
    fprog.filter[0]             = (struct sock_filter){0x20, 0, 0, 0};
    for (i = 0; i < this->len; ++i)
        fprog.filter[i + 1]     = (struct sock_filter){0x15, this->len - i, 0,
            this->filter[i]};
    fprog.filter[this->len + 1] = (struct sock_filter){0x06, 0, 0, 0};
    fprog.filter[this->len + 2] = (struct sock_filter){0x06, 0, 0, 0x7fff0000};

    /* for (i = 0; i < fprog.len; ++i) {
        pr_err("%d %d %d %d\n", 
                fprog.filter[i].code,
                fprog.filter[i].jt,
                fprog.filter[i].jf,
                fprog.filter[i].k);
    } */

    ret = bpf_prog_create_haha(&pf, &fprog, seccomp_check_filter);
    if (ret)
        return NULL;

    return pf;
}

// Check seccomp_prepare_filter
struct seccomp_filter *seccomp_info_to_seccomp_filter(struct seccomp_info *this)
{
    struct seccomp_filter *sfilter;

    sfilter = kzalloc(sizeof(*sfilter), GFP_KERNEL | __GFP_NOWARN);
    if (!sfilter)
        return NULL;

    mutex_init(&sfilter->notify_lock);
    sfilter->prog = seccomp_info_to_bpf_prog(this);
    if (!sfilter->prog) {
        kfree(sfilter);
        return NULL;
    }
    sfilter->log = true;
    sfilter->prev = NULL;

    refcount_set(&sfilter->usage, 1);

    return sfilter;
}

// Check seccomp_attach_filter
int seccomp_info_attach_filter(struct seccomp_info *this) {
    struct task_struct * task;
    struct seccomp_filter *filter;

    filter = seccomp_info_to_seccomp_filter(this);
    if (!filter)
        return -ENOMEM;

    task = find_task_by_pid_ns(this->pid, &init_pid_ns);
 	if (!task) {
 		pr_err("pid not exists.\n");
 		return -EFAULT;
 	}

    spin_lock_irq(&task->sighand->siglock);
    
    task_set_no_new_privs(task);

    filter->prev = task->seccomp.filter;
	task->seccomp.filter = filter;

    task->seccomp.mode = SECCOMP_MODE_FILTER;
	smp_mb__before_atomic();
    set_tsk_thread_flag(task, TIF_SECCOMP);

    spin_unlock_irq(&task->sighand->siglock);

    return 0;
}

/* copied from libfs.c */
static inline unsigned char dt_type(struct inode *inode)
{
    return (inode->i_mode >> 12) & 15;
}

/* cd needs lookup, ls needs iterate */
static int seccompfs_iterate(struct file *file, struct dir_context *dc)
{
    unsigned int count;
    unsigned int ino;
    struct seccomp_info *item;

    ino = file_inode(file)->i_ino;
    pr_info("%s called %d %p\n", __func__, ino, file);

    if (ino == INO_ROOT) {
        // . and ..
        if (dc->pos == 0) {
            dir_emit_dots(file, dc);
        }
        // config
        if (dc->pos == 2) {
            dir_emit(dc, config_dentry_p->d_name.name,
                    config_dentry_p->d_name.len,
                    d_inode(config_dentry_p)->i_ino,
                    dt_type(d_inode(config_dentry_p)));
            dc->pos++;
        }
        // begin
        if (dc->pos == 3) {
            dir_emit(dc, begin_dentry_p->d_name.name, 
                    begin_dentry_p->d_name.len, 
                    d_inode(begin_dentry_p)->i_ino, 
                    dt_type(d_inode(begin_dentry_p)));
            dc->pos++;
        }
        // pids
        count = dc->pos - 4;
        list_for_each_entry(item, &seccomp_info_list, list) {
            if (!count) {
                dir_emit(dc, item->dir->d_name.name, 
                        item->dir->d_name.len, 
                        d_inode(item->dir)->i_ino, 
                        dt_type(d_inode(item->dir)));
                dc->pos += 1;
            }
            else
                count--;
        }
    }
    else {
        // . and ..
        if (dc->pos == 0) {
            dir_emit_dots(file, dc);
        }
        if (dc->pos > 2) {
            return 0;
        }
        // log
        item = get_seccomp_info_by_dir_ino(ino);
        if (item) {
            dir_emit(dc, item->log->d_name.name, 
                    item->log->d_name.len, 
                    d_inode(item->log)->i_ino, 
                    dt_type(d_inode(item->log)));
            dc->pos += 1;
        }
    }

    return 0;
}

// dummy
static ssize_t seccompfs_read(struct file *file, char __user *buf,
        size_t count, loff_t *ppos)
{
    return count;
}

/* static ssize_t seccompfs_read(struct file *file, char __user *buf,
        size_t count, loff_t *ppos) 
{
    int i = 0;
    int written = 0;
    char * s = "hello world!\n";
    pr_info("%s called\n", __func__);
    if (*ppos > 12 || *ppos < 0) {
        pr_info("read return 0, *ppos: %lld\n", *ppos);
        return 0;
    }
    if (count > 13 - *ppos)
        count = 13 - *ppos;
    copy_to_user(buf, &(s[*ppos]), count);
    *ppos += count;
    pr_info("read %ld\n", count);
    return count;
} */

static int get_long(char **buf, long *val)
{
    char *token;
    int ret;

    token = strsep(buf, ",");
    if (token == NULL) {
        pr_err("seccompfs: strsep error.\n");
        return -EFAULT;
    }

    ret = kstrtol(token, 10, val);
    if (ret) {
        pr_err("seccompfs: kstrtol error.\n");
        return ret;
    }

    return 0;
}

static int handle_config (char *buf, size_t count)
{
    long val;
    int i, ret;
    pid_t pid;
    unsigned int len;
    unsigned int filter[MAX_FILTER];

    pr_info("%s called\n", __func__);
    pr_info("===== CONFIG INFO =====\n");

    // get pid
    ret = get_long(&buf, &val);
    if (ret) {
        return ret;
    }
    pid = (pid_t)val;
    pr_info("pid = %d\n", pid);

    // get len
    ret = get_long(&buf, &val);
    if (ret) {
        return ret;
    }
    len = val;
    pr_info("len = %d\n", len);

    // get filter
    if (len > MAX_FILTER)
        return -EFAULT;
    for (i = 0; i < len; ++i) {
        ret = get_long(&buf, &val);
        if (ret)
            return ret;
        filter[i] = (pid_t)val;
        pr_info("filter[%d] = %d\n", i, filter[i]);
    }

    pr_info("=======================\n");

    // all correct, save to into seccomp_info_now
    seccomp_info_set_filters(seccomp_info_now, pid, len, filter);

    return 0;
}

static int handle_begin (struct super_block *sb) {
    struct task_struct * task;
    int ret;

    // no config set
    if (seccomp_info_now->len == 0) {
 		pr_err("config first.\n");
        return -EFAULT;
    }

    // check already set
    if (get_seccomp_info_by_pid(seccomp_info_now->pid)) {
 		pr_err("pid already set.\n");
        return -EFAULT;
    }

    // check exists of pid
    task = find_task_by_pid_ns(seccomp_info_now->pid, &init_pid_ns);
 	if (!task) {
 		pr_err("pid not exists.\n");
 		return -EFAULT;
 	}

    // attach seccomp filter
    ret = seccomp_info_attach_filter(seccomp_info_now);
    if (ret)
        return ret;

    // post process
    seccomp_info_create_file(seccomp_info_now, sb);
    list_add(&(seccomp_info_now->list), &seccomp_info_list);
    seccomp_info_list_len++;
    seccomp_info_now = new_seccomp_info();

    return 0;
}

static ssize_t seccomp_write(struct file *file, const char __user *buf,
                            size_t count, loff_t *ppos) {
    int ret = 0;
    char kbuf[BUF_SIZE];
    count = (count > BUF_SIZE - 1)? (count > BUF_SIZE - 1): count;
    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;
    kbuf[count] = 0;

    switch (file_inode(file)->i_ino) {
        case INO_CONFIG:
            ret = handle_config(kbuf, count);
            printk("CONFIG\n");
            break;
        case INO_BEGIN:
            ret = handle_begin(file_inode(file)->i_sb);
            printk("BEGIN\n");
            break;
        default:
            printk("WTF\n");
    }
    // Cheat it
    return ret < 0? -EFAULT: count;
}

static const struct file_operations seccompfs_file_fops = {
    .read   = seccompfs_read,
    .write  = seccomp_write,
    .llseek = noop_llseek,
};
static const struct inode_operations seccompfs_dir_inode_ops = {
    .lookup  = simple_lookup, 
    .getattr = simple_getattr,
};

/* static const struct inode_operations seccompfs_inode_ops = {
	.lookup		= simple_lookup,
	.getattr	= simple_getattr,
}; */


/* static const struct file_operations seccompfs_dir_ops = {
	// Define dir operations here (e.g. open, iterate, close, release ...)
	// check out `fs/libfs.c` and `include/linux/fs.h`
}; */
static const struct file_operations seccompfs_dir_fops = {
    .iterate_shared = seccompfs_iterate, 
};

static const struct inode_operations seccompfs_file_inode_ops = {
    .lookup = simple_lookup, 
    .getattr = simple_getattr,
};

static const struct super_operations seccompfs_sops = {
    .statfs = simple_statfs,
    .drop_inode = generic_delete_inode,
};

/* allocate a new inode
 * ino convention
 * config INO_CONFIG
 * begin  INO_BEGIN
 * dir    pid * 2 + INO_SHIFT
 * log    pid * 2 + INO_SHIFT + 1
 */
static struct inode *seccompfs_get_inode(struct super_block *sb,
        unsigned int ino, const struct inode *dir, umode_t mode)
{
    struct inode *inode = new_inode(sb);
    pr_info("%s called\n", __func__);

    if (inode) {
        inode->i_ino   = ino;
        inode->i_mode  = mode;
        inode_init_owner(inode, dir, mode);
        inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);

        switch (mode & S_IFMT) {
            case S_IFDIR:
                inode->i_op  = &seccompfs_dir_inode_ops;
                inode->i_fop = &seccompfs_dir_fops;
                inc_nlink(inode);
                break;
            case S_IFREG:
                inode->i_op  = &seccompfs_file_inode_ops;
                inode->i_fop = &seccompfs_file_fops;
                break;
            case S_IFLNK:
            default:
                pr_err("only root inode now\n");
                return NULL;
                break;
        }
    }
    return inode;
}

struct dentry *seccompfs_setup(struct super_block *sb, struct dentry *parent_d,
        const char *name, unsigned int ino, umode_t mode)
{
    struct inode  *parent_inode = d_inode(parent_d);
    struct inode  *new_inode;
    struct dentry *new_d;

    pr_info("%s called\n", __func__);

    inode_lock(parent_inode);
    new_d = d_alloc_name(parent_d, name);
    if (new_d) {
        new_inode = seccompfs_get_inode(sb, ino, parent_inode, mode);
        if (new_inode)
            d_add(new_d, new_inode);
        else
            dput(new_d);
    }
    inode_unlock(parent_inode);

    return new_d;
}

static int seccompfs_fill_super(struct super_block *sb, struct fs_context * fc)
{
	// Initialize struct super_block here (e.g. s_flags, s_op, s_root, ...)
    struct inode * inode;

    pr_info("%s called\n", __func__);

    sb->s_iflags |= SB_I_NOEXEC | SB_I_NODEV;
    sb->s_flags |= SB_NOSUID | SB_NOEXEC | SB_DIRSYNC | SB_NODIRATIME;
    sb->s_blocksize = PAGE_SIZE;
    sb->s_blocksize_bits = PAGE_SHIFT;
    sb->s_magic = 0xEEEEFFFF;
    sb->s_op = &seccompfs_sops;
    sb->s_time_gran = 1;

    // init root
    inode = seccompfs_get_inode(sb, INO_ROOT, NULL, S_IFDIR | 0755);
    sb->s_root = d_make_root(inode);
    if (!sb->s_root)
        return -ENOMEM;

    // init config
    config_dentry_p = seccompfs_setup(sb, sb->s_root, "config", INO_CONFIG,
            S_IFREG | 0200);
    if (!config_dentry_p) {
        pr_info("seccompfs_fill_super: setup config error.");
        return -ENOMEM;
    }

    // init begin
    begin_dentry_p = seccompfs_setup(sb, sb->s_root, "begin", INO_BEGIN,
            S_IFREG | 0200);
    if (!begin_dentry_p) {
        pr_info("seccompfs_fill_super: setup begin error.");
        return -ENOMEM;
    }

    // init seccomp_info
    seccomp_info_now = new_seccomp_info();

    return 0;
}

/* this should free the dentry */
static void seccompfs_kill_sb(struct super_block *sb)
{
    pr_info("%s called\n", __func__);
    // simple_unlink(d_inode(sb->s_root), config_dentry_p);
    // simple_unlink(d_inode(sb->s_root), begin_dentry_p);
    // d_delete(config_dentry_p);
    // d_delete(begin_dentry_p);
    // dput(config_dentry_p);
    // dput(begin_dentry_p);
    kill_litter_super(sb);
}

static void seccompfs_free_fc(struct fs_context *fc)
{
    pr_info("%s called\n", __func__);
    return;
}

static int seccompfs_get_tree(struct fs_context *fc)
{
	// Call the appropriate get_tree_ API
	// check out `get_tree_*` in `fs/super.c`
    pr_info("%s called\n", __func__);
    return get_tree_nodev(fc, seccompfs_fill_super);
}

static const struct fs_context_operations seccompfs_context_ops = {
    .free       = seccompfs_free_fc,
    .get_tree   = seccompfs_get_tree,
};

static int seccompfs_init_fs_context(struct fs_context *fc)
{
	// Initialize fs_context here (e.g. ops)
    pr_info("%s called\n", __func__);
    fc->ops = &seccompfs_context_ops;
    return 0;
}

static struct file_system_type seccompfs_type = {
    .name = "seccompfs",
    .init_fs_context = seccompfs_init_fs_context,
    .kill_sb = seccompfs_kill_sb, 
};

static int __init init_seccompfs(void)
{
	int ret;
	struct vfsmount *mount;

	ret = register_filesystem(&seccompfs_type);
	if (ret < 0)
		return ret;

	mount = kern_mount(&seccompfs_type);
	if (IS_ERR(mount))
		return PTR_ERR(mount);

	return 0;
}

fs_initcall(init_seccompfs);
