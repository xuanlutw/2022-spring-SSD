#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/time.h>
#include <uapi/linux/mount.h>
#include "internal.h"
#define INO_ROOT   1

static const struct super_operations seccompfs_sops;
static const struct inode_operations seccompfs_inode_ops;
static const struct file_operations  seccompfs_dir_ops;

/* temp dentry pointer for "config" */
static struct dentry *config_dentry_p;
static struct dentry *begin_dentry_p;

/* temp seccomp info list */
static struct seccomp_info * seccomp_info_list = NULL;

/* copied from libfs.c */
static inline unsigned char dt_type(struct inode *inode)
{
    return (inode->i_mode >> 12) & 15;
}

/* cd needs lookup, ls needs iterate */
static int seccompfs_iterate(struct file *file, struct dir_context *dc)
{
    pr_info("%s called\n", __func__);

    if (file->f_inode->i_ino = INO_ROOT) {
        if (dc->pos == 0) {
            dir_emit_dots(file, dc);
        }
        if (dc->pos == 2) {
            dir_emit(dc, config_dentry_p->d_name.name,
                    config_dentry_p->d_name.len,
                    d_inode(config_dentry_p)->i_ino,
                    dt_type(d_inode(config_dentry_p)));
            dir_emit(dc, begin_dentry_p->d_name.name, 
                    begin_dentry_p->d_name.len, 
                    d_inode(begin_dentry_p)->i_ino, 
                    dt_type(d_inode(begin_dentry_p)));
            dc->pos += 2;
        }
        // TODO OTHERS
    }
    else {
        printk("PIDHIHI");
    }

    return 0;
}

static ssize_t seccompfs_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) 
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
}

static ssize_t seccomp_write(struct file *file, const char __user *buf,
                            size_t count, loff_t *ppos) {
    if (!(file->f_inode))
        return -EFAULT;
    switch (file->f_inode->i_ino) {
        case INO_CONFIG:
            printk("CONFIG\n");
            break;
        case INO_BEGIN:
            printk("BEGIN\n");
            break;
        default:
            printk("WTF\n");
    }
    // Cheat it
    return count;
}

static ssize_t config_write(struct file *file, const char __user *buf,
                            size_t count, loff_t *ppos)
{
    char buffer[BUF_SIZE];
    char *token, *cur = buffer;
    struct seccomp_info *info;
    long val;
    int i, ret;

    pr_info("%s called\n", __func__);

    memset(buffer, 0, sizeof(buffer));
    if (count > sizeof(buffer) - 1)
        count = sizeof(buffer) - 1;
    if (copy_from_user(buffer, buf, count))
        return -EFAULT;

    info = (struct seccomp_info *)kmalloc(sizeof(struct seccomp_info), GFP_KERNEL);

    /* Need to handle input errors. */
    token = strsep(&cur, ",");
    ret = kstrtol(token, 10, &val);
    if (ret)
        pr_err("seccompfs: config_write kstrtol error.\n");
    info->pid = (pid_t)val;
    pr_info("config_write pid: %d\n", info->pid);

    token = strsep(&cur, ",");
    ret = kstrtol(token, 10, &val);
    if (ret)
        pr_err("seccompfs: config_write kstrtol error.\n");
    info->len = (short int)val;
    pr_info("config_write len: %d\n", info->len);

    pr_info("config_write seccomp list:\n");
    info->seccomp_list = (short int *)kmalloc(info->len * sizeof(short int), GFP_KERNEL);
    for (i = 0; i < info->len; ++i) {
        token = strsep(&cur, ",");
        ret = kstrtol(token, 10, &val);
        if (ret)
            pr_err("seccompfs: config_write kstrtol error.\n");

        info->seccomp_list[i] = (short int)val;
        pr_info("%d %d\n", i, info->seccomp_list[i]);
    }

    info->next = seccomp_info_list;
    seccomp_info_list = info;

    return count;
}

static ssize_t begin_write(struct file *file, const char __user *buf,
                            size_t count, loff_t *ppos)
{
    char buffer[BUF_SIZE];
    char *token, *cur = buffer;
    long val;
    pid_t pid;
    int ret;

    pr_info("%s called\n", __func__);

    memset(buffer, 0, sizeof(buffer));
    if (count > sizeof(buffer) - 1)
        count = sizeof(buffer) - 1;
    if (copy_from_user(buffer, buf, count))
        return -EFAULT;

    /* Need to handle input errors. */
    token = strsep(&cur, ",");
    ret = kstrtol(token, 10, &val);
    if (ret)
        pr_err("seccompfs: begin_write kstrtol error.\n");
    pid = (pid_t)val;
    pr_info("begin_write pid: %d\n", pid);

    return count;
}

static const struct file_operations seccompfs_file_fops = {
    .read   = seccompfs_read,
    .write  = seccomp_write,
    .llseek = noop_llseek,
};

static const struct inode_operations seccompfs_dir_inode_ops = {
    .lookup = simple_lookup, 
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
    int ret;

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
