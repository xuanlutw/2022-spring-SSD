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

extern int seccomp_attach_filter_from_kern(struct task_struct *task,
		struct sock_fprog_kern *fprog);

static struct dentry *seccompfs_setup(struct super_block *sb,
	struct dentry *parent_d, const char *name, unsigned int ino,
	umode_t mode);

/* seccomp_info list */
LIST_HEAD(seccomp_info_list);
DEFINE_MUTEX(seccomp_info_list_mutex);
static int seccomp_info_list_len;

/* seccomp_info now */
static struct seccomp_info *seccomp_info_now;

/* seccomp_info operations */
static struct seccomp_info *new_seccomp_info(void)
{
	struct seccomp_info *this;

	this = kmalloc(sizeof(struct seccomp_info), GFP_KERNEL);
	if (!this)
		return NULL;

	this->pid         = 0;
	this->len         = 0;
	this->content_len = 0;
	this->content     = kmalloc(MAX_CONTENT_LEN, GFP_KERNEL);
	this->dir         = NULL;
	this->log         = NULL;
	if (!this->content)
		return NULL;

	return this;
}

static void seccomp_info_set_filters(struct seccomp_info *this, pid_t pid,
		unsigned int len, unsigned int *filter)
{
	int i;

	this->pid = pid;
	this->len = len;
	for (i = 0; i < len; ++i)
		this->filter[i] = filter[i];
}

static int seccomp_info_create_file(struct seccomp_info *this,
		struct super_block *sb)
{
	char dir_name[BUF_SIZE];

	// init dir
	snprintf(dir_name, BUF_SIZE, "%d", this->pid);
	this->dir = seccompfs_setup(sb, sb->s_root, dir_name,
				INO_DIR(this->pid), MODE_DIR);
	if (!this->dir) {
		pr_info("%s: setup dir error.\n", __func__);
		return -ENOMEM;
	}

	// init log
	this->log = seccompfs_setup(sb, this->dir, "log", INO_LOG(this->pid),
			MODE_LOG);
	if (!this->dir) {
		pr_info("%s: setup log error.\n", __func__);
		return -ENOMEM;
	}

	return 0;
}

static inline struct seccomp_info *get_seccomp_info_by_pid(pid_t pid)
{
	struct seccomp_info *item;

	list_for_each_entry(item, &seccomp_info_list, list) {
		if (pid == item->pid)
			return item;
	}
	return NULL;
}

static inline struct seccomp_info *get_seccomp_info_by_dir_ino(unsigned int ino)
{
	struct seccomp_info *item;

	list_for_each_entry(item, &seccomp_info_list, list) {
		if (ino == INO_DIR(item->pid))
			return item;
	}
	return NULL;
}

static inline struct seccomp_info *get_seccomp_info_by_log_ino(unsigned int ino)
{
	struct seccomp_info *item;

	list_for_each_entry(item, &seccomp_info_list, list) {
		if (ino == INO_LOG(item->pid))
			return item;
	}
	return NULL;
}

static struct sock_fprog_kern *seccomp_info_to_bpf_prog(
		struct seccomp_info *this)
{
	struct sock_fprog_kern *fprog;
	int i;

	fprog         = kmalloc(sizeof(struct sock_fprog_kern), GFP_KERNEL);
	if (!fprog)
		return NULL;
	fprog->len    = this->len + 3;
	fprog->filter = kmalloc_array(fprog->len, sizeof(struct sock_filter),
				GFP_KERNEL);
	if (!fprog->filter) {
		kfree(fprog);
		return NULL;
	}

	// A = sys_number
	// if (A == filter[i]) jump ALLOW
	// return KILL
	// return ALLOW
	fprog->filter[0]             = (struct sock_filter){0x20, 0, 0, 0};
	for (i = 0; i < this->len; ++i)
		fprog->filter[i + 1] = (struct sock_filter){0x15, this->len - i,
					0, this->filter[i]};
	fprog->filter[this->len + 1] = (struct sock_filter){0x06, 0, 0, 0};
	fprog->filter[this->len + 2] = (struct sock_filter){0x06, 0, 0,
					0x7fff0000};

	/*
	 * pr_err("%d", fprog->len);
	 * for (i = 0; i < fprog->len; ++i)
	 *      pr_err("%d %d %d %d\n",
	 *          fprog->filter[i].code,
	 *          fprog->filter[i].jt,
	 *          fprog->filter[i].jf,
	 *          fprog->filter[i].k);
	 */

	return fprog;
}

static int seccomp_info_attach(struct seccomp_info *this)
{
	struct task_struct *task;
	struct sock_fprog_kern *fprog;
	int ret;

	task = find_task_by_pid_ns(this->pid, &init_pid_ns);
	if (!task) {
		pr_info("%s: pid not exists.\n", __func__);
		return -EFAULT;
	}

	fprog = seccomp_info_to_bpf_prog(this);
	if (!fprog)
		return -EFAULT;

	task_set_no_new_privs(task);

	ret = seccomp_attach_filter_from_kern(task, fprog);

	kfree(fprog->filter);
	kfree(fprog);

	return ret;
}

/* seccomp log hook */
void seccompfs_log(pid_t pid, unsigned int nr, unsigned int action)
{
	struct seccomp_info *this;
	int len;

	mutex_lock(&seccomp_info_list_mutex);

	this = get_seccomp_info_by_pid(pid);
	if (this && this->content_len < MAX_CONTENT_LEN) {
		len = snprintf(this->content + this->content_len,
			MAX_CONTENT_LEN - this->content_len,
			"%d, %x\n", nr, action);
		this->content_len += len;
	}

	mutex_unlock(&seccomp_info_list_mutex);
}

/* struct file_operations */
static ssize_t seccompfs_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	struct seccomp_info *this;
	int ret;

	this = get_seccomp_info_by_log_ino(file_inode(file)->i_ino);
	if (!this) {
		pr_info("%s: WTF\n", __func__);
		return -EFAULT;
	}

	if (*ppos > this->content_len)
		return 0;
	count = count > (this->content_len - *ppos) ?
			(this->content_len - *ppos) : count;
	ret   = copy_to_user(buf, this->content + *ppos, count);
	count = count - ret;
	*ppos += count;

	return count;
}

static int get_long(char **buf, long *val)
{
	char *token;
	int ret;

	token = strsep(buf, ",");
	if (token == NULL) {
		pr_info("%s: strsep error.\n", __func__);
		return -EFAULT;
	}

	ret = kstrtol(token, 10, val);
	if (ret) {
		pr_info("%s: kstrtol error.\n", __func__);
		return ret;
	}

	return 0;
}

static int handle_config(char *buf, size_t count)
{
	long val;
	int i, ret;
	pid_t pid;
	unsigned int len;
	unsigned int filter[MAX_FILTER];

	pr_info("===== CONFIG INFO =====\n");

	// get pid
	ret = get_long(&buf, &val);
	if (ret)
		goto out;
	pid = (pid_t)val;
	pr_info("pid = %d\n", pid);

	// get len
	ret = get_long(&buf, &val);
	if (ret)
		goto out;
	len = val;
	if (len > MAX_FILTER) {
		ret = -EFAULT;
		goto out;
	}
	pr_info("len = %d\n", len);

	// get filter
	for (i = 0; i < len; ++i) {
		ret = get_long(&buf, &val);
		if (ret)
			goto out;
		filter[i] = (pid_t)val;
		pr_info("filter[%d] = %d\n", i, filter[i]);
	}

	mutex_lock(&seccomp_info_list_mutex);

	// all correct, save to into seccomp_info_now
	seccomp_info_set_filters(seccomp_info_now, pid, len, filter);

	mutex_unlock(&seccomp_info_list_mutex);

out:
	pr_info("=======================\n");

	return ret;
}

static int handle_begin(struct super_block *sb)
{
	struct task_struct *task;
	int ret = -EFAULT;

	pr_info("===== BEGIN INFO =====\n");

	mutex_lock(&seccomp_info_list_mutex);

	// no config set
	if (seccomp_info_now->len == 0) {
		pr_info("%s: config first.\n", __func__);
		goto out;
	}

	// check already set
	if (get_seccomp_info_by_pid(seccomp_info_now->pid)) {
		pr_info("%s: pid already set.\n", __func__);
		goto out;
	}

	// check exists of pid
	task = find_task_by_pid_ns(seccomp_info_now->pid, &init_pid_ns);
	if (!task) {
		pr_info("%s: pid not exists.\n", __func__);
		goto out;
	}

	// attach seccomp filter
	ret = seccomp_info_attach(seccomp_info_now);
	if (ret)
		goto out;

	// post process
	seccomp_info_create_file(seccomp_info_now, sb);
	list_add(&(seccomp_info_now->list), &seccomp_info_list);
	seccomp_info_list_len++;
	seccomp_info_now = new_seccomp_info();

	mutex_unlock(&seccomp_info_list_mutex);

	pr_info("ACCEPT\n");
	pr_info("=======================\n");
	return 0;

out:
	pr_info("REJECT\n");
	pr_info("=======================\n");
	return ret;
}

static ssize_t seccompfs_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	int ret = 0;
	char kbuf[BUF_SIZE];

	count = (count > BUF_SIZE - 1) ? (count > BUF_SIZE - 1) : count;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = 0;

	switch (file_inode(file)->i_ino) {
	case INO_CONFIG:
		ret = handle_config(kbuf, count);
		break;
	case INO_BEGIN:
		ret = handle_begin(file_inode(file)->i_sb);
		break;
	default:
		pr_info("%s: WTF\n", __func__);
	}
	// Cheat it
	return ret < 0 ? -EFAULT : count;
}

static int seccompfs_iterate(struct file *file, struct dir_context *dc)
{
	// TODO: return of dir_emit
	unsigned int count;
	unsigned int ino;
	struct seccomp_info *item;

	ino = file_inode(file)->i_ino;

	if (ino == INO_ROOT) {
		// . and ..
		if (dc->pos == 0)
			dir_emit_dots(file, dc);
		// config
		if (dc->pos == 2) {
			dir_emit(dc, "config", 6, INO_CONFIG, MODE_CONFIG);
			dc->pos++;
		}
		// begin
		if (dc->pos == 3) {
			dir_emit(dc, "begin", 5, INO_BEGIN, MODE_BEGIN);
			dc->pos++;
		}
		// pids
		count = dc->pos - 4;
		list_for_each_entry(item, &seccomp_info_list, list) {
			if (!count) {
				dir_emit(dc, item->dir->d_name.name,
					item->dir->d_name.len,
					INO_DIR(item->pid), MODE_DIR);
				dc->pos += 1;
			} else
				count--;
		}
	} else {
		// . and ..
		if (dc->pos == 0)
			dir_emit_dots(file, dc);
		if (dc->pos > 2)
			return 0;
		// log
		item = get_seccomp_info_by_dir_ino(ino);
		if (item) {
			dir_emit(dc, "log", 3, INO_LOG(item->pid), MODE_LOG);
			dc->pos += 1;
		}
	}

	return 0;
}

static const struct file_operations seccompfs_file_fops = {
	.read   = seccompfs_read,
	.write  = seccompfs_write,
	.llseek = noop_llseek,
};

static const struct file_operations seccompfs_dir_fops = {
	.iterate_shared = seccompfs_iterate,
};

/* struct inode_operations */
static const struct inode_operations seccompfs_inode_ops = {
	.lookup  = simple_lookup,
	.getattr = simple_getattr,
};

/* struct super_operations */
static const struct super_operations seccompfs_sops = {
	.statfs     = simple_statfs,
	.drop_inode = generic_delete_inode,
};

/* struct fs_context_operations */
/* allocate a new inode
 * ino convention
 * .      INO_ROOT     = 1
 * config INO_CONFIG   = 10
 * begin  INO_BEGIN    = 11
 * dir	  INO_DIR(pid) = pid * 2 + INO_SHIFT + 1
 * log	  INO_LOG(pid) = pid * 2 + INO_SHIFT + 1
 */
static struct inode *seccompfs_get_inode(struct super_block *sb,
		unsigned int ino, const struct inode *dir, umode_t mode)
{
	struct inode *inode = new_inode(sb);

	if (inode) {
		inode->i_ino   = ino;
		inode->i_mode  = mode;
		inode_init_owner(inode, dir, mode);
		inode->i_atime = inode->i_mtime
			= inode->i_ctime = current_time(inode);

		switch (mode & S_IFMT) {
		case S_IFDIR:
			inode->i_op  = &seccompfs_inode_ops;
			inode->i_fop = &seccompfs_dir_fops;
			inc_nlink(inode);
			break;
		case S_IFREG:
			inode->i_op  = &seccompfs_inode_ops;
			inode->i_fop = &seccompfs_file_fops;
			break;
		case S_IFLNK:
		default:
			pr_info("%s: WTF\n", __func__);
			return NULL;
		}
	}
	return inode;
}

static struct dentry *seccompfs_setup(struct super_block *sb,
		struct dentry *p_dentry, const char *name, unsigned int ino,
		umode_t mode)
{
	struct inode  *p_inode = d_inode(p_dentry);
	struct inode  *inode;
	struct dentry *dentry;

	inode_lock(p_inode);
	dentry = d_alloc_name(p_dentry, name);
	if (dentry) {
		inode = seccompfs_get_inode(sb, ino, p_inode, mode);
		if (inode)
			d_add(dentry, inode);
		else
			dput(dentry);
	}
	inode_unlock(p_inode);

	return dentry;
}

static int seccompfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct inode *inode;
	static struct dentry *dentry;

	sb->s_iflags    |= SB_I_NOEXEC | SB_I_NODEV;
	sb->s_flags     |= SB_NOSUID | SB_NOEXEC | SB_DIRSYNC | SB_NODIRATIME;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic     = 0xEEEEFFFF;
	sb->s_op        = &seccompfs_sops;
	sb->s_time_gran = 1;

	// init root
	inode = seccompfs_get_inode(sb, INO_ROOT, NULL, S_IFDIR | 0755);
	if (!inode) {
		pr_info("%s: setup root inode error.\n", __func__);
		return -ENOMEM;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		pr_info("%s: setup root error.\n", __func__);
		return -ENOMEM;
	}

	// init config
	dentry = seccompfs_setup(sb, sb->s_root, "config", INO_CONFIG,
			MODE_CONFIG);
	if (!dentry) {
		pr_info("%s: setup config error.\n", __func__);
		return -ENOMEM;
	}

	// init begin
	dentry = seccompfs_setup(sb, sb->s_root, "begin", INO_BEGIN,
			MODE_BEGIN);
	if (!dentry) {
		pr_info("%s: setup begin error.\n", __func__);
		return -ENOMEM;
	}

	// init seccomp_info
	seccomp_info_now = new_seccomp_info();
	if (!seccomp_info_now) {
		pr_info("%s: setup seccomp_info_now error.\n", __func__);
		return -ENOMEM;
	}

	return 0;
}

static void seccompfs_free_fc(struct fs_context *fc)
{
}

static int seccompfs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, seccompfs_fill_super);
}

static const struct fs_context_operations seccompfs_context_ops = {
	.free     = seccompfs_free_fc,
	.get_tree = seccompfs_get_tree,
};

/* struct file_system_type */
static int seccompfs_init_fs_context(struct fs_context *fc)
{
	fc->ops = &seccompfs_context_ops;
	return 0;
}

static void seccompfs_kill_sb(struct super_block *sb)
{
	kill_litter_super(sb);
}

static struct file_system_type seccompfs_type = {
	.name            = "seccompfs",
	.init_fs_context = seccompfs_init_fs_context,
	.kill_sb         = seccompfs_kill_sb,
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
