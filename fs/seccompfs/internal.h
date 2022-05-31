#include <linux/fs.h>
#include <linux/types.h>
#include <linux/list.h>

#define BUF_SIZE   1024
#define MAX_FILTER 128
#define MAX_CONTENT_LEN 4096

#define INO_ROOT   1
#define INO_CONFIG 10
#define INO_BEGIN  11
#define INO_SHIFT  12
#define INO_DIR(pid) (((pid) << 1) + INO_SHIFT)
#define INO_LOG(pid) (((pid) << 1) + INO_SHIFT + 1)

struct seccomp_filter {
	refcount_t usage;
	bool log;
	struct seccomp_filter *prev;
	struct bpf_prog *prog;
	struct notification *notif;
	struct mutex notify_lock;
};

extern int seccomp_check_filter(struct sock_filter *filter, unsigned int flen);

struct seccomp_info {
    struct list_head list;
    pid_t pid;
    unsigned int len;
    unsigned int filter[MAX_FILTER];
    unsigned int content_len;
    char* content;
    struct dentry *dir;
    struct dentry *log;
};
