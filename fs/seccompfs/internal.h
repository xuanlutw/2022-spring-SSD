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

#define MODE_CONFIG (S_IFREG | 0200)
#define MODE_BEGIN  (S_IFREG | 0200)
#define MODE_DIR    (S_IFDIR | 0500)
#define MODE_LOG    (S_IFREG | 0400)

struct seccomp_info {
	struct list_head list;
	pid_t pid;
	unsigned int len;
	unsigned int filter[MAX_FILTER];
	unsigned int content_len;
	char *content;
	struct dentry *dir;
	struct dentry *log;
};
