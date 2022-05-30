#include <linux/fs.h>
#include <linux/types.h>

#define ROOT_INO 1
#define BUF_SIZE 1024

#define INO_CONFIG 10
#define INO_BEGIN  11
#define INO_SHIFT  12
#define INO_DIR(pid) ((pid)<<1 + INO_SHIFT)
#define INO_LOG(pid) ((pid)<<1 + INO_SHIFT + 1)

struct seccomp_info {
    pid_t pid;
    short int len;
    short int *seccomp_list;
    struct seccomp_info *next;
};
