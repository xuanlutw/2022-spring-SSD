#include <linux/fs.h>
#include <linux/types.h>

#define ROOT_INO 1
#define BUF_SIZE 1024

struct seccomp_info {
    pid_t pid;
    short int len;
    short int *seccomp_list;
    struct seccomp_info *next;
};
