#include <linux/hashtable.h>
#include <linux/bitmap.h>
#include <linux/uidgid.h>
#include <linux/sched.h>

#include "types.h"
#include "_syst.h"

struct uid_node {
    uid_t uid;
    struct hlist_node node;
};

struct prog_node {
    char name[TASK_COMM_LEN];
    struct hlist_node node;
};

void setup_monitor_filter(void);
void cleanup_monitor_filter(void);

/* ---- SYS CALL MONITORING ---- */

unsigned long * get_syscall_monitor_ptr(void);
size_t get_syscall_monitor_vals(scidx_t *, size_t);

bool is_syscall_monitored(int syscall_nr);
void add_syscall_monitoring(int syscall_nr);
void remove_syscall_monitoring(int syscall_nr);

/* ---- UIDS MONITORING ---- */

struct hlist_head * get_uid_monitor_ptr(void);
size_t get_uid_monitor_vals(uid_t *, size_t);

bool is_uid_monitored(uid_t uid);
int add_uid_monitoring(uid_t uid);
int remove_uid_monitoring(uid_t uid);

/* ---- PROG NAMES MONITORING ---- */

struct hlist_head * get_prog_monitor_ptr(void);
size_t get_prog_monitor_vals(char **, size_t);

bool is_prog_monitored(const char *name);
int add_prog_monitoring(const char *name);
int remove_prog_monitoring(const char *name);