#pragma once

#include "sct.h"
#include "_syst.h"

#define UID_HT_SIZE     10
#define PNAMES_HT_SIZE  16

struct uid_node {
    uid_t uid;
    struct hlist_node node;
    struct rcu_head rcu;
};

struct prog_node {
    char name[TASK_COMM_LEN];
    struct hlist_node node;
    struct rcu_head rcu;
};

void setup_monitor_filter(void);
void cleanup_monitor_filter(void);

/* ---- SYS CALL MONITORING ---- */

size_t get_syscall_monitor_num(void);
size_t get_syscall_monitor_vals(scidx_t *, size_t);

bool is_syscall_monitored(scidx_t);
void add_syscall_monitoring(scidx_t);
void remove_syscall_monitoring(scidx_t);

/* ---- UIDS MONITORING ---- */

size_t get_uid_monitor_num(void);
size_t get_uid_monitor_vals(uid_t *, size_t);

bool is_uid_monitored(uid_t);
int add_uid_monitoring(uid_t);
int remove_uid_monitoring(uid_t);

/* ---- PROG NAMES MONITORING ---- */

size_t get_prog_monitor_num(void);
size_t get_prog_monitor_vals(char **, size_t);

bool is_prog_monitored(const char *);
int add_prog_monitoring(const char *);
int remove_prog_monitoring(const char *);