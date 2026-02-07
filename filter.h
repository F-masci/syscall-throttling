#pragma once

#include "sct.h"
#include "_syst.h"

#define UID_HT_SIZE 10
#define PNAMES_HT_SIZE 16

struct uid_node {
	struct rcu_head rcu;
	uid_t uid;
	struct hlist_node node;
};

struct prog_node {
	struct rcu_head rcu;
#ifndef LOW_MEMORY
	char *fpath;
#else
#endif
	unsigned long inode;
	dev_t device;
	struct hlist_node node;
};

int setup_monitor_filter(void);
void cleanup_monitor_filter(void);

/* ---- SYS CALL MONITORING ---- */

size_t get_syscall_monitor_num(void);
size_t get_syscall_monitor_vals(int *buf, size_t size);

bool is_syscall_monitored(int syscall_idx);
void add_syscall_monitoring(int syscall_idx);
void remove_syscall_monitoring(int syscall_idx);

/* ---- UIDS MONITORING ---- */

size_t get_uid_monitor_num(void);
size_t get_uid_monitor_vals(uid_t *buf, size_t size);

bool is_uid_monitored(uid_t uid);
int add_uid_monitoring(uid_t uid);
int remove_uid_monitoring(uid_t uid);

/* ---- PROG NAMES MONITORING ---- */

struct file *get_task_exe(struct task_struct *task);
char *get_exe_path(struct file *exe_file);

size_t get_prog_monitor_num(void);
size_t get_prog_monitor_vals(char **buf, size_t size);

bool is_prog_monitored(unsigned long inode, dev_t device);
int add_prog_monitoring(const char *path);
int remove_prog_monitoring(const char *path);
