/**
 * @file filter.c
 * @author Francesco Masci (francescomasci@outlook.com)
 * @brief This file implements the filtering mechanisms for the system call
 *		throttling module. It provides functions to manage monitored system
 *		calls, user IDs, and program names using bitmaps and hash tables.
 * @version 1.0
 * @date 2026-01-26
 */

#include <linux/hashtable.h>
#include <linux/bitmap.h>
#include <linux/stringhash.h>
#include <linux/string.h>
#include <linux/nospec.h>
#include <linux/rcupdate.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/jhash.h>

#include "filter.h"

// ---- INTERNAL DATA STRUCTURES ---- //

static DECLARE_BITMAP(syscall_bm,
		      SYSCALL_TABLE_SIZE); // SYSCALL_TABLE_SIZE bitmap
static atomic64_t syscall_count = ATOMIC64_INIT(0);
static DEFINE_RWLOCK(syscall_lock);

static DEFINE_HASHTABLE(uid_ht, UID_HT_SIZE); // 2^UID_HT_SIZE buckets
static atomic64_t uid_count = ATOMIC64_INIT(0);
static DEFINE_RWLOCK(uid_lock);

static DEFINE_HASHTABLE(progname_ht,
			PNAMES_HT_SIZE); // 2^PNAMES_HT_SIZE buckets
static atomic64_t prog_count = ATOMIC64_INIT(0);
static DEFINE_RWLOCK(prog_lock);

/**
 * @brief Set the up monitor filter structure
 *
 * @return int 0 on success, negative error code on failure
 */
int setup_monitor_filter(void)
{
	bitmap_zero(syscall_bm, SYSCALL_TABLE_SIZE);
	PR_DEBUG("Initialized syscall monitoring bitmap\n");

	return 0;
}

/**
 * @brief Free a program node in a safe manner for RCU
 *
 * @param head RCU head pointer
 */
static void prog_node_free_rcu(struct rcu_head *head)
{
	struct prog_node *node = container_of(head, struct prog_node, rcu);

#ifndef LOW_MEMORY
	kfree(node->fpath);
#endif
	kfree(node);

}

/**
 * @brief Cleanup the monitor filter structure
 */
void cleanup_monitor_filter(void)
{
	struct uid_node *cur_uid = NULL;
	struct hlist_node *tmp_uid;
	struct prog_node *cur_pn = NULL;
	struct hlist_node *tmp_pn;
	int bkt;

	// Cleanup syscall bitmap
	// Not really needed
	bitmap_zero(syscall_bm, SYSCALL_TABLE_SIZE);
	atomic64_set(&syscall_count, 0);
	PR_DEBUG("Cleared syscall monitoring bitmap\n");

	// Cleanup UID hash table
	hash_for_each_safe(uid_ht, bkt, tmp_uid, cur_uid, node) {
		hash_del_rcu(&cur_uid->node);
		kfree_rcu(cur_uid, rcu);
		atomic64_dec(&uid_count);
	}
	PR_DEBUG("Cleared UID monitoring hash table\n");

	// Cleanup program names hash table
	hash_for_each_safe(progname_ht, bkt, tmp_pn, cur_pn, node) {
		hash_del_rcu(&cur_pn->node);
		call_rcu(&cur_pn->rcu, prog_node_free_rcu);
		atomic64_dec(&prog_count);
	}
	PR_DEBUG("Cleared program names monitoring hash table\n");
}

/* ---- SYS CALL MONITORING ---- */

/**
 * @brief Get the number of syscall monitored
 * @return size_t
 */
size_t get_syscall_monitor_num(void)
{
	return atomic64_read(&syscall_count);
}

/**
 * @brief Get the syscall monitor values
 * @param buf Buffer to store the syscall numbers
 * @param max_size Maximum number of syscall numbers to retrieve
 * @return size_t Number of syscall numbers retrieved
 */
size_t get_syscall_monitor_vals(int *buf, size_t max_size)
{
	unsigned long flags;
	unsigned long i;
	size_t count = 0;

	// Start critical section
	read_lock_irqsave(&syscall_lock, flags);

	for_each_set_bit(i, syscall_bm, SYSCALL_TABLE_SIZE) {
		if (count >= max_size)
			break;
		if (buf)
			buf[count] = (int)i;
		count++;
	}
	PR_DEBUG("Retrieved %zu monitored syscall numbers\n", count);

	// End critical section
	read_unlock_irqrestore(&syscall_lock, flags);

	return count;
}

/**
 * @brief Check if a syscall is monitored
 * @param syscall_nr Syscall number to check
 * @return bool True if monitored, false otherwise
 */
bool is_syscall_monitored(int syscall_idx)
{
	return test_bit(syscall_idx, syscall_bm);
}

/**
 * @brief Add a syscall to the monitored list
 * @param syscall_idx Syscall number to add
 */
void add_syscall_monitoring(int syscall_idx)
{
	unsigned long flags;

	// Sanity check
	if (unlikely(syscall_idx < 0 || syscall_idx >= SYSCALL_TABLE_SIZE))
		return;
	syscall_idx = array_index_nospec(syscall_idx, SYSCALL_TABLE_SIZE);

	// Fast check without lock
	if (unlikely(is_syscall_monitored(syscall_idx)))
		return;

	write_lock_irqsave(&syscall_lock, flags);

	// Re-check with lock
	if (unlikely(is_syscall_monitored(syscall_idx))) {
		PR_DEBUG("Syscall %d already monitored\n", syscall_idx);
		goto syscall_monitored;
	}

	set_bit(syscall_idx, syscall_bm);
	atomic64_inc(&syscall_count);

	PR_DEBUG("Added syscall %d to monitoring list\n", syscall_idx);

syscall_monitored:
	write_unlock_irqrestore(&syscall_lock, flags);
}

/**
 * @brief Remove a syscall from the monitored list
 * @param syscall_idx Syscall number to remove
 */
void remove_syscall_monitoring(int syscall_idx)
{
	unsigned long flags;

	// Sanity check
	if (unlikely(syscall_idx < 0 || syscall_idx >= SYSCALL_TABLE_SIZE))
		return;
	syscall_idx = array_index_nospec(syscall_idx, SYSCALL_TABLE_SIZE);

	// Fast check without lock
	if (unlikely(is_syscall_monitored(syscall_idx)))
		return;

	write_lock_irqsave(&syscall_lock, flags);

	// Re-check with lock
	if (unlikely(!is_syscall_monitored(syscall_idx))) {
		PR_WARN("Syscall %d not monitored\n", syscall_idx);
		goto syscall_not_monitored;
	}

	clear_bit(syscall_idx, syscall_bm);
	atomic64_dec(&syscall_count);

	PR_DEBUG("Removed syscall %d from monitoring list\n", syscall_idx);

syscall_not_monitored:
	write_unlock_irqrestore(&syscall_lock, flags);
}

/* ---- UIDS MONITORING ---- */

/**
 * @brief Get the number of UIDs monitored
 * @return size_t
 */
size_t get_uid_monitor_num(void)
{
	return atomic64_read(&uid_count);
}

/**
 * @brief Get the uid monitor values
 * @param buf Buffer to store the UIDs
 * @param max_size Maximum number of UIDs to retrieve
 * @return size_t Number of UIDs retrieved
 */
size_t get_uid_monitor_vals(uid_t *buf, size_t max_size)
{
	unsigned long flags;
	struct uid_node *cur = NULL;
	int bkt;
	int count = 0;

	// Start critical section
	read_lock_irqsave(&uid_lock, flags);

	hash_for_each(uid_ht, bkt, cur, node) {
		if (count >= max_size)
			break;
		if (buf)
			buf[count] = cur->uid;
		count++;
	}
	PR_DEBUG("Retrieved %d monitored UIDs\n", count);

	// End critical section
	read_unlock_irqrestore(&uid_lock, flags);

	return count;
}

/**
 * @brief Check if a UID is monitored
 * @param uid UID to check
 * @return bool True if monitored, false otherwise
 */
bool is_uid_monitored(uid_t uid)
{
	struct uid_node *cur = NULL;
	bool found = false;

	// RCU read section
	rcu_read_lock();

	hash_for_each_possible_rcu(uid_ht, cur, node, uid) {
		if (cur->uid == uid) {
			found = true;
			break;
		}
	}

	// End RCU read section
	rcu_read_unlock();

	return found;
}

/**
 * @brief Add a UID to the monitored list
 * @param uid UID to add
 * @return int 0 on success, error code otherwise
 */
int add_uid_monitoring(uid_t uid)
{
	unsigned long flags;
	struct uid_node *new_node;

	// Prepare new node
	PR_DEBUG("Preparing node to add UID %d to monitoring list\n", uid);
	new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
	if (!new_node) {
		PR_ERROR("Cannot allocate memory for new UID node\n");
		return -ENOMEM;
	}
	new_node->uid = uid;

	// Start critical section
	write_lock_irqsave(&uid_lock, flags);

	// Check if already monitored
	if (is_uid_monitored(uid)) {
		PR_DEBUG("UID %d already monitored\n", uid);
		kfree(new_node);
		goto uid_monitored;
	}

	// Add to hash table
	hash_add_rcu(uid_ht, &new_node->node, uid);
	atomic64_inc(&uid_count);
	PR_DEBUG("Added UID %d to monitoring list\n", uid);

	// End critical section
uid_monitored:
	write_unlock_irqrestore(&uid_lock, flags);

	return 0;
}

/**
 * @brief Remove a UID from the monitored list
 * @param uid UID to remove
 * @return int 0 on success, error code otherwise
 */
int remove_uid_monitoring(uid_t uid)
{
	unsigned long flags;
	struct uid_node *cur = NULL;
	struct hlist_node *tmp;
	int ret = -ENOENT;

	// Start critical section
	write_lock_irqsave(&uid_lock, flags);

	PR_DEBUG("Searching UID %d to remove from monitoring list...\n", uid);
	hash_for_each_possible_safe(uid_ht, cur, tmp, node, uid) {
		if (cur->uid == uid) {
			hash_del_rcu(&cur->node);
			atomic64_dec(&uid_count);
			kfree_rcu(cur, rcu);
			PR_DEBUG("Removed UID %d from monitoring list\n", uid);
			ret = 0;
			goto uid_monitor_removed;
		}
	}

	PR_WARN("UID %d not monitored\n", uid);

uid_monitor_removed:
	// End critical section
	write_unlock_irqrestore(&uid_lock, flags);

	return ret;
}

/* --- PROG NAMES MONITORING --- */

/**
 * @brief Get the task exe file structure
 *
 * @param task Pointer to the task_struct
 * @return struct file* Pointer to the executable file structure, or NULL on failure
 *
 * @note The returned file structure has its reference count incremented.
 *	The caller is responsible for calling fput() to release the reference.
 */
struct file __rcu *get_task_exe(struct task_struct *task)
{
	struct file __rcu *exe = NULL;

	// Sanity check
	if (!task)
		return NULL;


	// RCU read section
	rcu_read_lock();
	if (task->mm) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
		exe = get_file_rcu(&task->mm->exe_file);
#else
		struct file *temp_exe;

		temp_exe = rcu_dereference(task->mm->exe_file);

		// If temp_exe exists, try to increment the reference count
		if (temp_exe && get_file_rcu(temp_exe))
			exe = temp_exe;
#endif
	}

	// End RCU read section
	rcu_read_unlock();

	return exe;
}

/**
 * @brief Get the current process executable path
 *
 * @param exe_file Pointer to the executable file structure
 * @return char* Kernel-allocated string containing the path, or NULL on failure
 *
 * @note The returned string must be freed by the caller using kfree().
 *	Must be called under task_lock.
 */
char *get_exe_path(struct file *exe_file)
{
	char *buf, *path_str = NULL, *res = NULL;

	// Sanity check
	if (!exe_file) {
		PR_ERROR_PID("Executable file pointer is NULL\n");
		goto sanity_err;
	}

	// Allocate buffer for path
	buf = kzalloc(PATH_MAX, GFP_ATOMIC);
	if (!buf) {
		PR_ERROR_PID("Failed to allocate memory for executable path buffer\n");
		goto alloc_err;
	}

	// Search path
	path_str = d_path(&exe_file->f_path, buf, PATH_MAX);
	if (IS_ERR(path_str)) {
		PR_ERROR_PID("Failed to get executable path string\n");
		goto dpath_err;
	}

	// Duplicate path string to return
	res = kstrndup(path_str, PATH_MAX, GFP_ATOMIC);
	if (!res) {
		PR_ERROR_PID("Failed to duplicate executable path string\n");
		goto kstrdup_err;
	}

kstrdup_err:
dpath_err:
	// Cleanup and return
	kfree(buf);

sanity_err:
alloc_err:

	return res;
}

/**
 * @brief Get the number of program names monitored
 * @return size_t
 */
size_t get_prog_monitor_num(void)
{
	return atomic64_read(&prog_count);
}

#define FPATH_BUF_SIZE 64
/**
 * @brief Get the program names monitor values
 * @param buf Buffer to store the program names
 * @param max_size Maximum number of program names to retrieve
 * @return size_t Number of program names retrieved
 */
size_t get_prog_monitor_vals(char **buf, size_t max_size)
{
	unsigned long flags;
	struct prog_node *cur = NULL;
	int bkt;
	size_t count = 0;
	char *fpath;
#ifdef LOW_MEMORY
	char tmp_fpath[FPATH_BUF_SIZE];
#else
#endif

	if (unlikely(!buf)) {
		PR_ERROR("Invalid buffer to store program names\n");
		return -EINVAL;
	}

	// Start critical section
	read_lock_irqsave(&prog_lock, flags);

	hash_for_each(progname_ht, bkt, cur, node) {
		if (count >= max_size)
			break;

#ifndef LOW_MEMORY
		fpath = kstrndup(cur->fpath, PATH_MAX, GFP_ATOMIC);
		if (!fpath) {
			PR_ERROR("Failed to duplicate program name %s\n", cur->fpath);
			continue;
		}
#else
		if (snprintf(tmp_fpath, FPATH_BUF_SIZE, "inode:%lu-device:%u", cur->inode, cur->device) < 0) {
			PR_ERROR("Failed to format program name for inode %lu and device %u\n", cur->inode, cur->device);
			continue;
		}
		fpath = kstrdup(tmp_fpath, GFP_ATOMIC);
		if (!fpath) {
			PR_ERROR("Failed to duplicate program name %s\n", tmp_fpath);
			continue;
		}
#endif
		buf[count] = fpath;
		count++;
	}
	PR_DEBUG("Retrieved %zu monitored program names\n", count);

	// End critical section
	read_unlock_irqrestore(&prog_lock, flags);

	return count;
}
#undef FPATH_BUF_SIZE

/**
 * @brief Check if a program name is monitored
 * @param inode Inode number of the program
 * @param device Device number of the program
 * @return bool True if monitored, false otherwise
 */
bool is_prog_monitored(unsigned long inode, dev_t device)
{
	struct prog_node *cur = NULL;
	bool found = false;
	u32 key_hash;

	// Basic sanity check
	key_hash = jhash_2words((u32)inode, (u32)device, PROG_HASH_SALT);

	// RCU read section
	rcu_read_lock();

	hash_for_each_possible_rcu(progname_ht, cur, node, key_hash) {
		if (cur->inode == inode && cur->device == device) {
			found = true;
			break;
		}
	}

	// End RCU read section
	rcu_read_unlock();

	return found;
}

/**
 * @brief Add a program name to the monitored list
 * @param fpath File path of the program to add
 * @return int 0 on success, error code otherwise
 */
int add_prog_monitoring(const char *fpath)
{
	unsigned long flags;
	struct prog_node *new_node;
	struct path path;
	struct inode *inode;
	u32 key_hash;
	int ret = 0;

	// Basic sanity check
	if (unlikely(!fpath)) {
		PR_ERROR("Invalid program name\n");
		return -EINVAL;
	}

	// Resolve path to get inode and device
	ret = kern_path(fpath, LOOKUP_FOLLOW, &path);
	if (ret) {
		PR_ERROR("Cannot resolve path %s\n", fpath);
		return ret;
	}

	// Get inode and device
	inode = path.dentry->d_inode;
	if (!inode) {
		PR_ERROR("Cannot get inode for path %s\n", fpath);
		path_put(&path);
		return -ENOENT;
	}

	// Prepare new node
	PR_DEBUG("Preparing node to add program name %s to monitoring list\n", fpath);
	new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
	if (!new_node) {
		PR_ERROR("Cannot allocate memory for new program node\n");
		path_put(&path);
		return -ENOMEM;
	}

	// Fill node data
	new_node->inode = inode->i_ino;
	new_node->device = inode->i_sb->s_dev;

#ifndef LOW_MEMORY
	new_node->fpath = kstrndup(fpath, PATH_MAX, GFP_KERNEL);
	if (!new_node->fpath) {
		PR_ERROR("Cannot allocate memory for program name %s\n", fpath);
		kfree(new_node);
		path_put(&path);
		return -ENOMEM;
	}
#else
#endif

	// Compute hash key
	key_hash = jhash_2words((u32)new_node->inode, (u32)new_node->device, PROG_HASH_SALT);

	// Release path
	path_put(&path);

	// Start critical section
	write_lock_irqsave(&prog_lock, flags);

	// Check if already monitored
	if (is_prog_monitored(new_node->inode, new_node->device)) {
		PR_DEBUG("Program name %s already monitored\n", fpath);
#ifndef LOW_MEMORY
		kfree(new_node->fpath);
#else
#endif
		kfree(new_node);
		goto prog_monitored;
	}

	// Add to hash table
	hash_add_rcu(progname_ht, &new_node->node, key_hash);
	atomic64_inc(&prog_count);
	PR_DEBUG("Added program name %s to monitoring list\n", fpath);

	// End critical section
prog_monitored:
	write_unlock_irqrestore(&prog_lock, flags);

	return 0;
}

/**
 * @brief Remove a program name from the monitored list
 * @param fpath File path of the program to add
 * @return int 0 on success, error code otherwise
 */
int remove_prog_monitoring(const char *fpath)
{
	unsigned long flags;
	struct prog_node *cur = NULL;
	struct path path;
	struct inode *inode;
	struct hlist_node *tmp;
	u32 key_hash;
	int ret = -ENOENT;

	// Basic sanity check
	if (unlikely(!fpath)) {
		PR_ERROR("Invalid program name\n");
		return -EINVAL;
	}

	// Resolve path to get inode and device
	ret = kern_path(fpath, LOOKUP_FOLLOW, &path);
	if (ret) {
		PR_ERROR("Cannot resolve path %s\n", fpath);
		return ret;
	}

	// Get inode and device
	inode = path.dentry->d_inode;
	if (!inode) {
		PR_ERROR("Cannot get inode for path %s\n", fpath);
		path_put(&path);
		return -ENOENT;
	}

	// Compute hash key
	key_hash = jhash_2words((u32)inode->i_ino, (u32)inode->i_sb->s_dev, PROG_HASH_SALT);

	// Release path
	path_put(&path);

	// Start critical section
	write_lock_irqsave(&prog_lock, flags);

	PR_DEBUG("Searching program name %s to remove from monitoring list...\n", fpath);
	hash_for_each_possible_safe(progname_ht, cur, tmp, node, key_hash) {
		if (cur->inode == inode->i_ino && cur->device == inode->i_sb->s_dev) {
			hash_del_rcu(&cur->node);
			atomic64_dec(&prog_count);
			call_rcu(&cur->rcu, prog_node_free_rcu);
			PR_DEBUG("Removed program name %s from monitoring list\n", fpath);
			ret = 0;
			goto prog_monitor_removed;
		}
	}

	PR_WARN("Program name %s not monitored\n", fpath);

	// End critical section
prog_monitor_removed:
	write_unlock_irqrestore(&prog_lock, flags);

	return ret;
}
