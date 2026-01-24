/**
 * @file filter.c
 * @author Francesco Masci (francescomasci@outlook.com)
 * 
 * @brief This file implements the filtering mechanisms for the system call
 *        throttling module. It provides functions to manage monitored system
 *        calls, user IDs, and program names using bitmaps and hash tables.
 * 
 * @version 1.0
 * @date 2026-01-21
 * 
 */

#include <linux/hashtable.h>
#include <linux/bitmap.h>
#include <linux/stringhash.h>
#include <linux/string.h>
#include <linux/nospec.h>
#include <linux/rcupdate.h>

#include "filter.h"

// ---- INTERNAL DATA STRUCTURES ---- //

static DECLARE_BITMAP(syscall_bm, SYSCALL_TABLE_SIZE);      // SYSCALL_TABLE_SIZE bitmap
static atomic64_t syscall_count = ATOMIC64_INIT(0);
static spinlock_t syscall_lock  = __SPIN_LOCK_UNLOCKED(syscall_lock);

static DEFINE_HASHTABLE(uid_ht, UID_HT_SIZE);               // 2^UID_HT_SIZE buckets
static atomic64_t uid_count = ATOMIC64_INIT(0);
static spinlock_t uid_lock  = __SPIN_LOCK_UNLOCKED(uid_lock);

static DEFINE_HASHTABLE(progname_ht, PNAMES_HT_SIZE);       // 2^PNAMES_HT_SIZE buckets
static atomic64_t prog_count = ATOMIC64_INIT(0);
static spinlock_t prog_lock  = __SPIN_LOCK_UNLOCKED(prog_lock);

/**
 * @brief Set the up monitor filter structure
 * 
 */
void setup_monitor_filter(void) {
    bitmap_zero(syscall_bm, SYSCALL_TABLE_SIZE);
    PR_DEBUG("Initialized syscall monitoring bitmap\n");
}

/**
 * @brief Cleanup the monitor filter structure
 * 
 */
void cleanup_monitor_filter(void) {
    
    unsigned long flags;
    struct uid_node *cur_uid;
    struct hlist_node *tmp_uid;
    struct prog_node *cur_pn;
    struct hlist_node *tmp_pn;
    int bkt;

    // Cleanup syscall bitmap
    // Not really needed
    bitmap_zero(syscall_bm, SYSCALL_TABLE_SIZE);
    atomic64_set(&syscall_count, 0);
    PR_DEBUG("Cleared syscall monitoring bitmap\n");
    
    // Cleanup UID hash table
    spin_lock_irqsave(&uid_lock, flags);
    hash_for_each_safe(uid_ht, bkt, tmp_uid, cur_uid, node) {
        hash_del_rcu(&cur_uid->node);
        kfree_rcu(cur_uid, rcu);
        atomic64_dec(&uid_count);
    }
    spin_unlock_irqrestore(&uid_lock, flags);
    PR_DEBUG("Cleared UID monitoring hash table\n");

    // Cleanup program names hash table
    spin_lock_irqsave(&prog_lock, flags);
    hash_for_each_safe(progname_ht, bkt, tmp_pn, cur_pn, node) {
        hash_del_rcu(&cur_pn->node);
        kfree_rcu(cur_pn, rcu);
        atomic64_dec(&prog_count);
    }
    spin_unlock_irqrestore(&prog_lock, flags);
    PR_DEBUG("Cleared program names monitoring hash table\n");

}

/* ---- SYS CALL MONITORING ---- */

/**
 * @brief Get the number of syscall monitored
 * 
 * @return size_t
 */
size_t get_syscall_monitor_num() {
    return atomic64_read(&syscall_count);
}

/**
 * @brief Get the syscall monitor values
 * 
 * @param buf Buffer to store the syscall numbers
 * @param max_size Maximum number of syscall numbers to retrieve
 * 
 * @return size_t Number of syscall numbers retrieved
 */
size_t get_syscall_monitor_vals(scidx_t *buf, size_t max_size) {
    unsigned long flags;
    unsigned long i;
    size_t count = 0;

    // Start critical section
    spin_lock_irqsave(&syscall_lock, flags);

    PR_DEBUG("Retrieving monitored syscall numbers from bitmap\n");
    for_each_set_bit(i, syscall_bm, SYSCALL_TABLE_SIZE) {
        if (count >= max_size) break;
        if (buf) buf[count] = (int) i;
        count++;
    }
    PR_DEBUG("Retrieved %zu monitored syscall numbers\n", count);

    // End critical section
    spin_unlock_irqrestore(&syscall_lock, flags);

    return count;
}

/**
 * @brief Check if a syscall is monitored
 * 
 * @param syscall_nr Syscall number to check
 * @return bool True if monitored, false otherwise
 */
inline bool is_syscall_monitored(scidx_t syscall_idx) {
    if (unlikely(syscall_idx < 0 || syscall_idx >= SYSCALL_TABLE_SIZE)) return false;
    syscall_idx = array_index_nospec(syscall_idx, SYSCALL_TABLE_SIZE);
    PR_DEBUG("Checking if syscall %d is monitored...\n", syscall_idx);
    return test_bit(syscall_idx, syscall_bm);
}

/**
 * @brief Add a syscall to the monitored list
 * 
 * @param syscall_idx Syscall number to add
 */
void add_syscall_monitoring(scidx_t syscall_idx) {
    if (unlikely(syscall_idx < 0 || syscall_idx >= SYSCALL_TABLE_SIZE)) return;
    syscall_idx = array_index_nospec(syscall_idx, SYSCALL_TABLE_SIZE);
    PR_DEBUG("Adding syscall %d to monitoring list\n", syscall_idx);
    set_bit(syscall_idx, syscall_bm);
    atomic64_inc(&syscall_count);
}

/**
 * @brief Remove a syscall from the monitored list
 * 
 * @param syscall_idx Syscall number to remove
 */
void remove_syscall_monitoring(scidx_t syscall_idx) {
    if (unlikely(syscall_idx < 0 || syscall_idx >= SYSCALL_TABLE_SIZE)) return;
    syscall_idx = array_index_nospec(syscall_idx, SYSCALL_TABLE_SIZE);
    PR_DEBUG("Removing syscall %d from monitoring list\n", syscall_idx);
    clear_bit(syscall_idx, syscall_bm);
    atomic64_dec(&syscall_count);
}

/* ---- UIDS MONITORING ---- */

/**
 * @brief Get the number of UIDs monitored
 * 
 * @return size_t 
 */
size_t get_uid_monitor_num() {
    return atomic64_read(&uid_count);
}

/**
 * @brief Get the uid monitor values
 * 
 * @param buf Buffer to store the UIDs
 * @param max_size Maximum number of UIDs to retrieve
 * 
 * @return size_t Number of UIDs retrieved
 */
size_t get_uid_monitor_vals(uid_t *buf, size_t max_size) {
    
    unsigned long flags;
    struct uid_node *cur;
    int bkt;
    int count = 0;

    // Start critical section
    spin_lock_irqsave(&uid_lock, flags);

    PR_DEBUG("Retrieving monitored UIDs from hash table\n");
    hash_for_each(uid_ht, bkt, cur, node) {
        if (count >= max_size) break;
        if (buf) buf[count] = cur->uid;
        count++;
    }
    PR_DEBUG("Retrieved %d monitored UIDs\n", count);

    // End critical section
    spin_unlock_irqrestore(&uid_lock, flags);
    
    return count;
}

/**
 * @brief Check if a UID is monitored
 * 
 * @param uid UID to check
 * @return bool True if monitored, false otherwise 
 */
inline bool is_uid_monitored(uid_t uid) {

    struct uid_node *cur;
    bool found = false;

    // RCU read section
    rcu_read_lock();

    PR_DEBUG("Searching UID %d in monitoring hash table...\n", uid);
    hash_for_each_possible_rcu(uid_ht, cur, node, uid) {
        if (cur->uid == uid) {
            found = true;
            break;
        }
    }
    PR_DEBUG("UID %d %s monitored\n", uid, found ? "is" : "is not");

    // End RCU read section
    rcu_read_unlock();

    return found;
}

/**
 * @brief Add a UID to the monitored list
 * 
 * @param uid UID to add
 * @return int 0 on success, error code otherwise
 */
int add_uid_monitoring(uid_t uid) {

    unsigned long flags;
    struct uid_node *new_node;

    // Prepare new node
    PR_DEBUG("Preparing node to add UID %d to monitoring list\n", uid);
    new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
    if (!new_node) return -ENOMEM;
    new_node->uid = uid;
    
    // Start critical section
    spin_lock_irqsave(&uid_lock, flags);

    // Check if already monitored
    if(is_uid_monitored(uid)) {
        spin_unlock_irqrestore(&uid_lock, flags);
        kfree(new_node);
        PR_DEBUG("UID %d already monitored\n", uid);
        return 0;
    }

    // Add to hash table
    hash_add_rcu(uid_ht, &new_node->node, uid);
    atomic64_inc(&uid_count);
    PR_DEBUG("Added UID %d to monitoring list\n", uid);

    // End critical section
    spin_unlock_irqrestore(&uid_lock, flags);
    
    return 0;
}

/**
 * @brief Remove a UID from the monitored list
 * 
 * @param uid UID to remove
 * @return int 0 on success, error code otherwise
 */
int remove_uid_monitoring(uid_t uid) {

    unsigned long flags;
    struct uid_node *cur;
    struct hlist_node *tmp;
    int ret = -ENOENT;
    
    // Start critical section
    spin_lock_irqsave(&uid_lock, flags);

    PR_DEBUG("Searching UID %d to remove from monitoring list...\n", uid);
    hash_for_each_possible_safe(uid_ht, cur, tmp, node, uid) {
        if (cur->uid == uid) {
            PR_DEBUG("Removing UID %d from monitoring list\n", uid);
            hash_del_rcu(&cur->node);
            atomic64_dec(&uid_count);
            kfree_rcu(cur, rcu);
            ret = 0;
            break; 
        }
    }

    // End critical section
    spin_unlock_irqrestore(&uid_lock, flags);

    return ret;
}

/* --- PROG NAMES MONITORING --- */

/**
 * @brief Get the number of program names monitored
 * 
 * @return size_t 
 */
size_t get_prog_monitor_num() {
    return atomic64_read(&prog_count);
}

/**
 * @brief Get the program names monitor values
 * 
 * @param buf Buffer to store the program names
 * @param max_size Maximum number of program names to retrieve
 * 
 * @return size_t Number of program names retrieved
 */
size_t get_prog_monitor_vals(char **buf, size_t max_size) {

    unsigned long flags;
    struct prog_node *cur;
    int bkt;
    size_t count = 0;

    // Start critical section
    spin_lock_irqsave(&prog_lock, flags);

    PR_DEBUG("Retrieving monitored program names from hash table\n");
    hash_for_each(progname_ht, bkt, cur, node) {
        if (count >= max_size) break;
        if (buf) {
            // Create a copy of the string
            // We need to use GFP_ATOMIC as we are in a spinlock (so no sleeping)
            buf[count] = kstrndup(cur->name, TASK_COMM_LEN, GFP_ATOMIC);
        }
        count++;
    }
    PR_DEBUG("Retrieved %zu monitored program names\n", count);

    // End critical section
    spin_unlock_irqrestore(&prog_lock, flags);
    
    return count;
}

/**
 * @brief Check if a program name is monitored
 * 
 * @param name Program name to check
 * @return bool True if monitored, false otherwise
 */
inline bool is_prog_monitored(const char *name) {

    struct prog_node *cur;
    bool found = false;
    u32 key_hash;

    if (!name) return false;
    key_hash = full_name_hash(NULL, name, strlen(name));

    // RCU read section
    rcu_read_lock();

    PR_DEBUG("Searching program name %s in monitoring hash table...\n", name);
    hash_for_each_possible_rcu(progname_ht, cur, node, key_hash) {
        if (strcmp(cur->name, name) == 0) {
            found = true;
            break;
        }
    }
    PR_DEBUG("Program name %s %s monitored\n", name, found ? "is" : "is not");

    // End RCU read section
    rcu_read_unlock();

    return found;
}

/**
 * @brief Add a program name to the monitored list
 * 
 * @param name Program name to add
 * @return int 0 on success, error code otherwise
 */
int add_prog_monitoring(const char *name) {

    unsigned long flags;
    struct prog_node *new_node;
    u32 key_hash;

    if (!name) return -EINVAL;
    key_hash = full_name_hash(NULL, name, strlen(name));

    // Prepare new node
    PR_DEBUG("Preparing node to add program name %s to monitoring list\n", name);
    new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
    if (!new_node) return -ENOMEM;
    strscpy(new_node->name, name, TASK_COMM_LEN);

    // Start critical section
    spin_lock_irqsave(&prog_lock, flags);

    // Check if already monitored
    if(is_prog_monitored(name)) {
        spin_unlock_irqrestore(&prog_lock, flags);
        kfree(new_node);
        PR_DEBUG("Program name %s already monitored\n", name);
        return 0;
    }

    // Add to hash table
    hash_add_rcu(progname_ht, &new_node->node, key_hash);
    atomic64_inc(&prog_count);
    PR_DEBUG("Added program name %s to monitoring list\n", name);

    // End critical section
    spin_unlock_irqrestore(&prog_lock, flags);

    return 0;
}

/**
 * @brief Remove a program name from the monitored list
 * 
 * @param name Program name to remove
 * @return int 0 on success, error code otherwise
 */
int remove_prog_monitoring(const char *name) {

    unsigned long flags;
    struct prog_node *cur;
    struct hlist_node *tmp;
    u32 key_hash;
    int ret = -ENOENT;

    if (!name) return -EINVAL;
    key_hash = full_name_hash(NULL, name, strlen(name));

    // Start critical section
    spin_lock_irqsave(&prog_lock, flags);

    PR_DEBUG("Searching program name %s to remove from monitoring list...\n", name);
    hash_for_each_possible_safe(progname_ht, cur, tmp, node, key_hash) {
        if (strcmp(cur->name, name) == 0) {
            PR_DEBUG("Removing program name %s from monitoring list\n", name);
            hash_del_rcu(&cur->node);
            atomic64_dec(&prog_count);
            kfree_rcu(cur, rcu);
            ret = 0;
            break; 
        }
    }

    // End critical section
    spin_unlock_irqrestore(&prog_lock, flags);

    return ret;
}