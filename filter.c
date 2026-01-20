#include <linux/slab.h>
#include <linux/stringhash.h>
#include <linux/string.h>
#include <asm/unistd.h>

#include "filter.h"
#include "types.h"

#define UID_HT_SIZE 10
#define PNAMES_HT_SIZE 16

static DECLARE_BITMAP(syscall_bm, SYSCALL_TABLE_SIZE);      // SYSCALL_TABLE_SIZE bitmap
static DEFINE_HASHTABLE(uid_ht, UID_HT_SIZE);               // 2^UID_HT_SIZE buckets
static DEFINE_HASHTABLE(progname_ht, PNAMES_HT_SIZE);       // 2^PNAMES_HT_SIZE buckets

void setup_monitor_filter(void) {
    bitmap_zero(syscall_bm, SYSCALL_TABLE_SIZE);
}

void cleanup_monitor_filter(void) {
    struct uid_node *cur_uid;
    struct hlist_node *tmp_uid;
    struct prog_node *cur_pn;
    struct hlist_node *tmp_pn;
    int bkt;

    // Cleanup UID hash table
    hash_for_each_safe(uid_ht, bkt, tmp_uid, cur_uid, node) {
        hash_del(&cur_uid->node);
        kfree(cur_uid);
    }

    // Cleanup program names hash table
    hash_for_each_safe(progname_ht, bkt, tmp_pn, cur_pn, node) {
        hash_del(&cur_pn->node);
        kfree(cur_pn);
    }
}

/* ---- SYS CALL MONITORING ---- */

unsigned long * get_syscall_monitor_ptr() {
    return (unsigned long *) &syscall_bm;
}

size_t get_syscall_monitor_vals(scidx_t *buf, size_t max_size) {
    unsigned long i;
    size_t count = 0;

    for_each_set_bit(i, syscall_bm, SYSCALL_TABLE_SIZE) {
        if (count >= max_size) break;
        if (buf) buf[count] = (int) i;
        count++;
    }

    return count;
}

// FIXME: check bounds
bool is_syscall_monitored(int syscall_nr) {
    // test_bit è atomico e molto veloce
    if (syscall_nr < 0 || syscall_nr >= SYSCALL_TABLE_SIZE)
        return false;
    return test_bit(syscall_nr, syscall_bm);
}

// FIXME: check bounds
void add_syscall_monitoring(int syscall_nr) {
    if (syscall_nr < 0 || syscall_nr >= SYSCALL_TABLE_SIZE)
        return;
    set_bit(syscall_nr, syscall_bm);
}

void remove_syscall_monitoring(int syscall_nr) {
    if (syscall_nr < 0 || syscall_nr >= SYSCALL_TABLE_SIZE)
        return;
    clear_bit(syscall_nr, syscall_bm);
}

/* ---- UIDS MONITORING ---- */

struct hlist_head * get_uid_monitor_ptr(void) {
    return (struct hlist_head *) &uid_ht;
}

size_t get_uid_monitor_vals(uid_t *buf, size_t max_size) {
    
    struct uid_node *cur;
    int bkt;
    int count = 0;

    // TODO
    // spin_lock(&uid_lock);

    hash_for_each(uid_ht, bkt, cur, node) {
        if (count >= max_size) break;
        if (buf) buf[count] = cur->uid;
        count++;
    }

    // spin_unlock(&uid_lock);
    
    return count;
}

bool is_uid_monitored(uid_t uid) {

    struct uid_node *cur;

    hash_for_each_possible(uid_ht, cur, node, uid) {
        if (cur->uid == uid) return true;
    }
    return false;
}

int add_uid_monitoring(uid_t uid) {
    struct uid_node *cur;
    struct uid_node *new_node;
    
    // Check if already monitored
    hash_for_each_possible(uid_ht, cur, node, uid) {
        if (cur->uid == uid) return 0;
    }

    new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
    if (!new_node) return -ENOMEM;

    new_node->uid = uid;
    
    hash_add(uid_ht, &new_node->node, uid);
    return 0;
}

int remove_uid_monitoring(uid_t uid) {

    struct uid_node *cur;
    struct hlist_node *tmp; 
    
    // FIXME: locking
    // spin_lock(&uid_lock);

    hash_for_each_possible_safe(uid_ht, cur, tmp, node, uid) {
        if (cur->uid == uid) {
            hash_del(&cur->node);
            kfree(cur);
            break; 
        }
    }

    // FIXME: locking
    // spin_unlock(&uid_lock);

    return 0;
}

/* --- PROG NAMES MONITORING --- */

struct hlist_head * get_prog_monitor_ptr(void) {
    return (struct hlist_head *) &progname_ht;
}

size_t get_prog_monitor_vals(char **buf, size_t max_size) {
    struct prog_node *cur;
    int bkt;
    size_t count = 0;

    // TODO: locking
    // spin_lock(&prog_lock);

    hash_for_each(progname_ht, bkt, cur, node) {
        if (count >= max_size) break;
        
        if (buf) {
            // Create a copy of the string
            // Use GFP_ATOMIC if under spinlock, otherwise GFP_KERNEL
            buf[count] = kstrdup(cur->name, GFP_KERNEL);
        }
        count++;
    }

    // spin_unlock(&prog_lock);
    
    return count;
}

bool is_prog_monitored(const char *name) {
    struct prog_node *cur;
    u32 key_hash;

    if (!name) return false;

    key_hash = full_name_hash(NULL, name, strlen(name));
    hash_for_each_possible(progname_ht, cur, node, key_hash) {
        if (strcmp(cur->name, name) == 0) return true;
    }
    return false;
}

int add_prog_monitoring(const char *name) {
    struct prog_node *cur;
    struct prog_node *new_node;
    u32 key_hash;

    if (!name) return -EINVAL;

    key_hash = full_name_hash(NULL, name, strlen(name));

    // Check if already monitored
    hash_for_each_possible(progname_ht, cur, node, key_hash) {
        if (strcmp(cur->name, name) == 0) return 0; // Already present
    }

    new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
    if (!new_node) return -ENOMEM;

    // Safe copy of the string into the node
    strscpy(new_node->name, name, TASK_COMM_LEN);
    
    hash_add(progname_ht, &new_node->node, key_hash);
    return 0;
}

int remove_prog_monitoring(const char *name) {
    struct prog_node *cur;
    struct hlist_node *tmp;
    u32 key_hash;

    if (!name) return -EINVAL;

    key_hash = full_name_hash(NULL, name, strlen(name));

    // FIXME: locking
    // spin_lock(&prog_lock);

    hash_for_each_possible_safe(progname_ht, cur, tmp, node, key_hash) {
        if (strcmp(cur->name, name) == 0) {
            hash_del(&cur->node);
            kfree(cur);
            break; 
        }
    }

    // FIXME: locking
    // spin_unlock(&prog_lock);

    return 0;
}