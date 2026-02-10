/**
 * @file stats.c
 * @author Francesco Masci (francescomasci@outlook.com)
 *
 * @brief This file implements the statistics gathering mechanisms for the
 *		system call throttling module. It tracks peak delayed syscalls,
 *		and counts of invoked and blocked threads per time window.
 *
 * @version 1.0
 * @date 2026-01-26
 *
 */

#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/file.h>

#include "stats.h"
#include "filter.h"

#ifdef _RCU_PROTECTED

struct peak_wrapper {
	struct rcu_head rcu;
	struct sysc_delayed_t data;
};

struct stats_wrapper {
	struct rcu_head rcu;
	struct wstats_t data;
};

static struct peak_wrapper __rcu *peakd_ptr;
static struct stats_wrapper __rcu *stats_ptr;

#elif defined _SPINLOCK_PROTECTED

static struct sysc_delayed_t peak_ds = { -1, 0, 0, NULL };
static struct wstats_t wstats = { 0, 0, 0 };

#endif

static DEFINE_RWLOCK(peakd_lock);
static DEFINE_RWLOCK(stats_lock);

// Number of blocked threads in the current time window
static atomic64_t blocked_current_window = ATOMIC64_INIT(0);

/**
 * @brief Setup the monitor statistics structures
 * @return int 0 on success, negative error code on failure
 */
int setup_monitor_stats(void)
{
#ifdef _RCU_PROTECTED
	struct peak_wrapper *init_peakd_ptr;
	struct stats_wrapper *init_stats_ptr;

	init_peakd_ptr = kzalloc(sizeof(struct peak_wrapper), GFP_KERNEL);
	if (!init_peakd_ptr)
		return -ENOMEM;
	init_peakd_ptr->data.syscall = -1;

	init_stats_ptr = kzalloc(sizeof(struct stats_wrapper), GFP_KERNEL);
	if (!init_stats_ptr) {
		kfree(init_peakd_ptr);
		return -ENOMEM;
	}

	// Publish initial pointer
	RCU_INIT_POINTER(peakd_ptr, init_peakd_ptr);
	RCU_INIT_POINTER(stats_ptr, init_stats_ptr);
#else
#endif

	return 0;
}

#ifdef _RCU_PROTECTED
/**
 * @brief Callback function to free peak delayed syscall data
 *
 * @param head RCU head pointer
 */
static void peak_free_callback(struct rcu_head *head)
{
	struct peak_wrapper *pk = container_of(head, struct peak_wrapper, rcu);

	kfree(pk->data.prog_name);
	kfree(pk);
}
#else
#endif

/**
 * @brief Cleanup the monitor statistics structures
 */
void cleanup_monitor_stats(void)
{
#ifdef _RCU_PROTECTED
	struct peak_wrapper *_peakd_ptr;
	struct stats_wrapper *_stats_ptr;

	// Cleanup peak delayed syscall structure
	_peakd_ptr = rcu_dereference_protected(peakd_ptr, true);
	if (_peakd_ptr)
		call_rcu(&(_peakd_ptr->rcu), peak_free_callback);
	RCU_INIT_POINTER(peakd_ptr, NULL);

	// Cleanup stats structure
	_stats_ptr = rcu_dereference_protected(stats_ptr, true);
	if (_stats_ptr)
		kfree_rcu(_stats_ptr, rcu);
	RCU_INIT_POINTER(stats_ptr, NULL);

	// Wait for all RCU callbacks to complete before returning, to ensure all memory is freed
	rcu_barrier();

#else

	// Cleanup peak delayed name
	if (peak_ds.prog_name)
		kfree(peak_ds.prog_name);

#endif
}

/* ---- PEAK DELAYED SYSCALL ---- */

/**
 * @brief Allocate and return the current program name
 *
 * @return char*
 */
static char *alloc_current_prog_name(void)
{
	struct file *exe_file;
	char *prog_name = NULL;

	// Get the current executable file
	exe_file = get_task_exe(current);
	if (exe_file) {
		// Get the program name from the executable file
		prog_name = get_exe_path(exe_file);
		fput(exe_file);
	}

	// If the program name is still NULL, allocate a default one
	if (!prog_name)
		prog_name = kstrdup("N/A", GFP_ATOMIC);

	return prog_name;
}

#ifdef _RCU_PROTECTED

#define GET_PEAK_DELAYED_SYSCALL(out) _get_peak_rcu(out)
#define UPDATE_PEAK_DELAY(delay_ms, syscall) _update_peak_rcu(delay_ms, syscall)
#define RESET_PEAK_DELAY() _reset_peak_rcu()

static void _get_peak_rcu(struct sysc_delayed_t *out)
{
	struct peak_wrapper *peak_ptr;
	char *prog_name_ptr;

	// Copy data to output buffer
	rcu_read_lock();
	peak_ptr = rcu_dereference(peakd_ptr);
	if (!peak_ptr)
		goto copy_peak_rcu_exit;

	prog_name_ptr = out->prog_name;

	// Copy data to output buffer
	memcpy(out, &peak_ptr->data, sizeof(struct sysc_delayed_t));

	// Restore program name pointer provided by the caller
	out->prog_name = prog_name_ptr;
	if (!out->prog_name) {
		PR_WARN("No buffer allocated for program name provided\n");
		goto copy_peak_rcu_exit;
	}

	// Copy program name in the buffer
	if (peak_ptr->data.prog_name)
		strscpy(out->prog_name, peak_ptr->data.prog_name, PATH_MAX);
	else
		out->prog_name[0] = '\0';

copy_peak_rcu_exit:
	rcu_read_unlock();
}

static bool _update_peak_rcu(s64 delay_ms, int syscall)
{
	struct peak_wrapper *old_peak, *new_peak;
	char *prog_name;
	unsigned long flags;
	bool updated = false;

	// Fast check without lock
	old_peak = rcu_access_pointer(peakd_ptr);
	if (likely(old_peak && delay_ms <= old_peak->data.delay_ms))
		return updated;

	// Alloc new peak structure
	new_peak = kzalloc(sizeof(*new_peak), GFP_ATOMIC);
	if (!new_peak)
		goto rcu_peak_alloc_err;

	// Allocate program name
	prog_name = alloc_current_prog_name();
	if (!prog_name)
		goto rcu_name_alloc_err;

	write_lock_irqsave(&peakd_lock, flags);

	// Re-check with lock
	old_peak = rcu_dereference_protected(peakd_ptr, lockdep_is_held(&peakd_lock));

	if (likely(old_peak && delay_ms > old_peak->data.delay_ms)) {
		// Populate new peak structure
		new_peak->data.delay_ms = delay_ms;
		new_peak->data.uid = current_euid().val;
		new_peak->data.syscall = syscall;
		new_peak->data.prog_name = prog_name;

		// Publish
		rcu_assign_pointer(peakd_ptr, new_peak);

		// Free old
		if (old_peak)
			call_rcu(&old_peak->rcu, peak_free_callback);

		new_peak = NULL;
		prog_name = NULL;
		updated = true;
	}

	write_unlock_irqrestore(&peakd_lock, flags);

	// Cleanup if not updated
	kfree(prog_name);

rcu_name_alloc_err:
	kfree(new_peak);

rcu_peak_alloc_err:
	return updated;
}

static int _reset_peak_rcu(void)
{
	unsigned long flags;
	struct peak_wrapper *old_peak_ptr, *new_peak_ptr;

	// Allocate new peak structure
	new_peak_ptr = kzalloc(sizeof(struct peak_wrapper), GFP_ATOMIC);
	if (!new_peak_ptr)
		return -ENOMEM;
	new_peak_ptr->data.syscall = -1;

	write_lock_irqsave(&peakd_lock, flags);

	// Publish new peak pointer
	old_peak_ptr = rcu_dereference_protected(peakd_ptr, lockdep_is_held(&peakd_lock));
	rcu_assign_pointer(peakd_ptr, new_peak_ptr);

	// Free old
	if (old_peak_ptr)
		call_rcu(&old_peak_ptr->rcu, peak_free_callback);

	write_unlock_irqrestore(&peakd_lock, flags);

	return 0;
}

#elif defined _SPINLOCK_PROTECTED

#define GET_PEAK_DELAYED_SYSCALL(out) _get_peak_spinlock(out)
#define UPDATE_PEAK_DELAY(delay_ms, syscall) _update_peak_spinlock(delay_ms, syscall)
#define RESET_PEAK_DELAY() _reset_peak_spinlock()

static void _get_peak_spinlock(struct sysc_delayed_t *out)
{
	unsigned long flags;
	char *prog_name_ptr;

	// Copy data to output buffer
	read_lock_irqsave(&peakd_lock, flags);

	prog_name_ptr = out->prog_name;

	// Copy data to output buffer
	memcpy(out, &peak_ds, sizeof(struct sysc_delayed_t));

	// Restore program name pointer provided by the caller
	out->prog_name = prog_name_ptr;
	if (!out->prog_name) {
		PR_WARN("No buffer allocated for program name provided\n");
		goto copy_peak_spinlock_exit;
	}

	// Copy program name in the buffer
	if (peak_ds.prog_name)
		strscpy(out->prog_name, peak_ds.prog_name, PATH_MAX);
	else
		out->prog_name[0] = '\0';

copy_peak_spinlock_exit:
	read_unlock_irqrestore(&peakd_lock, flags);
}

static bool _update_peak_spinlock(s64 delay_ms, int syscall)
{
	unsigned long flags;
	char *prog_name;
	bool updated = false;

	// Fast check
	if (likely(delay_ms <= peak_ds.delay_ms))
		return updated;

	// Alloc program name
	prog_name = alloc_current_prog_name();
	if (!prog_name)
		return updated;

	write_lock_irqsave(&peakd_lock, flags);

	// Re-check under lock
	if (likely(delay_ms <= peak_ds.delay_ms)) {
		kfree(prog_name);
		goto spinlock_update_fail;
	}

	// Free old program name
	if (peak_ds.prog_name)
		kfree(peak_ds.prog_name);

	// Update struct
	peak_ds.delay_ms = delay_ms;
	peak_ds.uid = current_euid().val;
	peak_ds.syscall = syscall;
	peak_ds.prog_name = prog_name;

	updated = true;

spinlock_update_fail:

	write_unlock_irqrestore(&peakd_lock, flags);

	return updated;
}

static int _reset_peak_spinlock(void)
{
	unsigned long flags;

	write_lock_irqsave(&peakd_lock, flags);

	// Free program name
	if (peak_ds.prog_name) {
		kfree(peak_ds.prog_name);
		peak_ds.prog_name = NULL;
	}

	// Publish new peak pointer
	memset(&peak_ds, 0, sizeof(struct sysc_delayed_t));
	peak_ds.syscall = -1;

	write_unlock_irqrestore(&peakd_lock, flags);

	return 0;
}

#else

#define GET_PEAK_DELAYED_SYSCALL(out) (*out = NULL)
#define UPDATE_PEAK_DELAY(delay_ms, syscall) (false)
#define RESET_PEAK_DELAY() (-1)

#endif

/**
 * @brief Get the peak delayed syscall info
 * @param out Output structure to fill with peak delayed syscall info
 */
void get_peak_delayed_syscall(struct sysc_delayed_t *out)
{
	// Safety check
	if (!out)
		return;

	// Copy data to output buffer
	GET_PEAK_DELAYED_SYSCALL(out);
}

// Fast path minimum delay threshold
// This avoids taking the lock for negligible delays
#define MIN_DELAY_MS 0
/**
 * @brief Update the peak delayed syscall info if the new delay is greater than the current peak
 * @param delay_ms Delay in milliseconds
 * @param syscall Syscall number
 * @return bool True if updated, false otherwise
 */
bool update_peak_delay(s64 delay_ms, int syscall)
{
	if (likely(delay_ms <= MIN_DELAY_MS))
		return false;

	return UPDATE_PEAK_DELAY(delay_ms, syscall);
}
#undef MIN_DELAY_MS

/**
 * @brief Reset the peak delayed syscall info
 */
int reset_peak_delay(void)
{
	return RESET_PEAK_DELAY();
}

/* ---- CURRENT WINDOW COUNTERS ---- */

#ifdef _RCU_PROTECTED

#define COMPRES_WSTATS_BLOCKED(curr_blocked) _compres_wstats_rcu(curr_blocked)
#define GET_PEAKW_BLOCKED() _get_peakw_blocked_rcu()
#define GET_AVGW_BLOCKED(sum, count) _get_avgw_blocked_rcu(sum, count)
#define GET_STATS_BLOCKED(peak, avg, wnum, scale) _get_stats_blocked_rcu(peak, avg, wnum, scale)
#define RESET_STATS_BLOCKED() _reset_stats_blocked_rcu()

static u64 _compres_wstats_rcu(u64 curr_blocked)
{
	unsigned long flags;
	struct stats_wrapper *old_stats_ptr, *new_stats_ptr;

	// Allocate new stats structure
	new_stats_ptr = kzalloc(sizeof(struct stats_wrapper), GFP_ATOMIC);
	if (!new_stats_ptr)
		return curr_blocked;

	write_lock_irqsave(&stats_lock, flags);

	// Get old stats
	old_stats_ptr = rcu_dereference_protected(stats_ptr, lockdep_is_held(&stats_lock));
	if (old_stats_ptr) {
		new_stats_ptr->data.max_blocked_threads = old_stats_ptr->data.max_blocked_threads;
		new_stats_ptr->data.sum_blocked_threads = old_stats_ptr->data.sum_blocked_threads;
		new_stats_ptr->data.total_windows_count = old_stats_ptr->data.total_windows_count;
	}

	// Update peak blocked threads if current is greater
	if (curr_blocked > new_stats_ptr->data.max_blocked_threads)
		new_stats_ptr->data.max_blocked_threads = curr_blocked;

	// Update sum and window count for average calculation
	new_stats_ptr->data.sum_blocked_threads += curr_blocked;
	new_stats_ptr->data.total_windows_count++;

	// Publish new stats pointer
	rcu_assign_pointer(stats_ptr, new_stats_ptr);

	// Free old stats after a grace period
	if (old_stats_ptr)
		kfree_rcu(old_stats_ptr, rcu);

	write_unlock_irqrestore(&stats_lock, flags);

	return curr_blocked;
}

static u64 _get_peakw_blocked_rcu(void)
{
	u64 ret;
	struct stats_wrapper *sptr;

	// Read stats under RCU lock
	rcu_read_lock();
	sptr = rcu_dereference(stats_ptr);
	if (sptr)
		ret = sptr->data.max_blocked_threads;
	else
		ret = 0;
	rcu_read_unlock();

	return ret;
}

static void _get_avgw_blocked_rcu(u64 *sum, u64 *count)
{
	struct stats_wrapper *sptr;

	// Initialize output values
	*sum = 0;
	*count = 0;

	// Read stats under RCU lock
	rcu_read_lock();
	sptr = rcu_dereference(stats_ptr);
	if (sptr) {
		*sum = sptr->data.sum_blocked_threads;
		*count = sptr->data.total_windows_count;
	}
	rcu_read_unlock();
}

static void _get_stats_blocked_rcu(u64 *peak_blocked, u64 *avg_blocked, u64 *windows_num, u64 scale)
{
	struct stats_wrapper *sptr;

	// Sanitize scale
	if (scale <= 0)
		scale = 1;

	// Initialize outputs
	if (peak_blocked)
		*peak_blocked = 0;
	if (avg_blocked)
		*avg_blocked = 0;
	if (windows_num)
		*windows_num = 0;

	// Read stats under RCU lock
	rcu_read_lock();
	sptr = rcu_dereference(stats_ptr);
	if (sptr) {
		if (windows_num)
			*windows_num = sptr->data.total_windows_count;

		if (peak_blocked)
			*peak_blocked = sptr->data.max_blocked_threads;

		if (avg_blocked) {
			if (sptr->data.total_windows_count == 0)
				*avg_blocked = 0;
			else
				*avg_blocked = (sptr->data.sum_blocked_threads * scale) / sptr->data.total_windows_count;
		}
	}
	rcu_read_unlock();
}

static int _reset_stats_blocked_rcu(void)
{
	unsigned long flags;
	struct stats_wrapper *new_stats, *old_stats;

	// Allocate new stats structure
	new_stats = kzalloc(sizeof(struct stats_wrapper), GFP_ATOMIC);
	if (!new_stats)
		return -ENOMEM;

	write_lock_irqsave(&stats_lock, flags);

	// Get old stats
	old_stats = rcu_dereference_protected(stats_ptr, lockdep_is_held(&stats_lock));

	// Publish new stats pointer
	rcu_assign_pointer(stats_ptr, new_stats);

	// Free old stats after a grace period
	if (old_stats)
		kfree_rcu(old_stats, rcu);

	write_unlock_irqrestore(&stats_lock, flags);

	return 0;
}

#elif defined _SPINLOCK_PROTECTED

#define COMPRES_WSTATS_BLOCKED(curr_blocked) _compres_wstats_spinlock(curr_blocked)
#define GET_PEAKW_BLOCKED() _get_peakw_blocked_spinlock()
#define GET_AVGW_BLOCKED(sum, count) _get_avgw_blocked_spinlock(sum, count)
#define GET_STATS_BLOCKED(peak, avg, wnum, scale) _get_stats_blocked_spinlock(peak, avg, wnum, scale)
#define RESET_STATS_BLOCKED() _reset_stats_blocked_spinlock()

static u64 _compres_wstats_spinlock(u64 curr_blocked)
{
	unsigned long flags;

	write_lock_irqsave(&stats_lock, flags);

	// Update peak blocked threads if current is greater
	if (curr_blocked > wstats.max_blocked_threads)
		wstats.max_blocked_threads = curr_blocked;

	// Update sum and window count for average calculation
	wstats.sum_blocked_threads += curr_blocked;
	wstats.total_windows_count++;

	write_unlock_irqrestore(&stats_lock, flags);

	return curr_blocked;
}

static u64 _get_peakw_blocked_spinlock(void)
{
	u64 ret;
	unsigned long flags;

	read_lock_irqsave(&stats_lock, flags);
	ret = wstats.max_blocked_threads;
	read_unlock_irqrestore(&stats_lock, flags);

	return ret;
}

static void _get_avgw_blocked_spinlock(u64 *sum, u64 *count)
{
	unsigned long flags;

	// Initialize output values
	*sum = 0;
	*count = 0;

	// Read stats under spinlock
	read_lock_irqsave(&stats_lock, flags);
	*sum = wstats.sum_blocked_threads;
	*count = wstats.total_windows_count;
	read_unlock_irqrestore(&stats_lock, flags);
}

static void _get_stats_blocked_spinlock(u64 *peak_blocked, u64 *avg_blocked, u64 *windows_num, u64 scale)
{
	unsigned long flags;

	// Sanitize scale
	if (scale <= 0)
		scale = 1;

	// Initialize outputs
	if (peak_blocked)
		*peak_blocked = 0;
	if (avg_blocked)
		*avg_blocked = 0;
	if (windows_num)
		*windows_num = 0;

	// Read stats under spinlock
	read_lock_irqsave(&stats_lock, flags);
	if (windows_num)
		*windows_num = wstats.total_windows_count;

	if (peak_blocked)
		*peak_blocked = wstats.max_blocked_threads;

	if (avg_blocked) {
		if (wstats.total_windows_count == 0)
			*avg_blocked = 0;
		else
			*avg_blocked = (wstats.sum_blocked_threads * scale) / wstats.total_windows_count;
	}
	read_unlock_irqrestore(&stats_lock, flags);
}

static int _reset_stats_blocked_spinlock(void)
{
	unsigned long flags;

	write_lock_irqsave(&stats_lock, flags);
	memset(&wstats, 0, sizeof(struct wstats_t));
	write_unlock_irqrestore(&stats_lock, flags);

	return 0;
}

#else

#define COMPRES_WSTATS_BLOCKED(curr_blocked) (curr_blocked)
#define GET_PEAKW_BLOCKED() -1
#define GET_AVGW_BLOCKED(sum, count) \
	do {                         \
		*sum = 0;            \
		*count = 0;          \
	} while (0)
#define GET_STATS_BLOCKED(peak, avg, wnum, scale) \
	do {                                      \
		if (wnum)                         \
			*wnum = -1;               \
		if (peak)                         \
			*peak = -1;               \
		if (avg)                          \
			*avg = -1;                \
	} while (0)
#define RESET_STATS_BLOCKED() (-1)

#endif

/**
 * @brief Increment the current window blocked counter
 * @return u64 The new value of the blocked counter
 */
u64 increment_curw_blocked(void)
{
	return (u64)atomic64_inc_return(&blocked_current_window);
}

/**
 * @brief Compute and update the statistics for blocked threads,
 * and reset current window counters
 * @return u64 The old value of the blocked counter before reset
 */
u64 compres_wstats_blocked(void)
{
	u64 curr_blocked;

	// Atomically get and reset the current window blocked count
	curr_blocked = atomic64_xchg(&blocked_current_window, 0);

	// Compress window statistics
	return COMPRES_WSTATS_BLOCKED(curr_blocked);
}

/**
 * @brief Get the peakw blocked count
 * @return u64
 */
u64 get_peakw_blocked(void)
{
	return GET_PEAKW_BLOCKED();
}

/**
 * @brief Get the average blocked count scaled by the given factor
 * Example: with scale = 100 (for percentage), if the average is 2.5 returns 250.
 * @param scale Scaling factor
 * @return u64
 */
u64 get_avgw_blocked(u64 scale)
{
	u64 sum = 0, count = 0;

	GET_AVGW_BLOCKED(&sum, &count);

	if (scale <= 0)
		scale = 1;

	if (count == 0)
		return 0;

	return (sum * scale) / count;
}

/**
 * @brief Get statistics for blocked threads on time windows
 * @param peak_blocked Pointer to store max blocked threads (can be NULL)
 * @param avg_blocked Pointer to store average blocked threads (can be NULL)
 * @param windows_num Time windows counter (can be NULL)
 * @param scale Scaling factor for average
 */
void get_stats_blocked(u64 *peak_blocked, u64 *avg_blocked, u64 *windows_num, u64 scale)
{
	// Early exit if no data requested
	if (!peak_blocked && !avg_blocked && !windows_num)
		return;

	// Get statistics
	GET_STATS_BLOCKED(peak_blocked, avg_blocked, windows_num, scale);
}

/**
 * @brief Reset all blocked statistics on time windows
 */
int reset_stats_blocked(void)
{
	// Reset the atomic counters (current window)
	atomic64_set(&blocked_current_window, 0);

	return RESET_STATS_BLOCKED();
}
