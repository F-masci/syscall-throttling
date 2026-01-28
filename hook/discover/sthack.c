/**
 * @file sthack.c
 * @author Francesco Masci (francescomasci@outlook.com)
 *
 * @brief This file implements the syscall table hacking mechanisms. It provides
 *		functions to disable and enable write protection on the syscall table.
 *
 * @version 1.0
 * @date 2026-01-26
 *
 */

#include <linux/errno.h>
#include <linux/preempt.h>
#include <asm/special_insns.h>
#include <asm/processor.h>

#include "sthack.h"

static unsigned long cr0, cr4;

/**
 * @brief Write to CR0 register
 *
 * @param val Value to write
 */
static inline void write_cr0_forced(unsigned long val)
{
	unsigned long __force_order;

	asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

/**
 * @brief Protect memory by setting the WP bit in CR0
 *
 */
static inline void protect_memory(void)
{
	write_cr0_forced(cr0);
}

/**
 * @brief Unprotect memory by clearing the WP bit in CR0
 *
 */
static inline void unprotect_memory(void)
{
	write_cr0_forced(cr0 & ~X86_CR0_WP);
}

/**
 * @brief Write to CR4 register
 *
 * @param val Value to write
 */
static inline void write_cr4_forced(unsigned long val)
{
	unsigned long __force_order;

	asm volatile("mov %0, %%cr4" : "+r"(val), "+m"(__force_order));
}

/**
 * @brief Disable CET if enabled
 *
 */
static inline void conditional_cet_disable(void)
{
#ifdef X86_CR4_CET
	if (cr4 & X86_CR4_CET)
		write_cr4_forced(cr4 & ~X86_CR4_CET);
#endif
}

/**
 * @brief Enable CET if it was enabled before
 *
 */
static inline void conditional_cet_enable(void)
{
#ifdef X86_CR4_CET
	if (cr4 & X86_CR4_CET)
		write_cr4_forced(cr4);
#endif
}

/**
 * @brief Begin syscall table hacking. Disables write protection.
 *
 */
void begin_syscall_table_hack(void)
{
	preempt_disable();
	cr0 = read_cr0();
	cr4 = native_read_cr4();
	conditional_cet_disable();
	unprotect_memory();
}

/**
 * @brief End syscall table hacking. Enables write protection.
 *
 */
void end_syscall_table_hack(void)
{
	protect_memory();
	conditional_cet_enable();
	preempt_enable();
}
